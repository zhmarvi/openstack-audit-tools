#!/usr/bin/env python3
"""Correlate Nova instance directories across computes.

This tool is intentionally report-only. It consumes:

* JSON files produced by audit_instances.yml; and
* JSON server listings produced by the OpenStack client.

It does not connect to OpenStack, libvirt, or remote hosts, and it never
deletes or changes anything.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from textwrap import shorten
from typing import Any, Iterable


UUID_PATTERN = (
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{12}"
)
DIRECTORY_PATTERN = re.compile(
    rf"^(?P<uuid>{UUID_PATTERN})(?P<suffix>_(?P<suffix_kind>resize|del))?$",
    re.IGNORECASE,
)

NON_FINDING_CLASSIFICATIONS = {
    "LIVE_OR_STOPPED",
    "EXPECTED_RESIZE",
    "NON_INSTANCE_DIRECTORY",
}


def canonical_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def field(record: dict[str, Any], *names: str) -> Any:
    values = {canonical_key(key): value for key, value in record.items()}
    for name in names:
        key = canonical_key(name)
        if key in values:
            return values[key]
    return None


def as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value).strip()


def as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {path}: {exc}") from exc


def records_from_json(data: Any, preferred_keys: Iterable[str]) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in preferred_keys:
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        for value in data.values():
            if isinstance(value, list) and all(isinstance(item, dict) for item in value):
                return value
    return []


def normalize_host(value: Any) -> str:
    host = as_text(value).lower().rstrip(".")
    return host


def short_host(value: Any) -> str:
    return normalize_host(value).split(".", 1)[0]


def host_matches(nova_host: str, host_names: list[str]) -> bool:
    if not nova_host:
        return False
    wanted = {normalize_host(nova_host), short_host(nova_host)}
    available = set()
    for name in host_names:
        available.add(normalize_host(name))
        available.add(short_host(name))
    return bool(wanted & available)


def parse_server_files(paths: list[Path], deleted: bool) -> list[dict[str, Any]]:
    output = []
    for path in paths:
        data = load_json(path)
        for raw in records_from_json(data, ("servers", "data", "records")):
            instance_uuid = as_text(field(raw, "id", "uuid", "server_id"))
            if not instance_uuid:
                continue
            status = as_text(field(raw, "status"))
            output.append(
                {
                    "uuid": instance_uuid.lower(),
                    "name": as_text(field(raw, "name")),
                    "host": as_text(
                        field(
                            raw,
                            "Host",
                            "hostname",
                            "OS-EXT-SRV-ATTR:host",
                            "compute_host",
                        )
                    ),
                    "status": status,
                    "task_state": as_text(
                        field(raw, "task_state", "Task State", "OS-EXT-STS:task_state")
                    ),
                    "vm_state": as_text(
                        field(raw, "vm_state", "VM State", "OS-EXT-STS:vm_state")
                    ),
                    "power_state": as_text(
                        field(raw, "power_state", "Power State", "OS-EXT-STS:power_state")
                    ),
                    "deleted": deleted or status.lower() == "deleted",
                    "source": str(path),
                }
            )
    return output


def build_server_index(
    active_paths: list[Path], deleted_paths: list[Path]
) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    # Prefer the non-deleted listing if duplicate records are supplied.
    for record in parse_server_files(deleted_paths, deleted=True) + parse_server_files(
        active_paths, deleted=False
    ):
        current = index.get(record["uuid"])
        if current is None or current["deleted"] and not record["deleted"]:
            index[record["uuid"]] = record
    return index


def parse_directory_name(name: str) -> tuple[str | None, str]:
    match = DIRECTORY_PATTERN.match(name)
    if not match:
        return None, "other"
    return match.group("uuid").lower(), match.group("suffix_kind") or "base"


def parse_tab_lines(value: Any) -> list[list[str]]:
    if isinstance(value, list):
        lines = [as_text(item) for item in value]
    else:
        lines = as_text(value).splitlines()
    return [line.split("\t") for line in lines if line.strip()]


def parse_compute_file(path: Path, now: float, min_age_days: float) -> tuple[list[dict[str, Any]], list[str]]:
    data = load_json(path)
    if not isinstance(data, dict):
        raise RuntimeError(f"compute collection {path} is not a JSON object")

    inventory_hostname = as_text(data.get("inventory_hostname")) or path.stem
    host_names = [inventory_hostname, as_text(data.get("ansible_host"))]
    for parts in parse_tab_lines(data.get("host_names")):
        if len(parts) >= 2:
            host_names.append(parts[1])
    host_names = [name for name in host_names if name]

    commands = data.get("commands")
    if not isinstance(commands, dict):
        commands = {}
    libvirt_rc = commands.get("libvirt_rc", -1)
    directories_rc = commands.get("directories_rc", -1)
    libvirt_known = str(libvirt_rc) == "0" or libvirt_rc == 0
    directories_known = str(directories_rc) == "0" or directories_rc == 0

    mount = as_text(data.get("mount"))
    mount_parts = mount.split()
    fstype = mount_parts[1].lower() if len(mount_parts) >= 2 else ""
    source = mount_parts[0].lower() if mount_parts else ""
    shared_storage = fstype in {
        "nfs",
        "nfs4",
        "ceph",
        "cephfs",
        "cifs",
        "glusterfs",
        "9p",
    } or ":" in source

    domain_by_uuid: dict[str, dict[str, str]] = {}
    for parts in parse_tab_lines(data.get("libvirt")):
        if not parts or parts[0] != "DOMAIN" or len(parts) < 4:
            continue
        domain_name, domain_uuid, state = parts[1], parts[2].lower(), "\t".join(parts[3:])
        if re.fullmatch(UUID_PATTERN, domain_uuid, re.IGNORECASE):
            domain_by_uuid[domain_uuid] = {"name": domain_name, "state": state}

    sizes: dict[str, int] = {}
    for parts in parse_tab_lines(data.get("sizes")):
        if len(parts) >= 3 and parts[0] == "SIZE":
            try:
                sizes[parts[1]] = int(parts[2])
            except ValueError:
                pass

    entries_by_directory: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for parts in parse_tab_lines(data.get("entries")):
        if len(parts) < 3:
            continue
        relative_path = parts[0]
        directory_name = relative_path.split("/", 1)[0]
        entry = {"path": relative_path, "size": parts[1], "mtime": parts[2]}
        entries_by_directory[directory_name].append(entry)

    warnings = []
    if not data.get("path_exists", False):
        warnings.append(f"{inventory_hostname}: instances path does not exist")
    if not directories_known:
        warnings.append(
            f"{inventory_hostname}: directory collection failed (rc={directories_rc})"
        )
    if not libvirt_known:
        warnings.append(
            f"{inventory_hostname}: libvirt collection failed (rc={libvirt_rc})"
        )

    rows = []
    for parts in parse_tab_lines(data.get("directories")):
        if len(parts) < 5:
            continue
        name, mtime_raw, uid, gid, mode = parts[:5]
        instance_uuid, kind = parse_directory_name(name)
        mtime = as_float(mtime_raw)
        age_days = max(0.0, (now - mtime) / 86400.0) if mtime is not None else None
        domain = domain_by_uuid.get(instance_uuid or "")
        row = {
            "compute": inventory_hostname,
            "host_names": host_names,
            "instances_path": as_text(data.get("instances_path")),
            "path": f"{as_text(data.get('instances_path'))}/{name}",
            "directory": name,
            "uuid": instance_uuid,
            "kind": kind,
            "mtime_epoch": mtime,
            "age_days": round(age_days, 2) if age_days is not None else None,
            "uid": uid,
            "gid": gid,
            "mode": mode,
            "size_bytes": sizes.get(name),
            "entries": entries_by_directory.get(name, []),
            "shared_storage": shared_storage,
            "mount": mount,
            "libvirt_collection_known": libvirt_known,
            "libvirt_domain": domain.get("name") if domain else "",
            "libvirt_state": domain.get("state") if domain else "",
            "libvirt_present": bool(domain),
            "libvirt_active": is_active_domain(domain.get("state", "")) if domain else False,
        }
        rows.append(row)
    return rows, warnings


def is_active_domain(state: str) -> bool:
    value = state.lower()
    return any(token in value for token in ("running", "paused", "blocked", "idle", "pmsuspended"))


def state_contains(server: dict[str, Any] | None, *tokens: str) -> bool:
    if not server:
        return False
    text = " ".join(
        as_text(server.get(key)).lower()
        for key in ("status", "task_state", "vm_state", "power_state")
    )
    return any(token in text for token in tokens)


def old_enough(row: dict[str, Any], min_age_days: float) -> bool:
    age = row.get("age_days")
    return age is not None and age >= min_age_days


def classify_row(
    row: dict[str, Any],
    server: dict[str, Any] | None,
    min_age_days: float,
) -> None:
    row["nova_host"] = server.get("host", "") if server else ""
    row["nova_status"] = server.get("status", "") if server else ""
    row["nova_task_state"] = server.get("task_state", "") if server else ""
    row["nova_vm_state"] = server.get("vm_state", "") if server else ""
    row["nova_record"] = bool(server)
    row["nova_deleted"] = bool(server and server.get("deleted"))
    row["nova_host_matches"] = host_matches(row["nova_host"], row["host_names"])
    row["reasons"] = []

    if row["kind"] == "other":
        row["classification"] = "NON_INSTANCE_DIRECTORY"
        row["reasons"].append("name is not a UUID, UUID_resize, or UUID_del directory")
        return

    if not row["libvirt_collection_known"]:
        row["classification"] = "INCOMPLETE_LIBVIRT_DATA"
        row["reasons"].append("libvirt collection failed; no stale decision is safe")
        return

    if row["libvirt_present"]:
        row["reasons"].append(
            f"libvirt domain {row['libvirt_domain']} exists ({row['libvirt_state'] or 'unknown state'})"
        )

    # A DELETED record is historical evidence, not an in-progress deletion.
    # Keep it available for stale-instance classification below.
    delete_context = bool(server and not server.get("deleted") and state_contains(server, "delet"))
    resize_context = state_contains(server, "resize", "migrat", "verify")

    if row["kind"] == "del":
        if row["libvirt_present"]:
            row["classification"] = "REVIEW_ACTIVE_OR_PERSISTENT_DOMAIN"
            row["reasons"].append("_del directory still has a libvirt domain")
        elif server and delete_context:
            row["classification"] = "DELETE_IN_PROGRESS_OR_STUCK"
            row["reasons"].append("Nova record indicates deletion-related state")
        elif old_enough(row, min_age_days):
            row["classification"] = "STALE_DELETE_CANDIDATE"
            row["reasons"].append("_del directory has no libvirt domain and exceeds age threshold")
        else:
            row["classification"] = "RECENT_DELETE_REVIEW"
            row["reasons"].append("_del directory is younger than the age threshold")
        return

    if row["kind"] == "resize":
        if row["libvirt_active"]:
            row["classification"] = "REVIEW_ACTIVE_SPECIAL_DIRECTORY"
            row["reasons"].append("resize directory has an active libvirt domain")
        elif server and resize_context:
            row["classification"] = "EXPECTED_RESIZE"
            row["reasons"].append("Nova record indicates resize/migration/verification context")
        elif not server or row["nova_deleted"]:
            if old_enough(row, min_age_days):
                row["classification"] = "STALE_RESIZE_CANDIDATE"
                row["reasons"].append("resize directory has no live Nova context and exceeds age threshold")
            else:
                row["classification"] = "RECENT_RESIZE_REVIEW"
                row["reasons"].append("resize directory has no live Nova context but is recent")
        else:
            row["classification"] = "REVIEW_RESIZE_DIRECTORY"
            row["reasons"].append("resize suffix exists without an obvious resize state")
        return

    if row["libvirt_present"]:
        if server and row["nova_host_matches"]:
            row["classification"] = "LIVE_OR_STOPPED"
            row["reasons"].append("Nova host matches the compute containing the libvirt domain")
        elif server:
            row["classification"] = "REVIEW_ACTIVE_DOMAIN_HOST_MISMATCH"
            row["reasons"].append("libvirt domain exists, but Nova host does not match this compute")
        else:
            row["classification"] = "REVIEW_ACTIVE_DOMAIN_NO_NOVA_RECORD"
            row["reasons"].append("libvirt domain exists without a matching Nova server record")
    elif server and row["nova_deleted"]:
        if old_enough(row, min_age_days):
            row["classification"] = "STALE_DELETED_INSTANCE_CANDIDATE"
            row["reasons"].append("deleted Nova record, no libvirt domain, and exceeds age threshold")
        else:
            row["classification"] = "RECENT_DELETED_INSTANCE_REVIEW"
            row["reasons"].append("deleted Nova record exists but directory is recent")
    elif server and delete_context:
        row["classification"] = "DELETE_IN_PROGRESS_OR_STUCK"
        row["reasons"].append("Nova record indicates deletion-related state")
    elif server and row["nova_host_matches"]:
        row["classification"] = "REVIEW_NO_LIBVIRT_DOMAIN"
        row["reasons"].append("Nova host matches, but no libvirt domain was found")
    elif server:
        row["classification"] = "REVIEW_HOST_MISMATCH"
        row["reasons"].append("directory is on a compute different from Nova's recorded host")
    elif old_enough(row, min_age_days):
        row["classification"] = "STALE_ORPHAN_CANDIDATE"
        row["reasons"].append("no Nova record, no libvirt domain, and exceeds age threshold")
    else:
        row["classification"] = "RECENT_ORPHAN_REVIEW"
        row["reasons"].append("no Nova record or libvirt domain, but directory is recent")


def annotate_duplicates(rows: list[dict[str, Any]]) -> None:
    by_uuid: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("uuid"):
            by_uuid[row["uuid"]].append(row)

    for instance_uuid, occurrences in by_uuid.items():
        computes = sorted({row["compute"] for row in occurrences})
        if len(computes) < 2:
            continue
        shared = all(row["shared_storage"] for row in occurrences)
        for row in occurrences:
            row["duplicate_compute_count"] = len(computes)
            row["duplicate_computes"] = computes
            if shared:
                row["reasons"].append(
                    "same UUID is visible on multiple computes, but instances_path appears shared"
                )
                continue

            row["reasons"].append(
                "same UUID appears on local storage on computes: " + ", ".join(computes)
            )

        active_owner = [
            row
            for row in occurrences
            if row["kind"] == "base"
            and row["libvirt_active"]
            and row["nova_host_matches"]
        ]
        if len(active_owner) == 1 and not shared:
            owner = active_owner[0]["compute"]
            for row in occurrences:
                if row is active_owner[0]:
                    row["reasons"].append("only active libvirt/Nova-host match in duplicate group")
                    continue
                if row["kind"] == "base" and not row["libvirt_present"]:
                    row["reasons"].append(f"likely non-owner; active owner is {owner}")
                    if row["classification"] in {
                        "STALE_ORPHAN_CANDIDATE",
                        "REVIEW_HOST_MISMATCH",
                        "RECENT_ORPHAN_REVIEW",
                    }:
                        row["classification"] = "DUPLICATE_NONOWNER_CANDIDATE"


def build_report(
    compute_dir: Path,
    active_paths: list[Path],
    deleted_paths: list[Path],
    min_age_days: float,
) -> dict[str, Any]:
    now = time.time()
    server_index = build_server_index(active_paths, deleted_paths)
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    compute_files = sorted(compute_dir.glob("*.json"))
    if not compute_files:
        warnings.append(f"no compute collection JSON files found under {compute_dir}")

    for path in compute_files:
        try:
            compute_rows, compute_warnings = parse_compute_file(path, now, min_age_days)
        except RuntimeError as exc:
            warnings.append(str(exc))
            continue
        rows.extend(compute_rows)
        warnings.extend(compute_warnings)

    for row in rows:
        classify_row(row, server_index.get(row.get("uuid", "")), min_age_days)
    annotate_duplicates(rows)

    classifications = Counter(row["classification"] for row in rows)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "inputs": {
            "compute_dir": str(compute_dir),
            "active_server_files": [str(path) for path in active_paths],
            "deleted_server_files": [str(path) for path in deleted_paths],
            "min_age_days": min_age_days,
        },
        "summary": {
            "compute_files": len(compute_files),
            "directory_rows": len(rows),
            "unique_uuids": len({row["uuid"] for row in rows if row.get("uuid")}),
            "duplicate_uuid_groups": len(
                {
                    uuid
                    for uuid, group in group_rows_by_uuid(rows).items()
                    if len({row["compute"] for row in group}) > 1
                }
            ),
            "classifications": dict(sorted(classifications.items())),
            "warnings": len(warnings),
        },
        "warnings": warnings,
        "rows": rows,
    }


def group_rows_by_uuid(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("uuid"):
            groups[row["uuid"]].append(row)
    return dict(groups)


def shorten_reason(row: dict[str, Any], width: int = 90) -> str:
    return shorten("; ".join(row.get("reasons", [])), width=width, placeholder="…")


def print_table(rows: list[dict[str, Any]], width: int) -> None:
    headers = [
        "compute",
        "directory",
        "kind",
        "age_days",
        "nova_host",
        "libvirt",
        "classification",
        "reasons",
    ]
    values = []
    for row in rows:
        values.append(
            [
                row["compute"],
                row["directory"],
                row["kind"],
                "" if row["age_days"] is None else f"{row['age_days']:.1f}",
                row.get("nova_host", ""),
                row.get("libvirt_state", "") or "-",
                row.get("classification", ""),
                shorten_reason(row),
            ]
        )

    widths = [max(len(headers[i]), *(len(row[i]) for row in values)) for i in range(len(headers))]
    if sum(widths) + 3 * (len(headers) - 1) > width:
        widths[1] = min(widths[1], 36)
        widths[4] = min(widths[4], 24)
        widths[6] = min(widths[6], 34)
        widths[7] = max(24, width - sum(widths[:7]) - 3 * (len(headers) - 1))
        widths[7] = max(24, widths[7])

    def render(row: list[str]) -> str:
        cells = []
        for index, value in enumerate(row):
            cell = shorten(value, width=widths[index], placeholder="…")
            cells.append(cell.ljust(widths[index]))
        return " | ".join(cells)

    print(render(headers))
    print("-+-".join("-" * value for value in widths))
    for row in values:
        print(render(row))


def print_csv(rows: list[dict[str, Any]]) -> None:
    fields = [
        "compute",
        "path",
        "directory",
        "uuid",
        "kind",
        "age_days",
        "size_bytes",
        "shared_storage",
        "nova_host",
        "nova_status",
        "nova_task_state",
        "nova_vm_state",
        "nova_host_matches",
        "libvirt_domain",
        "libvirt_state",
        "libvirt_present",
        "classification",
        "duplicate_compute_count",
        "duplicate_computes",
        "reasons",
    ]
    writer = csv.DictWriter(sys.stdout, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        output = dict(row)
        output["duplicate_computes"] = ",".join(row.get("duplicate_computes", []))
        output["reasons"] = "; ".join(row.get("reasons", []))
        writer.writerow(output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--compute-dir",
        type=Path,
        required=True,
        help="directory containing JSON files produced by audit_instances.yml",
    )
    parser.add_argument(
        "--servers",
        type=Path,
        action="append",
        default=[],
        help="active/non-deleted OpenStack server list JSON; repeatable",
    )
    parser.add_argument(
        "--deleted",
        type=Path,
        action="append",
        default=[],
        help="deleted OpenStack server list JSON; repeatable",
    )
    parser.add_argument(
        "--min-age-days",
        type=float,
        default=7.0,
        help="age before an orphan/special directory is called a candidate (default: 7)",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default="table",
        help="report format (default: table)",
    )
    parser.add_argument(
        "--findings-only",
        action="store_true",
        help="omit live, expected-resize, and non-instance rows",
    )
    parser.add_argument(
        "--width",
        type=int,
        default=160,
        help="maximum table width (default: 160)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.min_age_days < 0:
        print("--min-age-days must be non-negative", file=sys.stderr)
        return 2
    if args.width < 80:
        print("--width must be at least 80", file=sys.stderr)
        return 2
    if not args.compute_dir.is_dir():
        print(f"compute directory does not exist: {args.compute_dir}", file=sys.stderr)
        return 2

    try:
        report = build_report(args.compute_dir, args.servers, args.deleted, args.min_age_days)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    rows = report["rows"]
    if args.findings_only:
        rows = [
            row
            for row in rows
            if row.get("classification") not in NON_FINDING_CLASSIFICATIONS
        ]

    if args.format == "json":
        output = dict(report)
        output["rows"] = rows
        print(json.dumps(output, indent=2, sort_keys=True))
    elif args.format == "csv":
        print_csv(rows)
    else:
        print_table(rows, args.width)
        print()
        print(json.dumps(report["summary"], indent=2, sort_keys=True))
        if report["warnings"]:
            print("\nWarnings:")
            for warning in report["warnings"]:
                print(f"- {warning}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
