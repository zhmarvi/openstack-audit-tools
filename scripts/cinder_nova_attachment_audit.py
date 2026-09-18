#!/usr/bin/env python3
"""Audit Nova/Cinder volume attachment IDs for OpenStack project instances.

The script is intentionally read-only.  It uses the Compute API to find the
volumes currently attached to instances in a project, and then compares those
attachments with the Nova and Cinder database records:

* Nova: ``block_device_mapping.attachment_id``
* Cinder: ``volume_attachment.id`` (the Cinder attachment UUID)

Nova cells are separate databases in a cells v2 deployment.  By default, the
script reads the Nova cell database connection from ``/etc/nova/nova.conf``.
Pass every additional cell database URL with a repeated ``--nova-db-url`` or
point ``--nova-conf`` at each relevant configuration file.  Cinder normally
keeps its database connection in ``/etc/cinder/cinder.conf``; the script
reads that file automatically when it exists and also understands
Cinder-specific database sections in ``nova.conf``.

Exit status:
    0  No errors or warnings were found.
    1  The audit completed and found an inconsistency or warning.
    2  The audit could not complete (configuration, API, or database error).

Examples:

    python3 cinder_nova_attachment_audit.py \
        --os-cloud admin \
        --project-id 11111111-1111-1111-1111-111111111111 \
        --nova-db-url 'mysql+pymysql://audit:***@nova-db/nova_cell1' \
        --nova-db-url 'mysql+pymysql://audit:***@nova-db/nova_cell2' \
        --cinder-db-url 'mysql+pymysql://audit:***@cinder-db/cinder'

    Audit every project (requires permission to list all projects):

    python3 cinder_nova_attachment_audit.py --all-projects

    If the deployment keeps all database settings in one file, specify it for
    both services:

    python3 cinder_nova_attachment_audit.py \
        --all-projects \
        --nova-conf /etc/nova/nova.conf \
        --cinder-conf /etc/nova/nova.conf

Use ``--format table`` for the default human-readable tabular output or
``--format json`` for machine-readable output.  Explicit database URLs and the
``NOVA_DB_URL``/``CINDER_DB_URL`` environment variables remain supported and
override configuration-file discovery.  The script never prints the database
URLs it reads.  The account in each URL only needs SELECT access to the
relevant tables.
"""

from __future__ import annotations

import argparse
import configparser
import datetime as dt
import json
import os
import re
import shutil
import sys
import textwrap
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any


class AuditError(RuntimeError):
    """Raised when the audit cannot safely produce a complete result."""


def _normalize(value: Any) -> str | None:
    """Return a normalized identifier/status value, or None for blank data."""

    if value is None:
        return None
    text = str(value).strip()
    return text.lower() if text else None


def _json_safe(value: Any) -> Any:
    """Convert common database/API values into JSON-compatible values."""

    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return str(value)
    return value


def _resource_value(resource: Any, *names: str) -> Any:
    """Get a value from an SDK resource, accepting API and SDK key styles."""

    data: dict[str, Any] = {}
    if isinstance(resource, Mapping):
        data.update(resource)
    else:
        to_dict = getattr(resource, "to_dict", None)
        if callable(to_dict):
            try:
                converted = to_dict()
                if isinstance(converted, Mapping):
                    data.update(converted)
            except Exception:
                # Attribute access below can still work for SDK resources.
                pass

    for name in names:
        if name in data and data[name] is not None:
            return data[name]
    for name in names:
        try:
            value = getattr(resource, name)
        except (AttributeError, KeyError, TypeError):
            continue
        if value is not None:
            return value
    return None


def _row_value(row: Mapping[str, Any], name: str) -> Any:
    return row.get(name)


def _is_deleted(row: Mapping[str, Any]) -> bool:
    value = _row_value(row, "deleted")
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"", "0", "false", "no", "none", "null"}:
        return False
    try:
        return int(text) != 0
    except ValueError:
        return True


def _pair(instance_id: Any, volume_id: Any) -> tuple[str | None, str | None]:
    return _normalize(instance_id), _normalize(volume_id)


def _sanitize_error(error: BaseException) -> str:
    """Avoid accidentally echoing a password embedded in a DB/API error."""

    message = str(error) or error.__class__.__name__
    return re.sub(
        r"(://[^:/@]+:)[^@/]+(@)",
        r"\1***\2",
        message,
    )


def _table(engine: Any, table_name: str, required: Sequence[str]) -> tuple[Any, list[str]]:
    """Reflect a table and fail clearly if this deployment lacks required fields."""

    try:
        inspector = _sa.inspect(engine)
        if not inspector.has_table(table_name):
            raise AuditError(f"table {table_name!r} does not exist")
        reflected = _sa.Table(
            table_name,
            _sa.MetaData(),
            autoload_with=engine,
        )
    except AuditError:
        raise
    except Exception as error:
        raise AuditError(
            f"could not inspect table {table_name!r}: {_sanitize_error(error)}"
        ) from error

    missing = [name for name in required if name not in reflected.c]
    if missing:
        raise AuditError(
            f"table {table_name!r} is missing required column(s): "
            + ", ".join(missing)
        )
    selected = [
        name
        for name in (
            "id",
            "uuid",
            "instance_uuid",
            "volume_id",
            "attachment_id",
            "device_name",
            "attach_status",
            "attached_host",
            "mountpoint",
            "deleted",
            "attach_time",
            "detach_time",
            "updated_at",
        )
        if name in reflected.c
    ]
    return reflected, selected


def _read_rows(
    engine: Any,
    table: Any,
    selected: Sequence[str],
    column_name: str,
    values: Sequence[str],
    chunk_size: int = 500,
) -> list[dict[str, Any]]:
    """Read rows using bounded IN lists and never modify the database."""

    if not values:
        return []
    column = table.c[column_name]
    rows: list[dict[str, Any]] = []
    for start in range(0, len(values), chunk_size):
        chunk = list(values[start : start + chunk_size])
        statement = _sa.select(*(table.c[name] for name in selected)).where(
            column.in_(chunk)
        )
        try:
            with engine.connect() as connection:
                result = connection.execute(statement)
                for row in result:
                    mapping = row._mapping
                    rows.append({name: _json_safe(mapping.get(name)) for name in selected})
        except Exception as error:
            raise AuditError(
                f"could not read {table.name}.{column_name}: {_sanitize_error(error)}"
            ) from error
    return rows


def _dedupe_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Merge rows returned by overlapping instance/volume/id queries."""

    result: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in rows:
        row_id = _normalize(row.get("id"))
        key = (row_id,) if row_id is not None else tuple(sorted(row.items()))
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(row))
    return result


def _load_nova_rows(
    db_url: str,
    db_label: str,
    instance_ids: Sequence[str],
) -> list[dict[str, Any]]:
    engine = None
    try:
        engine = _sa.create_engine(db_url, pool_pre_ping=True)
        table, selected = _table(
            engine,
            "block_device_mapping",
            ("instance_uuid", "volume_id", "attachment_id"),
        )
        rows = _read_rows(
            engine,
            table,
            selected,
            "instance_uuid",
            list(instance_ids),
        )
        for row in rows:
            row["database"] = db_label
            row["deleted_row"] = _is_deleted(row)
        return rows
    except AuditError as error:
        raise AuditError(f"Nova database {db_label}: {_sanitize_error(error)}") from error
    except Exception as error:
        raise AuditError(f"Nova database {db_label}: {_sanitize_error(error)}") from error
    finally:
        if engine is not None:
            engine.dispose()


def _load_cinder_rows(
    db_url: str,
    db_label: str,
    instance_ids: Sequence[str],
    volume_ids: Sequence[str],
    attachment_ids: Sequence[str],
) -> list[dict[str, Any]]:
    engine = None
    try:
        engine = _sa.create_engine(db_url, pool_pre_ping=True)
        table, selected = _table(
            engine,
            "volume_attachment",
            ("id", "volume_id", "instance_uuid"),
        )
        rows: list[dict[str, Any]] = []
        rows.extend(
            _read_rows(
                engine,
                table,
                selected,
                "instance_uuid",
                list(instance_ids),
            )
        )
        rows.extend(
            _read_rows(
                engine,
                table,
                selected,
                "volume_id",
                list(volume_ids),
            )
        )
        rows.extend(
            _read_rows(
                engine,
                table,
                selected,
                "id",
                list(attachment_ids),
            )
        )
        rows = _dedupe_rows(rows)
        for row in rows:
            row["database"] = db_label
            row["deleted_row"] = _is_deleted(row)
        return rows
    except AuditError as error:
        raise AuditError(
            f"Cinder database {db_label}: {_sanitize_error(error)}"
        ) from error
    except Exception as error:
        raise AuditError(f"Cinder database {db_label}: {_sanitize_error(error)}") from error
    finally:
        if engine is not None:
            engine.dispose()


def _add_finding(
    record: dict[str, Any],
    code: str,
    severity: str,
    message: str,
    **details: Any,
) -> None:
    findings = record.setdefault("findings", [])
    key = (code, message)
    existing = record.setdefault("_finding_keys", set())
    if key in existing:
        return
    existing.add(key)
    finding: dict[str, Any] = {
        "code": code,
        "severity": severity,
        "message": message,
    }
    if details:
        finding["details"] = _json_safe(details)
    findings.append(finding)


def _active(rows: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [row for row in rows if not row.get("deleted_row", False)]


def _rows_for_pair(
    rows: Sequence[Mapping[str, Any]],
    instance_id: str,
    volume_id: str,
) -> list[Mapping[str, Any]]:
    wanted = _pair(instance_id, volume_id)
    return [
        row
        for row in rows
        if _pair(row.get("instance_uuid"), row.get("volume_id")) == wanted
    ]


def _index_by_id(rows: Sequence[Mapping[str, Any]]) -> dict[str, list[Mapping[str, Any]]]:
    index: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        value = _normalize(row.get("id"))
        if value is not None:
            index[value].append(row)
    return index


def _index_by_bdm_uuid(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    index: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        value = _normalize(row.get("uuid"))
        if value is not None:
            index[value].append(row)
    return index


def _audit_api_record(
    record: dict[str, Any],
    nova_rows: Sequence[Mapping[str, Any]],
    cinder_rows: Sequence[Mapping[str, Any]],
    cinder_by_id: Mapping[str, Sequence[Mapping[str, Any]]],
    nova_by_bdm_uuid: Mapping[str, Sequence[Mapping[str, Any]]],
) -> None:
    instance_id = record["instance_id"]
    volume_id = record["volume_id"]
    record.setdefault("findings", [])
    api_attachment_id = _normalize(record.get("api_attachment_id"))
    api_bdm_uuid = _normalize(record.get("api_bdm_uuid"))

    active_nova = _active(_rows_for_pair(nova_rows, instance_id, volume_id))
    all_nova_pair = _rows_for_pair(nova_rows, instance_id, volume_id)
    active_cinder = _active(_rows_for_pair(cinder_rows, instance_id, volume_id))
    all_cinder_volume = [
        row
        for row in cinder_rows
        if _normalize(row.get("volume_id")) == _normalize(volume_id)
    ]

    record["nova_bdm_rows"] = _json_safe(all_nova_pair)
    record["cinder_attachment_rows_for_volume_instance"] = _json_safe(
        active_cinder
    )
    record["expected_active_cinder_attachment_ids"] = [
        _normalize(row.get("id"))
        for row in active_cinder
        if _normalize(row.get("id")) is not None
    ]

    if not active_nova:
        if all_nova_pair:
            _add_finding(
                record,
                "NOVA_BDM_ONLY_SOFT_DELETED",
                "ERROR",
                "The API reports the volume attached, but every matching Nova BDM row is soft-deleted.",
            )
        else:
            _add_finding(
                record,
                "NOVA_BDM_MISSING",
                "ERROR",
                "The API reports the volume attached, but no active Nova BDM row exists for the instance and volume.",
            )
    elif len(active_nova) > 1:
        _add_finding(
            record,
            "MULTIPLE_ACTIVE_NOVA_BDM",
            "ERROR",
            "More than one active Nova BDM row exists for this instance and volume.",
            count=len(active_nova),
        )

    if api_bdm_uuid:
        matching_bdm = list(nova_by_bdm_uuid.get(api_bdm_uuid, ()))
        if not matching_bdm:
            _add_finding(
                record,
                "API_BDM_NOT_IN_NOVA",
                "ERROR",
                "The bdm_uuid returned by Nova is not present in the supplied Nova database(s).",
                bdm_uuid=api_bdm_uuid,
            )
        else:
            if all(row.get("deleted_row", False) for row in matching_bdm):
                _add_finding(
                    record,
                    "API_BDM_SOFT_DELETED_IN_NOVA",
                    "ERROR",
                    "The bdm_uuid returned by Nova resolves only to a soft-deleted Nova BDM row.",
                    bdm_uuid=api_bdm_uuid,
                )
            for row in matching_bdm:
                if _pair(row.get("instance_uuid"), row.get("volume_id")) != _pair(
                    instance_id, volume_id
                ):
                    _add_finding(
                        record,
                        "API_BDM_PAIR_MISMATCH",
                        "ERROR",
                        "Nova returned a BDM UUID whose database row belongs to a different instance or volume.",
                        bdm_uuid=api_bdm_uuid,
                        nova_instance_uuid=row.get("instance_uuid"),
                        nova_volume_id=row.get("volume_id"),
                    )

    active_nova_attachment_ids: set[str] = set()
    for row in active_nova:
        nova_attachment_id = _normalize(row.get("attachment_id"))
        if nova_attachment_id is None:
            _add_finding(
                record,
                "NOVA_ATTACHMENT_ID_MISSING",
                "ERROR",
                "The active Nova BDM row has no attachment_id.",
                nova_bdm_id=row.get("id"),
            )
            continue
        active_nova_attachment_ids.add(nova_attachment_id)
        referenced_cinder = list(cinder_by_id.get(nova_attachment_id, ()))
        if not referenced_cinder:
            _add_finding(
                record,
                "NOVA_ATTACHMENT_ID_NOT_IN_CINDER",
                "ERROR",
                "Nova's attachment_id does not resolve to any Cinder volume_attachment row.",
                attachment_id=nova_attachment_id,
            )
        for cinder_row in referenced_cinder:
            if cinder_row.get("deleted_row", False):
                _add_finding(
                    record,
                    "NOVA_ATTACHMENT_ID_SOFT_DELETED_IN_CINDER",
                    "ERROR",
                    "Nova's attachment_id resolves only to a soft-deleted Cinder attachment row.",
                    attachment_id=nova_attachment_id,
                )
            if _normalize(cinder_row.get("volume_id")) != _normalize(volume_id):
                _add_finding(
                    record,
                    "CINDER_ATTACHMENT_VOLUME_MISMATCH",
                    "ERROR",
                    "Nova's attachment_id points to a Cinder attachment for a different volume.",
                    attachment_id=nova_attachment_id,
                    cinder_volume_id=cinder_row.get("volume_id"),
                )
            if _normalize(cinder_row.get("instance_uuid")) != _normalize(instance_id):
                _add_finding(
                    record,
                    "CINDER_ATTACHMENT_INSTANCE_MISMATCH",
                    "ERROR",
                    "Nova's attachment_id points to a Cinder attachment for a different or missing instance UUID.",
                    attachment_id=nova_attachment_id,
                    cinder_instance_uuid=cinder_row.get("instance_uuid"),
                )

    if api_attachment_id:
        record["api_attachment_id"] = api_attachment_id
        api_cinder_rows = list(cinder_by_id.get(api_attachment_id, ()))
        if not api_cinder_rows:
            _add_finding(
                record,
                "API_ATTACHMENT_ID_NOT_IN_CINDER",
                "ERROR",
                "The attachment_id returned by Nova is not present in the supplied Cinder database(s).",
                attachment_id=api_attachment_id,
            )
        if active_nova and api_attachment_id not in active_nova_attachment_ids:
            _add_finding(
                record,
                "API_NOVA_ATTACHMENT_ID_MISMATCH",
                "ERROR",
                "Nova's API attachment_id differs from the attachment_id stored in its active BDM row.",
                api_attachment_id=api_attachment_id,
                nova_attachment_ids=sorted(active_nova_attachment_ids),
            )

    if not active_cinder:
        if all_cinder_volume:
            _add_finding(
                record,
                "CINDER_ATTACHMENT_ONLY_SOFT_DELETED",
                "ERROR",
                "The API reports the volume attached, but no active Cinder attachment row matches both instance and volume.",
            )
        else:
            _add_finding(
                record,
                "CINDER_ATTACHMENT_MISSING",
                "ERROR",
                "The API reports the volume attached, but Cinder has no attachment row matching both instance and volume.",
            )
        # A row for the volume without instance_uuid is useful evidence: it
        # means the attachment was created but never completed for this VM.
        for row in all_cinder_volume:
            if not _normalize(row.get("instance_uuid")):
                _add_finding(
                    record,
                    "CINDER_INSTANCE_UUID_MISSING",
                    "ERROR",
                    "A Cinder attachment exists for the volume but its instance_uuid is blank.",
                    cinder_attachment_id=row.get("id"),
                )
    elif len(active_cinder) > 1:
        _add_finding(
            record,
            "MULTIPLE_ACTIVE_CINDER_ATTACHMENTS",
            "ERROR",
            "More than one active Cinder attachment row exists for this instance and volume.",
            count=len(active_cinder),
        )

    for row in active_cinder:
        status = _normalize(row.get("attach_status"))
        if status and status != "attached":
            _add_finding(
                record,
                "CINDER_ATTACHMENT_STATUS_NOT_ATTACHED",
                "WARN",
                "The matching Cinder attachment row is not in attach_status=attached.",
                cinder_attachment_id=row.get("id"),
                attach_status=row.get("attach_status"),
            )

    expected_ids = {
        _normalize(row.get("id"))
        for row in active_cinder
        if _normalize(row.get("id")) is not None
    }
    if expected_ids and active_nova_attachment_ids.isdisjoint(expected_ids):
        _add_finding(
            record,
            "NOVA_CINDER_ATTACHMENT_ID_MISMATCH",
            "ERROR",
            "The active Nova BDM attachment_id does not match any active Cinder attachment ID for the instance and volume.",
            nova_attachment_ids=sorted(active_nova_attachment_ids),
            cinder_attachment_ids=sorted(expected_ids),
        )

    if active_cinder and api_attachment_id:
        if api_attachment_id not in expected_ids:
            _add_finding(
                record,
                "API_CINDER_ATTACHMENT_ID_MISMATCH",
                "ERROR",
                "Nova's API attachment_id does not match an active Cinder attachment for the instance and volume.",
                api_attachment_id=api_attachment_id,
                cinder_attachment_ids=sorted(expected_ids),
            )

    record.pop("_finding_keys", None)
    if any(f["severity"] == "ERROR" for f in record["findings"]):
        record["status"] = "ERROR"
    elif record["findings"]:
        record["status"] = "WARN"
    else:
        record["status"] = "OK"


def _make_api_inventory(conn: Any, project_id: str | None, all_projects: bool) -> tuple[
    list[dict[str, Any]], list[str], list[dict[str, str]]
]:
    """Return API attachment records, instance UUIDs, and operational errors."""

    try:
        list_kwargs: dict[str, Any] = {
            "detailed": True,
            "all_projects": all_projects,
            "bare": True,
        }
        if project_id:
            list_kwargs["filters"] = {"project_id": project_id}
        servers = conn.list_servers(**list_kwargs)
    except Exception as error:
        raise AuditError(f"could not list Nova servers: {_sanitize_error(error)}") from error

    records: list[dict[str, Any]] = []
    instance_ids: list[str] = []
    errors: list[dict[str, str]] = []
    normalized_project_id = _normalize(project_id)
    for server in servers:
        instance_id = _normalize(_resource_value(server, "id", "server_id"))
        if not instance_id:
            errors.append(
                {
                    "scope": "server-list",
                    "message": "Nova returned a server without an ID",
                }
            )
            continue
        server_project = _normalize(
            _resource_value(server, "project_id", "tenant_id", "projectId")
        )
        # A project-scoped token may not return project_id.  In that mode the
        # server list is already scoped.  When a target project was supplied,
        # an all-projects response must expose the field so a server from
        # another project cannot enter the audit.  With no target project,
        # every server returned by the all-projects listing is in scope.
        if project_id and all_projects and not server_project:
            errors.append(
                {
                    "scope": instance_id,
                    "message": "all-projects server result did not include project_id; server was skipped",
                }
            )
            continue
        if normalized_project_id and server_project and server_project != normalized_project_id:
            continue
        instance_ids.append(instance_id)
        try:
            attachments = conn.compute.volume_attachments(instance_id)
            for attachment in attachments:
                # At compute microversion 2.89+, attachment_id and bdm_uuid
                # are returned.  Before that, id is the volume ID, not the
                # Cinder attachment ID, so it is deliberately only a fallback
                # for volume_id.
                volume_id = _normalize(
                    _resource_value(attachment, "volume_id", "volumeId", "id")
                )
                if not volume_id:
                    errors.append(
                        {
                            "scope": instance_id,
                            "message": "Nova returned an attachment without a volume ID",
                        }
                    )
                    continue
                records.append(
                    {
                        "instance_id": instance_id,
                        "project_id": server_project,
                        "instance_name": _resource_value(server, "name"),
                        "instance_status": _resource_value(server, "status"),
                        "volume_id": volume_id,
                        "device": _resource_value(
                            attachment, "device", "mountpoint"
                        ),
                        "api_attachment_id": _resource_value(
                            attachment, "attachment_id", "attachmentId"
                        ),
                        "api_bdm_uuid": _resource_value(
                            attachment, "bdm_uuid", "bdmUuid"
                        ),
                    }
                )
        except Exception as error:
            errors.append(
                {
                    "scope": instance_id,
                    "message": f"could not list volume attachments: {_sanitize_error(error)}",
                }
            )
    return records, instance_ids, errors


def _summary(
    records: Sequence[Mapping[str, Any]],
    database_only: Sequence[Any],
    ignored_nova_bdm_rows: int,
) -> dict[str, int]:
    return {
        "instances_with_api_attachments": len(
            {_normalize(record.get("instance_id")) for record in records}
            - {None}
        ),
        "api_volume_attachments": len(records),
        "records_ok": sum(record.get("status") == "OK" for record in records),
        "records_warn": sum(record.get("status") == "WARN" for record in records),
        "records_error": sum(record.get("status") == "ERROR" for record in records),
        "database_only_findings": len(database_only),
        "ignored_nova_bdm_rows_without_volume_id": ignored_nova_bdm_rows,
    }


def audit(args: argparse.Namespace) -> dict[str, Any]:
    """Run the complete audit and return a JSON-serializable report."""

    nova_conf_paths = _config_paths(
        args.nova_conf,
        "NOVA_CONF",
        "/etc/nova/nova.conf",
    )
    nova_config_sources = [(path, True) for path in nova_conf_paths]

    # Cinder normally has its own config file.  If it is not present, also
    # inspect nova.conf for explicitly Cinder-named settings, without treating
    # Nova's [database] connection as a Cinder URL by mistake.
    if args.cinder_conf or os.environ.get("CINDER_CONF"):
        cinder_conf_paths = _config_paths(
            args.cinder_conf,
            "CINDER_CONF",
            "/etc/cinder/cinder.conf",
        )
        nova_conf_identities = {os.path.realpath(path) for path in nova_conf_paths}
        cinder_config_sources = [
            (path, os.path.realpath(path) not in nova_conf_identities)
            for path in cinder_conf_paths
        ]
    elif os.path.isfile("/etc/cinder/cinder.conf"):
        cinder_config_sources = [("/etc/cinder/cinder.conf", True)]
        cinder_config_sources.extend((path, False) for path in nova_conf_paths)
    else:
        cinder_config_sources = [(path, False) for path in nova_conf_paths]

    nova_urls = _database_urls(
        args.nova_db_url,
        "NOVA_DB_URL",
        nova_config_sources,
        "nova",
    )
    cinder_urls = _database_urls(
        args.cinder_db_url,
        "CINDER_DB_URL",
        cinder_config_sources,
        "cinder",
    )
    if not nova_urls:
        raise AuditError(
            "no Nova cell database URL found; set [database] connection in "
            f"{', '.join(nova_conf_paths)}, or use --nova-db-url/NOVA_DB_URL"
        )
    if not cinder_urls:
        raise AuditError(
            "no Cinder database URL found; set [database] connection in "
            "/etc/cinder/cinder.conf, or a Cinder-specific database setting in "
            f"{', '.join(nova_conf_paths)}, or use --cinder-db-url/CINDER_DB_URL"
        )

    try:
        import openstack
    except ImportError as error:
        raise AuditError(
            "openstacksdk is required; install dependencies from requirements.txt"
        ) from error

    try:
        connection_kwargs = {"compute_api_version": args.compute_api_version}
        conn = openstack.connect(cloud=args.os_cloud, **connection_kwargs)
    except Exception as error:
        raise AuditError(f"could not connect to OpenStack: {_sanitize_error(error)}") from error

    api_records, instance_ids, api_errors = _make_api_inventory(
        conn,
        args.project_id,
        args.all_projects,
    )
    project_instances = sorted(set(instance_ids))
    api_volume_ids = sorted(
        {
            _normalize(record.get("volume_id"))
            for record in api_records
            if _normalize(record.get("volume_id"))
        }
    )

    nova_rows: list[dict[str, Any]] = []
    cinder_rows: list[dict[str, Any]] = []
    database_errors: list[str] = []
    for index, url in enumerate(nova_urls, start=1):
        try:
            nova_rows.extend(
                _load_nova_rows(url, f"nova-cell-{index}", project_instances)
            )
        except AuditError as error:
            database_errors.append(str(error))

    relevant_attachment_ids = sorted(
        {
            _normalize(row.get("attachment_id"))
            for row in nova_rows
            if _normalize(row.get("attachment_id"))
        }
        | {
            _normalize(record.get("api_attachment_id"))
            for record in api_records
            if _normalize(record.get("api_attachment_id"))
        }
    )
    nova_volume_ids = sorted(
        {
            _normalize(row.get("volume_id"))
            for row in nova_rows
            if _normalize(row.get("volume_id"))
        }
    )
    relevant_volume_ids = sorted(set(api_volume_ids) | set(nova_volume_ids))

    for index, url in enumerate(cinder_urls, start=1):
        try:
            cinder_rows.extend(
                _load_cinder_rows(
                    url,
                    f"cinder-{index}",
                    project_instances,
                    relevant_volume_ids,
                    relevant_attachment_ids,
                )
            )
        except AuditError as error:
            database_errors.append(str(error))

    cinder_by_id = _index_by_id(cinder_rows)
    nova_by_bdm_uuid = _index_by_bdm_uuid(nova_rows)
    for record in api_records:
        _audit_api_record(
            record,
            nova_rows,
            cinder_rows,
            cinder_by_id,
            nova_by_bdm_uuid,
        )

    normalized_project_instances = {
        _normalize(item) for item in project_instances
    }
    api_pairs = {
        _pair(record.get("instance_id"), record.get("volume_id"))
        for record in api_records
    }
    database_only: list[dict[str, Any]] = []
    ignored_nova_bdm_rows = 0
    for row in _active(nova_rows):
        # Nova also stores non-Cinder block devices in this table. Rows with
        # no volume_id are not Cinder volume attachments and cannot be
        # meaningfully compared with the Compute volume-attachment API.
        if not _normalize(row.get("volume_id")):
            ignored_nova_bdm_rows += 1
            continue
        pair = _pair(row.get("instance_uuid"), row.get("volume_id"))
        if pair[0] in normalized_project_instances and pair not in api_pairs:
            database_only.append(
                {
                    "source": "nova",
                    "code": "NOVA_BDM_NOT_IN_NOVA_API",
                    "severity": "WARN",
                    "message": "An active Nova volume BDM for a project instance is absent from Nova's current attachment API inventory.",
                    "database": row.get("database"),
                    "instance_id": row.get("instance_uuid"),
                    "volume_id": row.get("volume_id"),
                    "attachment_id": row.get("attachment_id"),
                    "nova_bdm_id": row.get("id"),
                }
            )
    for row in _active(cinder_rows):
        pair = _pair(row.get("instance_uuid"), row.get("volume_id"))
        if pair[0] in normalized_project_instances and pair not in api_pairs:
            database_only.append(
                {
                    "source": "cinder",
                    "code": "CINDER_ATTACHMENT_NOT_IN_NOVA_API",
                    "severity": "WARN",
                    "message": "An active Cinder attachment for a project instance is absent from Nova's current attachment API inventory.",
                    "database": row.get("database"),
                    "instance_id": row.get("instance_uuid"),
                    "volume_id": row.get("volume_id"),
                    "attachment_id": row.get("id"),
                }
            )

    for record in api_records:
        if record.get("status") == "OK":
            record.pop("nova_bdm_rows", None)
            record.pop("cinder_attachment_rows_for_volume_instance", None)

    report: dict[str, Any] = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "project_id": args.project_id,
        "project_scope": (
            f"PROJECT:{args.project_id}"
            if args.project_id
            else "ALL_PROJECTS" if args.all_projects else "AUTH_SCOPED"
        ),
        "compute_api_version": args.compute_api_version,
        "read_only": True,
        "summary": _summary(
            api_records,
            database_only,
            ignored_nova_bdm_rows,
        ),
        "records": api_records,
        "database_only": database_only,
        "operational_errors": api_errors + [
            {"scope": "database", "message": message} for message in database_errors
        ],
    }
    return report


def _config_paths(
    cli_values: Sequence[str] | None,
    env_name: str,
    default: str,
) -> list[str]:
    """Resolve configuration paths without exposing configuration contents."""

    if cli_values:
        return [value for value in cli_values if value]
    env_value = os.environ.get(env_name)
    if env_value:
        return [value for value in env_value.split(os.pathsep) if value]
    return [default]


def _read_config_file(path: str) -> configparser.ConfigParser:
    """Read an OpenStack INI-style config without interpolating secrets."""

    config = configparser.ConfigParser(interpolation=None, strict=False)
    config.optionxform = str.lower
    try:
        with open(path, encoding="utf-8") as config_file:
            config.read_file(config_file)
    except FileNotFoundError as error:
        raise AuditError(f"configuration file not found: {path}") from error
    except PermissionError as error:
        raise AuditError(f"permission denied reading configuration file: {path}") from error
    except configparser.Error as error:
        # ConfigParser errors can include the offending line, which could
        # contain a database password.  Report only the exception type.
        raise AuditError(
            f"could not parse configuration file {path}: {error.__class__.__name__}"
        ) from error
    except OSError as error:
        raise AuditError(
            f"could not read configuration file {path}: {error.__class__.__name__}"
        ) from error
    return config


def _config_section(
    config: configparser.ConfigParser,
    section_name: str,
) -> Mapping[str, str] | None:
    wanted = section_name.lower()
    for actual_name in config.sections():
        if actual_name.lower() == wanted:
            return config[actual_name]
    if wanted == "default":
        return config.defaults()
    return None


def _clean_config_value(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1].strip()
    if not value or value.lower() in {"<none>", "none", "null"}:
        return None
    return value


def _urls_from_config(
    path: str,
    service: str,
    include_standard_database_section: bool = True,
) -> list[str]:
    """Extract database URLs from a Nova or Cinder config file.

    Nova's standard database setting is ``[database] connection``.  Cinder
    normally uses the same setting in ``cinder.conf``.  When a Nova config is
    used as the Cinder source, only explicitly Cinder-named sections/options
    are considered so Nova's own database URL is never accidentally reused.
    """

    config = _read_config_file(path)
    values: list[str] = []
    seen: set[str] = set()

    def add_section_values(section_name: str, options: Sequence[str]) -> None:
        section = _config_section(config, section_name)
        if section is None:
            return
        for option in options:
            value = _clean_config_value(section.get(option))
            if value and value not in seen:
                seen.add(value)
                values.append(value)

    if service == "nova":
        if include_standard_database_section:
            add_section_values("database", ("connection", "sql_connection"))
            add_section_values("sql", ("connection",))
            add_section_values("default", ("sql_connection",))

        # A few deployments keep per-cell settings in explicitly named
        # sections.  Do not include api_database: it is not a cell BDM DB.
        for section_name in config.sections():
            lower_name = section_name.lower()
            if (
                lower_name in {"nova_database", "nova_db"}
                or (lower_name.startswith("cell") and lower_name.endswith("_database"))
            ):
                add_section_values(section_name, ("connection", "sql_connection"))
    elif service == "cinder":
        if include_standard_database_section:
            add_section_values("database", ("connection", "sql_connection"))
            add_section_values("sql", ("connection",))
            add_section_values("default", ("sql_connection",))

        for section_name in config.sections():
            lower_name = section_name.lower()
            if lower_name in {
                "cinder",
                "cinder_database",
                "cinder_db",
                "cinder_database_connection",
                "block_storage_database",
                "volume_database",
            }:
                add_section_values(
                    section_name,
                    (
                        "connection",
                        "sql_connection",
                        "db_connection",
                        "database_connection",
                    ),
                )
        add_section_values(
            "default",
            (
                "cinder_connection",
                "cinder_db_connection",
                "cinder_database_connection",
            ),
        )
    else:
        raise ValueError(f"unsupported database service: {service}")

    return values


def _database_urls(
    cli_values: Sequence[str] | None,
    env_name: str,
    config_sources: Sequence[tuple[str, bool]],
    service: str,
) -> list[str]:
    """Resolve URLs in precedence order: CLI, environment, then config."""

    if cli_values:
        return [value for value in cli_values if value]
    env_value = os.environ.get(env_name)
    if env_value:
        return [env_value]

    values: list[str] = []
    seen: set[str] = set()
    for path, include_standard_database_section in config_sources:
        for value in _urls_from_config(
            path,
            service,
            include_standard_database_section,
        ):
            if value not in seen:
                seen.add(value)
                values.append(value)
    return values


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only Nova/Cinder attachment ID consistency audit."
    )
    parser.add_argument(
        "--os-cloud",
        default=os.environ.get("OS_CLOUD"),
        help="cloud name from clouds.yaml (default: OS_CLOUD or SDK defaults)",
    )
    parser.add_argument(
        "--project-id",
        default=os.environ.get("OS_PROJECT_ID"),
        help="project UUID to audit; omit with --all-projects to audit every project (default: OS_PROJECT_ID)",
    )
    parser.add_argument(
        "--compute-api-version",
        default="2.89",
        help="Nova compute microversion; 2.89 exposes attachment_id and bdm_uuid (default: 2.89)",
    )
    parser.add_argument(
        "--nova-db-url",
        action="append",
        help="Nova cell DB SQLAlchemy URL; repeat once per cell (overrides config and NOVA_DB_URL)",
    )
    parser.add_argument(
        "--cinder-db-url",
        action="append",
        help="Cinder DB SQLAlchemy URL (overrides config and CINDER_DB_URL)",
    )
    parser.add_argument(
        "--nova-conf",
        action="append",
        default=None,
        help=(
            "Nova config file to read; repeat for additional cell configs "
            "(default: NOVA_CONF or /etc/nova/nova.conf)"
        ),
    )
    parser.add_argument(
        "--cinder-conf",
        action="append",
        default=None,
        help=(
            "Cinder config file to read; repeat for additional configs "
            "(default: CINDER_CONF, /etc/cinder/cinder.conf, or Cinder-specific "
            "settings in nova.conf)"
        ),
    )
    project_scope = parser.add_mutually_exclusive_group()
    project_scope.add_argument(
        "--all-projects",
        dest="all_projects",
        action="store_true",
        default=True,
        help="use an all-projects server listing; with --project-id, limit results to that project (default)",
    )
    project_scope.add_argument(
        "--no-all-projects",
        dest="all_projects",
        action="store_false",
        help="use the current auth-scoped project listing; useful with non-admin credentials",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "text"),
        default="table",
        help="output format: table (default), json, or text",
    )
    parser.add_argument(
        "--width",
        type=int,
        default=None,
        help="table width in terminal columns; defaults to the detected shell width",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="include OK records in table output",
    )
    return parser


def _display_cell(value: Any) -> str:
    """Convert a report value into a safe, readable table cell."""

    if value is None:
        return "-"
    if isinstance(value, (Mapping, list, tuple, set)):
        value = json.dumps(_json_safe(value), sort_keys=True, separators=(",", ":"))
    text = str(value).strip()
    return text if text else "-"


def _render_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    max_widths: Mapping[str, int] | None = None,
    table_width: int | None = None,
    min_widths: Mapping[str, int] | None = None,
) -> str:
    """Render a dependency-free table that fits within ``table_width``."""

    header_values = [_display_cell(header) for header in headers]
    cell_rows = [
        [_display_cell(value) for value in row]
        for row in rows
    ]
    widths: list[int] = []
    for index, header in enumerate(header_values):
        natural_width = max(
            [len(header)]
            + [
                max((len(part) for part in row[index].splitlines()), default=0)
                for row in cell_rows
                if index < len(row)
            ]
        )
        limit = (max_widths or {}).get(header, 40)
        widths.append(max(1, min(natural_width, limit)))

    if table_width:
        overhead = 3 * len(headers) + 1
        available = max(1, table_width - overhead)
        minimums = [
            max(1, min(widths[index], (min_widths or {}).get(header, 1)))
            for index, header in enumerate(header_values)
        ]
        while sum(widths) > available:
            candidates = [
                index
                for index in range(len(widths))
                if widths[index] > minimums[index]
            ]
            if not candidates:
                candidates = [index for index, width in enumerate(widths) if width > 1]
            if not candidates:
                break
            index = max(candidates, key=lambda item: widths[item] - minimums[item])
            widths[index] -= 1

    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def render_line(values: Sequence[str]) -> str:
        return "|" + "|".join(
            f" {(values[index] if values[index] else '')[:widths[index]].ljust(widths[index])} "
            for index in range(len(headers))
        ) + "|"

    output = [border, render_line(header_values), border]
    for row in cell_rows:
        values = list(row) + ["-"] * (len(headers) - len(row))
        wrapped: list[list[str]] = []
        for index in range(len(headers)):
            cell_lines: list[str] = []
            for paragraph in values[index].splitlines() or [""]:
                cell_lines.extend(
                    textwrap.wrap(
                        paragraph,
                        width=widths[index],
                        break_long_words=True,
                        break_on_hyphens=False,
                    )
                    or [""]
                )
            wrapped.append(cell_lines or [""])
        for line_index in range(max(len(lines) for lines in wrapped)):
            output.append(
                render_line(
                    [
                        lines[line_index] if line_index < len(lines) else ""
                        for lines in wrapped
                    ]
                )
            )
        output.append(border)
    return "\n".join(output)


def _print_table_block(
    title: str,
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    max_widths: Mapping[str, int] | None = None,
    table_width: int | None = None,
    min_widths: Mapping[str, int] | None = None,
) -> None:
    print(f"\n{title}")
    print(_render_table(headers, rows, max_widths, table_width, min_widths))
    if not rows:
        print("(no rows)")


def _finding_details(item: Mapping[str, Any]) -> str:
    """Combine the human message and structured details in one table cell."""

    message = _display_cell(item.get("message"))
    details = item.get("details")
    if details:
        message += " details=" + json.dumps(
            _json_safe(details), sort_keys=True, separators=(",", ":")
        )
    return message


def _combine_findings(findings: Sequence[Mapping[str, Any]]) -> tuple[str, str]:
    """Combine codes and messages for one VM/volume resource row."""

    codes: list[str] = []
    details: list[str] = []
    for finding in findings:
        code = _display_cell(finding.get("code"))
        if code not in codes:
            codes.append(code)
        severity = _display_cell(finding.get("severity"))
        prefix = "" if severity == "-" else f"{severity}: "
        details.append(prefix + _finding_details(finding))
    return "\n".join(codes), "\n".join(details)


def _merge_finding_rows(rows: Sequence[Sequence[Any]]) -> list[tuple[Any, ...]]:
    """Merge findings that refer to the same project, instance, and volume."""

    merged: dict[tuple[Any, Any, Any], list[Any]] = {}
    status_rank = {"OK": 0, "WARN": 1, "ERROR": 2}
    for row in rows:
        key = (row[1], row[2], row[3])
        current = merged.get(key)
        if current is None:
            merged[key] = list(row)
            continue

        current_status = _display_cell(current[0])
        new_status = _display_cell(row[0])
        if status_rank.get(new_status, 0) > status_rank.get(current_status, 0):
            current[0] = row[0]

        for index in (4, 5, 6):
            existing = [line for line in str(current[index] or "").splitlines() if line]
            additions = [line for line in str(row[index] or "").splitlines() if line]
            for line in additions:
                if line not in existing:
                    existing.append(line)
            current[index] = "\n".join(existing) or None
    return [tuple(row) for row in merged.values()]


def _terminal_width(requested_width: int | None) -> int:
    """Return a usable table width for a terminal or redirected output."""

    if requested_width is not None:
        if requested_width < 40:
            raise ValueError("--width must be at least 40 columns")
        return requested_width
    return max(40, shutil.get_terminal_size(fallback=(120, 24)).columns)


def _print_table(
    report: Mapping[str, Any],
    verbose: bool,
    requested_width: int | None = None,
) -> None:
    table_width = _terminal_width(requested_width)
    summary = report["summary"]
    _print_table_block(
        "Audit summary",
        ("Metric", "Value"),
        (
            ("Project scope", report.get("project_scope")),
            ("Compute API microversion", report.get("compute_api_version")),
            ("Instances with API attachments", summary["instances_with_api_attachments"]),
            ("API volume attachments", summary["api_volume_attachments"]),
            ("Records OK", summary["records_ok"]),
            ("Records WARN", summary["records_warn"]),
            ("Records ERROR", summary["records_error"]),
            ("Database-only findings", summary["database_only_findings"]),
            (
                "Ignored Nova BDM rows without volume_id",
                summary["ignored_nova_bdm_rows_without_volume_id"],
            ),
            ("Read only", "yes" if report.get("read_only") else "no"),
        ),
        {"Metric": 44, "Value": 70},
        table_width,
        {"Metric": 24, "Value": 12},
    )

    finding_rows: list[tuple[Any, ...]] = []
    for record in report.get("records", []):
        findings = record.get("findings", [])
        if not findings and verbose:
            findings = [
                {
                    "severity": "-",
                    "code": "OK",
                    "message": "No attachment ID inconsistencies found.",
                }
            ]
        if not findings:
            continue
        codes, details = _combine_findings(findings)
        finding_rows.append(
            (
                record.get("status"),
                record.get("project_id") or report.get("project_id"),
                record.get("instance_id"),
                record.get("volume_id"),
                record.get("device"),
                codes,
                details,
            )
        )

    database_only = report.get("database_only", [])
    for item in database_only:
        finding_rows.append(
            (
                item.get("severity"),
                report.get("project_id"),
                item.get("instance_id"),
                item.get("volume_id"),
                None,
                f"{item.get('source', '-')}:{item.get('code', '-')}",
                _finding_details(item),
            )
        )

    finding_rows = _merge_finding_rows(finding_rows)

    if table_width >= 160:
        _print_table_block(
            "Attachment findings",
            (
                "Status",
                "Project",
                "Instance",
                "Volume",
                "Device",
                "Code",
                "Details",
            ),
            finding_rows,
            {
                "Status": 9,
                "Project": 36,
                "Instance": 36,
                "Volume": 36,
                "Device": 16,
                "Code": 42,
                "Details": 72,
            },
            table_width,
            {
                "Status": 8,
                "Project": 18,
                "Instance": 18,
                "Volume": 18,
                "Device": 8,
                "Code": 20,
                "Details": 24,
            },
        )
    else:
        compact_rows: list[tuple[Any, ...]] = []
        for row in finding_rows:
            compact_rows.append(
                (
                    row[0],
                    "\n".join(
                        f"{label}={_display_cell(value)}"
                        for label, value in (
                            ("project", row[1]),
                            ("instance", row[2]),
                            ("volume", row[3]),
                            ("device", row[4]),
                        )
                    ),
                    row[5],
                    # Keep the narrow table readable. The JSON mode retains
                    # the complete structured details for troubleshooting.
                    "\n".join(
                        str(line).split(" details=", 1)[0]
                        for line in str(row[6] or "").splitlines()
                    ),
                )
            )
        compact_available = max(1, table_width - 13)
        compact_widths = {
            "State": min(12, max(5, int(compact_available * 0.14))),
            "Resource": min(48, max(8, int(compact_available * 0.36))),
            "Code": min(32, max(4, int(compact_available * 0.28))),
        }
        compact_widths["Details"] = max(
            7,
            compact_available
            - sum(compact_widths.values()),
        )
        _print_table_block(
            "Attachment findings (compact)",
            ("State", "Resource", "Code", "Details"),
            compact_rows,
            compact_widths,
            table_width,
            compact_widths,
        )

    operational_errors = report.get("operational_errors", [])
    if operational_errors:
        _print_table_block(
            "Operational errors (the result is incomplete)",
            ("Scope", "Message"),
            [
                (item.get("scope"), item.get("message"))
                for item in operational_errors
            ],
            {"Scope": 30, "Message": 100},
            table_width,
            {"Scope": 12, "Message": 20},
        )


def _print_text(
    report: Mapping[str, Any],
    verbose: bool,
    requested_width: int | None = None,
) -> None:
    """Print the original block-style human-readable output."""

    del requested_width  # Width fitting applies only to the table renderer.
    summary = report["summary"]
    print(f"Project scope: {report['project_scope']}")
    print(f"Compute API microversion: {report['compute_api_version']}")
    print(
        "Scanned {instances_with_api_attachments} instances with {api_volume_attachments} "
        "API volume attachments: {records_ok} OK, {records_warn} warnings, "
        "{records_error} errors.".format(**summary)
    )
    print(f"Database-only findings: {summary['database_only_findings']}")
    print(
        "Ignored active Nova BDM rows without volume_id: "
        f"{summary['ignored_nova_bdm_rows_without_volume_id']}"
    )

    shown = 0
    for record in report["records"]:
        if record.get("status") == "OK" and not verbose:
            continue
        shown += 1
        print(
            f"\n[{record.get('status')}] instance={record.get('instance_id')} "
            f"volume={record.get('volume_id')} device={record.get('device') or '-'}"
        )
        for finding in record.get("findings", []):
            print(f"  {finding['severity']}: {finding['code']}: {finding['message']}")
            if "details" in finding:
                print(f"    {json.dumps(finding['details'], sort_keys=True)}")

    for item in report.get("database_only", []):
        shown += 1
        print(
            f"\n[{item['severity']}] {item['code']}: instance={item.get('instance_id')} "
            f"volume={item.get('volume_id')} source={item.get('source')} "
            f"database={item.get('database')}"
        )
        print(f"  {item['message']}")

    operational_errors = report.get("operational_errors", [])
    if operational_errors:
        print("\nOperational errors (the result is incomplete):")
        for item in operational_errors:
            print(f"  {item.get('scope')}: {item.get('message')}")
    if shown == 0 and not operational_errors:
        print("No attachment ID inconsistencies found.")


def main(argv: Sequence[str] | None = None) -> int:
    global _sa
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.width is not None and args.width < 40:
        parser.error("--width must be at least 40 columns")
    try:
        import sqlalchemy as sqlalchemy_module
    except ImportError:
        message = "SQLAlchemy is required; install dependencies from requirements.txt"
        if args.format == "json":
            print(json.dumps({"read_only": True, "operational_errors": [message]}))
        else:
            print(message, file=sys.stderr)
        return 2
    _sa = sqlalchemy_module

    try:
        report = audit(args)
    except AuditError as error:
        if args.format == "json":
            print(
                json.dumps(
                    {
                        "read_only": True,
                        "summary": {},
                        "records": [],
                        "database_only": [],
                        "operational_errors": [str(error)],
                    },
                    indent=2,
                )
            )
        else:
            print(f"Audit could not complete: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.format == "table":
        _print_table(report, args.verbose, args.width)
    else:
        _print_text(report, args.verbose, args.width)

    if report.get("operational_errors"):
        return 2
    summary = report["summary"]
    return 1 if summary["records_warn"] or summary["records_error"] or summary["database_only_findings"] else 0


if __name__ == "__main__":
    # SQLAlchemy is imported lazily so --help remains usable on an operator's
    # workstation before the optional dependencies are installed.
    _sa: Any = None
    raise SystemExit(main())
