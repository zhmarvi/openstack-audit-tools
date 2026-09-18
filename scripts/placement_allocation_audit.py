#!/usr/bin/env python3
"""Audit Nova hypervisor and Placement allocation consistency.

The audit is deliberately read-only.  It lists Nova hypervisors and visible
servers, lists Placement resource providers, then reads each provider's
allocations and compares compute-provider roots with the server's current
hypervisor.

This is intended for OpenStack Zed deployments.  It requires an administrative
or system-scoped credential because the Nova host fields and an all-project
server listing are normally admin-only.  A consumer that is absent from the
Nova server listing is reported as an orphan *candidate*: migration consumers
and other non-instance consumers may be legitimate.  Confirm those with
``nova-manage placement audit`` before taking corrective action.

Examples::

    python3 placement_allocation_audit.py --os-cloud admin
    python3 placement_allocation_audit.py --os-cloud admin --format json \
        > placement-audit.json

No Placement PUT or DELETE endpoint is called by this program.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
import os
import re
import shutil
import sys
import textwrap
from typing import Any


DEFAULT_COMPUTE_API_VERSION = "2.53"
DEFAULT_PLACEMENT_API_VERSION = "1.28"
MIN_PLACEMENT_API_VERSION = (1, 14)

TRANSITIONAL_TASK_STATES = {
    "deleting",
    "migrating",
    "rebuilding",
    "resize_prep",
    "resize_migrating",
    "resize_finish",
    "revert_resize",
    "shelving",
    "unshelving",
}
TRANSITIONAL_STATUSES = {
    "BUILD",
    "MIGRATING",
    "REBUILD",
    "RESIZE",
    "VERIFY_RESIZE",
}


class AuditError(RuntimeError):
    """An error that prevents a trustworthy audit."""


def _normalize(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text.lower() if text else None


def _resource_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        converted = to_dict()
        if isinstance(converted, Mapping):
            return dict(converted)
    return {}


def _resource_value(resource: Any, *names: str) -> Any:
    if isinstance(resource, Mapping):
        for name in names:
            if name in resource and resource[name] is not None:
                return resource[name]
    for name in names:
        value = getattr(resource, name, None)
        if value is not None:
            return value
    return None


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return isoformat()
    return str(value)


def _sanitize_error(error: Exception) -> str:
    message = str(error).strip() or error.__class__.__name__
    message = re.sub(r"(?i)(x-auth-token|authorization|password|secret)\s*[:=]\s*[^,; ]+", r"\1=<redacted>", message)
    return message[:500]


def _parse_microversion(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"\s*(\d+)\.(\d+)\s*", value)
    if not match:
        raise argparse.ArgumentTypeError("must be in MAJOR.MINOR form, for example 1.28")
    return int(match.group(1)), int(match.group(2))


def _placement_version_arg(value: str) -> str:
    parsed = _parse_microversion(value)
    if parsed < MIN_PLACEMENT_API_VERSION:
        raise argparse.ArgumentTypeError("must be >= 1.14 for provider topology")
    return value.strip()


def _unique_by(records: Sequence[Mapping[str, Any]], field: str) -> dict[str, Mapping[str, Any]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for record in records:
        key = _normalize(record.get(field))
        if key:
            grouped[key].append(record)
    return {key: items[0] for key, items in grouped.items() if len(items) == 1}


def _root_provider_uuid(provider_uuid: str, providers: Mapping[str, Mapping[str, Any]]) -> str:
    provider = providers.get(provider_uuid, {})
    explicit_root = _normalize(provider.get("root_provider_uuid"))
    if explicit_root:
        return explicit_root

    current = provider_uuid
    visited: set[str] = set()
    while current not in visited:
        visited.add(current)
        parent = _normalize(providers.get(current, {}).get("parent_provider_uuid"))
        if not parent or parent not in providers:
            break
        current = parent
    return current


def _build_provider_records(raw_providers: Sequence[Any]) -> dict[str, dict[str, Any]]:
    providers: dict[str, dict[str, Any]] = {}
    for raw in raw_providers:
        provider = _resource_dict(raw)
        provider_uuid = _normalize(_resource_value(provider, "uuid", "id"))
        if not provider_uuid:
            continue
        provider["uuid"] = provider_uuid
        provider["parent_provider_uuid"] = _normalize(
            _resource_value(provider, "parent_provider_uuid", "parent_uuid")
        )
        provider["root_provider_uuid"] = _normalize(
            _resource_value(provider, "root_provider_uuid")
        )
        providers[provider_uuid] = provider

    for provider_uuid, provider in providers.items():
        provider["root_provider_uuid"] = _root_provider_uuid(provider_uuid, providers)
        provider["is_root"] = provider["root_provider_uuid"] == provider_uuid
    return providers


def _list_hypervisors(connection: Any) -> list[dict[str, Any]]:
    try:
        items = connection.compute.hypervisors(details=True)
    except AttributeError:
        try:
            items = connection.list_hypervisors(detailed=True)
        except Exception as error:  # pragma: no cover - SDK-version fallback
            raise AuditError(f"could not list Nova hypervisors: {_sanitize_error(error)}") from error
    except Exception as error:
        raise AuditError(f"could not list Nova hypervisors: {_sanitize_error(error)}") from error
    return [_resource_dict(item) for item in items]


def _list_servers(connection: Any, args: argparse.Namespace) -> list[dict[str, Any]]:
    query: dict[str, Any] = {
        "details": True,
        "all_projects": args.all_projects,
    }
    if args.project_id and not args.all_projects:
        query["project_id"] = args.project_id
    try:
        items = connection.compute.servers(**query)
    except Exception as error:
        raise AuditError(f"could not list Nova servers: {_sanitize_error(error)}") from error
    servers = [_resource_dict(item) for item in items]
    if args.project_id and not args.all_projects:
        target_project = _normalize(args.project_id)
        servers = [
            server
            for server in servers
            if _normalize(_resource_value(server, "project_id", "tenant_id")) == target_project
        ]
    return servers


def _scope_server_records(
    servers: Mapping[str, Mapping[str, Any]], project_id: str | None
) -> dict[str, dict[str, Any]]:
    if not project_id:
        return {server_id: dict(server) for server_id, server in servers.items()}
    target_project = _normalize(project_id)
    return {
        server_id: dict(server)
        for server_id, server in servers.items()
        if _normalize(server.get("project_id")) == target_project
    }


def _list_placement_providers(connection: Any) -> dict[str, dict[str, Any]]:
    try:
        items = connection.placement.resource_providers()
    except Exception as error:
        raise AuditError(f"could not list Placement resource providers: {_sanitize_error(error)}") from error
    return _build_provider_records(list(items))


def _placement_get(connection: Any, path: str, api_version: str) -> Mapping[str, Any]:
    endpoint_for = getattr(connection, "endpoint_for", None)
    session = getattr(connection, "session", None) or getattr(connection, "_session", None)
    if not callable(endpoint_for) or session is None:
        raise AuditError("openstacksdk connection does not expose a Placement endpoint/session")

    try:
        endpoint = endpoint_for("placement")
        url = endpoint.rstrip("/") + "/" + path.lstrip("/")
        response = session.get(
            url,
            headers={
                "Accept": "application/json",
                "OpenStack-API-Version": f"placement {api_version}",
            },
        )
        status_code = getattr(response, "status_code", 200)
        if status_code >= 400:
            response_text = getattr(response, "text", "")
            raise AuditError(f"HTTP {status_code}: {str(response_text).strip()[:300]}")
        body = response.json()
    except AuditError:
        raise
    except Exception as error:
        raise AuditError(_sanitize_error(error)) from error
    if not isinstance(body, Mapping):
        raise AuditError("Placement returned a non-object JSON response")
    return body


def _read_allocations(
    connection: Any,
    providers: Mapping[str, Mapping[str, Any]],
    api_version: str,
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]], set[str]]:
    allocation_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    errors: list[dict[str, Any]] = []
    failed_roots: set[str] = set()

    for provider_uuid, provider in providers.items():
        path = f"/resource_providers/{provider_uuid}/allocations"
        try:
            body = _placement_get(connection, path, api_version)
        except AuditError as error:
            root_uuid = str(provider.get("root_provider_uuid") or provider_uuid)
            failed_roots.add(root_uuid)
            errors.append(
                {
                    "kind": "placement_allocations",
                    "provider_uuid": provider_uuid,
                    "provider_name": _resource_value(provider, "name"),
                    "error": str(error),
                }
            )
            continue

        allocations = body.get("allocations", {})
        if not isinstance(allocations, Mapping):
            errors.append(
                {
                    "kind": "placement_allocations",
                    "provider_uuid": provider_uuid,
                    "provider_name": _resource_value(provider, "name"),
                    "error": "Placement response has no object-valued allocations member",
                }
            )
            failed_roots.add(str(provider.get("root_provider_uuid") or provider_uuid))
            continue

        for consumer_uuid, allocation in allocations.items():
            consumer_id = _normalize(consumer_uuid)
            if not consumer_id:
                continue
            allocation_data = _resource_dict(allocation)
            resources = _resource_value(allocation_data, "resources") or {}
            allocation_index[consumer_id].append(
                {
                    "provider_uuid": provider_uuid,
                    "provider_name": _resource_value(provider, "name"),
                    "root_provider_uuid": provider["root_provider_uuid"],
                    "is_root_provider": provider["is_root"],
                    "resources": _resource_dict(resources),
                }
            )
    return dict(allocation_index), errors, failed_roots


def _server_records(
    raw_servers: Sequence[Mapping[str, Any]],
    hypervisors: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    by_hostname = _unique_by(hypervisors, "hypervisor_hostname")
    by_host = _unique_by(hypervisors, "host")
    servers: dict[str, dict[str, Any]] = {}

    for raw_server in raw_servers:
        server_id = _normalize(_resource_value(raw_server, "id", "server_id"))
        if not server_id:
            continue
        host = _resource_value(raw_server, "OS-EXT-SRV-ATTR:host", "host")
        hypervisor_hostname = _resource_value(
            raw_server,
            "OS-EXT-SRV-ATTR:hypervisor_hostname",
            "hypervisor_hostname",
        )
        hypervisor = by_hostname.get(_normalize(hypervisor_hostname) or "")
        if hypervisor is None:
            hypervisor = by_host.get(_normalize(host) or "")
        servers[server_id] = {
            "id": server_id,
            "name": _resource_value(raw_server, "name"),
            "project_id": _resource_value(raw_server, "project_id", "tenant_id"),
            "host": host,
            "hypervisor_hostname": hypervisor_hostname,
            "status": _resource_value(raw_server, "status"),
            "task_state": _resource_value(raw_server, "OS-EXT-STS:task_state", "task_state"),
            "hypervisor_id": _normalize(_resource_value(hypervisor or {}, "id", "uuid")),
            "expected_provider_uuid": _normalize(
                _resource_value(hypervisor or {}, "placement_provider_uuid")
            ),
        }
    return servers


def _transitional(server: Mapping[str, Any]) -> bool:
    task_state = _normalize(server.get("task_state"))
    status = str(server.get("status") or "").upper()
    return task_state in TRANSITIONAL_TASK_STATES or status in TRANSITIONAL_STATUSES


def _allocation_summary(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "provider_uuid": entry.get("provider_uuid"),
        "provider_name": entry.get("provider_name"),
        "root_provider_uuid": entry.get("root_provider_uuid"),
        "is_root_provider": entry.get("is_root_provider"),
        "resources": entry.get("resources", {}),
    }


def _server_context(server: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "server_name": server.get("name"),
        "project_id": server.get("project_id"),
        "host": server.get("host"),
        "hypervisor_hostname": server.get("hypervisor_hostname"),
    }


def _finding(
    severity: str,
    code: str,
    message: str,
    *,
    consumer_id: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "severity": severity,
        "code": code,
        "message": message,
    }
    if consumer_id:
        result["consumer_id"] = consumer_id
    if details:
        result["details"] = dict(details)
    return result


def _analyze(
    hypervisors: list[dict[str, Any]],
    providers: dict[str, dict[str, Any]],
    servers: dict[str, dict[str, Any]],
    allocation_index: Mapping[str, Sequence[Mapping[str, Any]]],
    failed_roots: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []

    compute_roots = {
        provider_uuid
        for provider_uuid, provider in providers.items()
        if provider.get("is_root") and provider.get("placement_hypervisor_id")
    }

    for hypervisor in hypervisors:
        if not hypervisor.get("placement_provider_uuid"):
            findings.append(
                _finding(
                    "WARN",
                    "HYPERVISOR_MISSING_IN_PLACEMENT",
                    "Nova hypervisor has no unambiguous matching Placement compute provider",
                    details={
                        "hypervisor_id": hypervisor.get("id"),
                        "hypervisor_hostname": hypervisor.get("hypervisor_hostname"),
                        "host": hypervisor.get("host"),
                    },
                )
            )

    for consumer_id, entries in allocation_index.items():
        server = servers.get(consumer_id)
        if server is None:
            findings.append(
                _finding(
                    "WARN",
                    "ORPHANED_OR_NON_NOVA_CONSUMER",
                    "Placement allocation consumer is absent from the visible Nova server list; it may be orphaned or a migration/non-instance consumer",
                    consumer_id=consumer_id,
                    details={"allocations": [_allocation_summary(entry) for entry in entries]},
                )
            )
            continue

        actual_compute_roots = sorted(
            {
                str(entry["root_provider_uuid"])
                for entry in entries
                if entry.get("root_provider_uuid") in compute_roots
            }
        )
        expected_provider_uuid = server.get("expected_provider_uuid")
        transitional = _transitional(server)

        if expected_provider_uuid in failed_roots:
            continue

        if not expected_provider_uuid:
            if actual_compute_roots:
                findings.append(
                    _finding(
                        "WARN",
                        "SERVER_HOST_NOT_MAPPED_TO_HYPERVISOR",
                        "Live Nova server has compute-provider allocations but its host does not map to a Nova hypervisor",
                        consumer_id=consumer_id,
                        details={
                            **_server_context(server),
                            "actual_compute_roots": actual_compute_roots,
                        },
                    )
                )
            continue

        expected_present = expected_provider_uuid in actual_compute_roots
        if not expected_present and actual_compute_roots:
            severity = "WARN" if transitional else "ERROR"
            findings.append(
                _finding(
                    severity,
                    "MISMATCHED_ALLOCATION",
                    "Live Nova server has compute allocations on a provider different from its current hypervisor",
                    consumer_id=consumer_id,
                    details={
                        **_server_context(server),
                        "expected_provider_uuid": expected_provider_uuid,
                        "actual_compute_roots": actual_compute_roots,
                        "transitional_state": transitional,
                        "status": server.get("status"),
                        "task_state": server.get("task_state"),
                    },
                )
            )
        elif not expected_present:
            findings.append(
                _finding(
                    "WARN",
                    "NO_EXPECTED_COMPUTE_PROVIDER_ALLOCATION",
                    "Live Nova server has no Placement allocation in the compute-provider tree for its current hypervisor",
                    consumer_id=consumer_id,
                    details={
                        **_server_context(server),
                        "expected_provider_uuid": expected_provider_uuid,
                        "status": server.get("status"),
                        "task_state": server.get("task_state"),
                    },
                )
            )
        elif len(actual_compute_roots) > 1:
            severity = "WARN" if transitional else "ERROR"
            findings.append(
                _finding(
                    severity,
                    "MULTIPLE_COMPUTE_PROVIDER_ALLOCATIONS",
                    "Live Nova server has allocations in more than one compute-provider tree",
                    consumer_id=consumer_id,
                    details={
                        **_server_context(server),
                        "expected_provider_uuid": expected_provider_uuid,
                        "actual_compute_roots": actual_compute_roots,
                        "transitional_state": transitional,
                        "status": server.get("status"),
                        "task_state": server.get("task_state"),
                    },
                )
            )

    for consumer_id, server in servers.items():
        if consumer_id in allocation_index:
            continue
        expected_provider_uuid = server.get("expected_provider_uuid")
        if expected_provider_uuid and expected_provider_uuid not in failed_roots:
            findings.append(
                _finding(
                    "WARN",
                    "NO_EXPECTED_COMPUTE_PROVIDER_ALLOCATION",
                    "Live Nova server has no Placement allocations at all for its current hypervisor",
                    consumer_id=consumer_id,
                    details={
                        **_server_context(server),
                        "expected_provider_uuid": expected_provider_uuid,
                        "status": server.get("status"),
                        "task_state": server.get("task_state"),
                    },
                )
            )

    unmatched_provider_roots: list[dict[str, Any]] = []
    for provider_uuid, provider in providers.items():
        if provider.get("is_root") and not provider.get("placement_hypervisor_id"):
            if any(entry.get("root_provider_uuid") == provider_uuid for entries in allocation_index.values() for entry in entries):
                unmatched_provider_roots.append(
                    {
                        "uuid": provider_uuid,
                        "name": _resource_value(provider, "name"),
                        "note": "May be a shared or non-Nova provider; inspect only if expected to represent a compute node",
                    }
                )
    return findings, unmatched_provider_roots


def audit(connection: Any, args: argparse.Namespace) -> dict[str, Any]:
    raw_hypervisors = _list_hypervisors(connection)
    providers = _list_placement_providers(connection)

    provider_by_uuid = {
        provider_uuid: provider
        for provider_uuid, provider in providers.items()
        if provider.get("is_root")
    }
    roots_by_id = {provider_uuid: provider for provider_uuid, provider in provider_by_uuid.items()}
    roots_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for provider in provider_by_uuid.values():
        name = _normalize(_resource_value(provider, "name"))
        if name:
            roots_by_name[name].append(provider)

    hypervisors: list[dict[str, Any]] = []
    for raw in raw_hypervisors:
        hypervisor_id = _normalize(_resource_value(raw, "id", "uuid"))
        hypervisor_hostname = _resource_value(raw, "hypervisor_hostname", "name")
        host = _resource_value(raw, "host")
        provider = roots_by_id.get(hypervisor_id or "")
        match_type = "uuid" if provider else None
        if provider is None:
            candidates = roots_by_name.get(_normalize(hypervisor_hostname) or "", [])
            if len(candidates) != 1:
                candidates = roots_by_name.get(_normalize(host) or "", [])
            if len(candidates) == 1:
                provider = candidates[0]
                match_type = "name"
        hypervisors.append(
            {
                "id": hypervisor_id,
                "hypervisor_hostname": hypervisor_hostname,
                "host": host,
                "state": _resource_value(raw, "state"),
                "status": _resource_value(raw, "status"),
                "placement_provider_uuid": provider.get("uuid") if provider else None,
                "placement_provider_match": match_type or "missing",
            }
        )

    for provider in providers.values():
        provider["placement_hypervisor_id"] = None
    for hypervisor in hypervisors:
        provider_uuid = hypervisor.get("placement_provider_uuid")
        if provider_uuid in providers:
            providers[provider_uuid]["placement_hypervisor_id"] = hypervisor.get("id")

    raw_servers = _list_servers(connection, args)
    all_servers = _server_records(raw_servers, hypervisors)
    servers = _scope_server_records(all_servers, args.project_id)
    allocation_index, operational_errors, failed_roots = _read_allocations(
        connection, providers, args.placement_api_version
    )
    suppressed_allocation_consumers = 0
    reported_allocation_index = allocation_index
    if args.project_id:
        reported_allocation_index = {
            consumer_id: entries
            for consumer_id, entries in allocation_index.items()
            if consumer_id in servers
        }
        suppressed_allocation_consumers = len(allocation_index) - len(reported_allocation_index)
    findings, unmatched_provider_roots = _analyze(
        hypervisors,
        providers,
        servers,
        reported_allocation_index,
        failed_roots,
    )

    summary = {
        "hypervisors": len(hypervisors),
        "placement_resource_providers": len(providers),
        "placement_compute_provider_roots": len(provider_by_uuid),
        "servers_visible": len(servers),
        "nova_server_records_returned": len(all_servers),
        "consumers_with_allocations": len(reported_allocation_index),
        "allocation_consumers_out_of_scope": suppressed_allocation_consumers,
        "orphan_candidates": sum(f["code"] == "ORPHANED_OR_NON_NOVA_CONSUMER" for f in findings),
        "mismatched_allocations": sum(f["code"] == "MISMATCHED_ALLOCATION" for f in findings),
        "multiple_compute_provider_allocations": sum(
            f["code"] == "MULTIPLE_COMPUTE_PROVIDER_ALLOCATIONS" for f in findings
        ),
        "missing_expected_compute_allocations": sum(
            f["code"] == "NO_EXPECTED_COMPUTE_PROVIDER_ALLOCATION" for f in findings
        ),
        "findings_warn": sum(f["severity"] == "WARN" for f in findings),
        "findings_error": sum(f["severity"] == "ERROR" for f in findings),
    }

    provider_report = []
    for provider_uuid, provider in sorted(providers.items()):
        provider_report.append(
            {
                "uuid": provider_uuid,
                "name": _resource_value(provider, "name"),
                "parent_provider_uuid": provider.get("parent_provider_uuid"),
                "root_provider_uuid": provider.get("root_provider_uuid"),
                "is_root": provider.get("is_root"),
                "generation": _resource_value(provider, "generation"),
                "allocation_consumer_count": sum(
                    1
                    for entries in reported_allocation_index.values()
                    for entry in entries
                    if entry.get("provider_uuid") == provider_uuid
                ),
                "matched_hypervisor_id": provider.get("placement_hypervisor_id"),
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "nova_release_target": "Zed",
        "compute_api_version": args.compute_api_version,
        "placement_api_version": args.placement_api_version,
        "scope": {
            "project_id": args.project_id,
            "all_projects": args.all_projects,
            "server_visibility": (
                "project_filtered_from_all_projects"
                if args.project_id and args.all_projects
                else "project_scope"
                if args.project_id
                else "all_projects"
                if args.all_projects
                else "limited_project_or_scope"
            ),
            "orphan_candidate_caveat": "Placement provider allocations do not include project_id. In project-scoped mode, allocation consumers that cannot be attributed to a visible server in the requested project are suppressed; use an all-projects run plus nova-manage placement audit for orphan candidates.",
        },
        "summary": summary,
        "hypervisors": hypervisors,
        "providers": provider_report,
        "unmatched_provider_roots": unmatched_provider_roots,
        "findings": findings,
        "operational_errors": operational_errors,
    }


def _render_table(report: Mapping[str, Any], width: int) -> str:
    summary = report["summary"]
    lines = [
        "Placement allocation audit (read-only; Nova target: Zed)",
        "  "
        + "  ".join(
            [
                f"hypervisors={summary['hypervisors']}",
                f"providers={summary['placement_resource_providers']}",
                f"servers_visible={summary['servers_visible']}",
                f"server_records={summary['nova_server_records_returned']}",
                f"allocation_consumers={summary['consumers_with_allocations']}",
                f"out_of_scope={summary['allocation_consumers_out_of_scope']}",
                f"warnings={summary['findings_warn']}",
                f"errors={summary['findings_error']}",
            ]
        ),
    ]
    findings = report["findings"]
    if not findings:
        lines.append("No consistency findings.")
    else:
        lines.append("")
        lines.append("Findings:")
        for finding in findings:
            details = finding.get("details", {})
            detail_text = ", ".join(f"{key}={value}" for key, value in details.items())
            prefix = f"{finding['severity']:<5} {finding['code']:<42}"
            if finding.get("consumer_id"):
                prefix += f" consumer={finding['consumer_id']}"
            lines.append(f"{prefix} {finding['message']} ({detail_text})")
    if report["operational_errors"]:
        lines.append("")
        lines.append("Operational errors (audit is incomplete):")
        for error in report["operational_errors"]:
            lines.append(f"{error['kind']} provider={error.get('provider_uuid')}: {error['error']}")
    if report["unmatched_provider_roots"]:
        lines.append("")
        lines.append(
            f"Unmatched allocated root providers (may be shared/non-Nova): {len(report['unmatched_provider_roots'])}"
        )
    if report["scope"].get("project_id"):
        lines.append("")
        lines.append(
            "Project-scoped mode suppresses orphan candidates because Placement allocation records do not include consumer project IDs."
        )
    wrapped_lines: list[str] = []
    for line in lines:
        wrapped_lines.extend(
            textwrap.wrap(
                line,
                width=max(20, width),
                break_long_words=False,
                break_on_hyphens=False,
                subsequent_indent="     ",
            )
            or [""]
        )
    return "\n".join(wrapped_lines)


def _render_text(report: Mapping[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "audit="
        + ("clean" if not report["findings"] else "findings")
        + f" hypervisors={summary['hypervisors']} providers={summary['placement_resource_providers']}"
        + f" servers={summary['servers_visible']} consumers={summary['consumers_with_allocations']}",
    ]
    for finding in report["findings"]:
        consumer = f" consumer={finding['consumer_id']}" if finding.get("consumer_id") else ""
        lines.append(f"{finding['severity']} {finding['code']}{consumer}: {finding['message']}")
    for error in report["operational_errors"]:
        lines.append(f"ERROR OPERATIONAL provider={error.get('provider_uuid')}: {error['error']}")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--os-cloud",
        default=os.getenv("OS_CLOUD"),
        help="cloud name from clouds.yaml (default: OS_CLOUD)",
    )
    parser.add_argument(
        "--compute-api-version",
        default=DEFAULT_COMPUTE_API_VERSION,
        help=f"Nova compute API microversion (default: {DEFAULT_COMPUTE_API_VERSION})",
    )
    parser.add_argument(
        "--placement-api-version",
        type=_placement_version_arg,
        default=DEFAULT_PLACEMENT_API_VERSION,
        help=f"Placement API microversion, >= 1.14 (default: {DEFAULT_PLACEMENT_API_VERSION})",
    )
    parser.add_argument("--project-id", help="limit the Nova server query to this project")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--all-projects",
        dest="all_projects",
        action="store_true",
        default=True,
        help="request an all-project Nova server listing (default)",
    )
    scope.add_argument(
        "--no-all-projects",
        dest="all_projects",
        action="store_false",
        help="do not request an all-project Nova server listing",
    )
    parser.add_argument("--format", choices=("table", "text", "json"), default="table")
    parser.add_argument(
        "--width",
        type=int,
        default=0,
        help="table wrapping width (default: detected terminal width; output is never clipped)",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="return zero even when consistency findings are present; operational errors still return 2",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.width and args.width < 20:
        parser.error("--width must be at least 20")

    try:
        import openstack
    except ImportError:
        print("ERROR: openstacksdk is required; install requirements.txt", file=sys.stderr)
        return 2

    try:
        connection = openstack.connect(
            cloud=args.os_cloud,
            compute_api_version=args.compute_api_version,
            placement_api_version=args.placement_api_version,
        )
        report = audit(connection, args)
    except AuditError as error:
        if args.format == "json":
            print(
                json.dumps(
                    {
                        "read_only": True,
                        "nova_release_target": "Zed",
                        "operational_errors": [{"kind": "fatal", "error": str(error)}],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"ERROR: {_sanitize_error(error)}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(_json_safe(report), indent=2, sort_keys=True))
    elif args.format == "text":
        print(_render_text(report))
    else:
        width = args.width or shutil.get_terminal_size((120, 24)).columns
        print(_render_table(report, width))

    if report["operational_errors"]:
        return 2
    if report["findings"] and not args.exit_zero:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
