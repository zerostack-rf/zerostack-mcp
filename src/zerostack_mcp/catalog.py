# Copyright (c) 2026 SMLIGHT
# SPDX-License-Identifier: Apache-2.0

"""Single-source-of-truth loader for bundled `diagnosticsCatalog.json`."""

from __future__ import annotations

import importlib.resources
import json
import re
from pathlib import Path

from zerostack_mcp.models import (
    CompatClassificationLiteral,
    CompatLayerLiteral,
    CompatPolicyLiteral,
    CompatRegistryRecord,
    CompatVendorLiteral,
    LogSignatureRule,
    RemediationMetaEntry,
)


def load_catalog_json_text(catalog_path: Path | None = None) -> str:
    """Read raw UTF-8 JSON text from `catalog_path` or bundled `zerostack_mcp.data`."""
    if catalog_path is not None:
        if not catalog_path.is_file():
            raise FileNotFoundError(f"Diagnostics catalog file not found: {catalog_path}")
        return catalog_path.read_text(encoding="utf-8")

    resource = importlib.resources.files("zerostack_mcp.data").joinpath("diagnosticsCatalog.json")
    if not resource.is_file():
        raise FileNotFoundError(
            "Bundled zerostack_mcp/data/diagnosticsCatalog.json resource is missing."
        )
    return resource.read_text(encoding="utf-8")


def _parse_catalog_object(catalog_path: Path | None = None) -> dict[str, object]:
    raw_text = load_catalog_json_text(catalog_path)
    try:
        parsed: object = json.loads(raw_text)
    except ValueError as exc:
        raise ValueError(f"Invalid JSON in diagnosticsCatalog.json: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("diagnosticsCatalog.json root must be a JSON object.")
    return {str(k): v for k, v in parsed.items()}


def _require_str(mapping: dict[str, object], key: str, context: str) -> str:
    val = mapping.get(key)
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"Missing or empty string field '{key}' in {context}.")
    return val


def _require_str_list(mapping: dict[str, object], key: str, context: str) -> list[str]:
    val = mapping.get(key)
    if not isinstance(val, list):
        raise ValueError(f"Field '{key}' in {context} must be a list of strings.")
    out: list[str] = []
    for item in val:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"Field '{key}' in {context} contains a non-string or empty entry.")
        out.append(item)
    return out


def _require_vendor(val: str, context: str) -> CompatVendorLiteral:
    if val == "ti-zstack":
        return "ti-zstack"
    if val == "zigbee-herdsman":
        return "zigbee-herdsman"
    raise ValueError(f"Invalid vendor '{val}' in {context}.")


def _require_layer(val: str, context: str) -> CompatLayerLiteral:
    if val == "UART-NPI":
        return "UART-NPI"
    if val == "MAC":
        return "MAC"
    if val == "NWK":
        return "NWK"
    if val == "APS":
        return "APS"
    if val == "ZDO":
        return "ZDO"
    if val == "GP":
        return "GP"
    raise ValueError(f"Invalid layer '{val}' in {context}.")


def _require_classification(val: str, context: str) -> CompatClassificationLiteral:
    if val == "normative-spec-violation":
        return "normative-spec-violation"
    if val == "resource-sizing-limit":
        return "resource-sizing-limit"
    if val == "upstream-firmware-or-host-bug":
        return "upstream-firmware-or-host-bug"
    raise ValueError(f"Invalid classification '{val}' in {context}.")


def _require_policy(val: str, context: str) -> CompatPolicyLiteral:
    if val == "strict-spec":
        return "strict-spec"
    if val == "compat-shim":
        return "compat-shim"
    if val == "hybrid-fallback":
        return "hybrid-fallback"
    raise ValueError(f"Invalid policy '{val}' in {context}.")


def load_compat_registry_json_text(registry_path: Path | None = None) -> str:
    """Read raw UTF-8 JSON text from `registry_path` or bundled `compatRegistry.json`."""
    if registry_path is not None:
        if not registry_path.is_file():
            raise FileNotFoundError(f"Compat registry file not found: {registry_path}")
        return registry_path.read_text(encoding="utf-8")

    resource = importlib.resources.files("zerostack_mcp.data").joinpath("compatRegistry.json")
    if not resource.is_file():
        raise FileNotFoundError(
            "Bundled zerostack_mcp/data/compatRegistry.json resource is missing."
        )
    return resource.read_text(encoding="utf-8")


def load_compat_registry(
    registry_path: Path | None = None,
) -> tuple[CompatRegistryRecord, ...]:
    """Load and validate the 69-record `compatRegistry.json` dataset."""
    raw_text = load_compat_registry_json_text(registry_path)
    try:
        parsed: object = json.loads(raw_text)
    except ValueError as exc:
        raise ValueError(f"Invalid JSON in compatRegistry.json: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("compatRegistry.json root must be a JSON object.")

    raw_records = parsed.get("records")
    if not isinstance(raw_records, list) or not raw_records:
        raise ValueError("compatRegistry.json must contain a non-empty 'records' array.")

    records: list[CompatRegistryRecord] = []
    for idx, raw_item in enumerate(raw_records):
        if not isinstance(raw_item, dict):
            raise ValueError(f"compatRegistry.json records[{idx}] must be a JSON object.")
        entry = {str(k): v for k, v in raw_item.items()}
        rec_id = _require_str(entry, "id", f"records[{idx}]")
        ctx = f"compatRegistry['{rec_id}']"
        spec_citations = _require_str_list(entry, "spec_citations", ctx)
        if not spec_citations:
            raise ValueError(f"{ctx} must have at least one spec_citations entry.")
        log_signatures = _require_str_list(entry, "log_signatures", ctx)
        if not log_signatures:
            raise ValueError(f"{ctx} must have at least one log_signatures entry.")

        records.append(
            {
                "id": rec_id,
                "vendor": _require_vendor(_require_str(entry, "vendor", ctx), ctx),
                "layer": _require_layer(_require_str(entry, "layer", ctx), ctx),
                "title": _require_str(entry, "title", ctx),
                "classification": _require_classification(
                    _require_str(entry, "classification", ctx), ctx
                ),
                "policy": _require_policy(_require_str(entry, "policy", ctx), ctx),
                "spec_citations": spec_citations,
                "mt_commands": _require_str_list(entry, "mt_commands", ctx),
                "nv_items": _require_str_list(entry, "nv_items", ctx),
                "status_codes": _require_str_list(entry, "status_codes", ctx),
                "log_signatures": log_signatures,
                "upstream_root_cause": _require_str(entry, "upstream_root_cause", ctx),
                "public_resolution": _require_str(entry, "public_resolution", ctx),
            }
        )
    return tuple(records)


def load_remediation_meta(
    catalog_path: Path | None = None,
) -> dict[str, RemediationMetaEntry]:
    """Load and validate `remediationMeta` strictly from `diagnosticsCatalog.json`."""
    root = _parse_catalog_object(catalog_path)
    raw_meta = root.get("remediationMeta")
    if not isinstance(raw_meta, dict) or not raw_meta:
        raise ValueError("diagnosticsCatalog.json must contain a non-empty 'remediationMeta' map.")

    result: dict[str, RemediationMetaEntry] = {}
    for raw_key, raw_entry in raw_meta.items():
        key = str(raw_key)
        if not isinstance(raw_entry, dict):
            raise ValueError(f"remediationMeta['{key}'] must be a JSON object.")
        entry = {str(k): v for k, v in raw_entry.items()}
        ctx = f"remediationMeta['{key}']"
        result[key] = {
            "siliconRootCause": _require_str(entry, "siliconRootCause", ctx),
            "zeroStackFix": _require_str(entry, "zeroStackFix", ctx),
            "zeroStackDiagUrl": _require_str(entry, "zeroStackDiagUrl", ctx),
        }
    return result


def load_diagnostics_catalog(
    catalog_path: Path | None = None,
) -> tuple[LogSignatureRule, ...]:
    """Load and compile declarative signature rules strictly from `diagnosticsCatalog.json`."""
    root = _parse_catalog_object(catalog_path)
    raw_sigs = root.get("signatures")
    if not isinstance(raw_sigs, dict) or not raw_sigs:
        raise ValueError("diagnosticsCatalog.json must contain a non-empty 'signatures' map.")

    rules: list[LogSignatureRule] = []
    for raw_id, raw_entry in raw_sigs.items():
        sig_key = str(raw_id)
        if not isinstance(raw_entry, dict):
            raise ValueError(f"signatures['{sig_key}'] must be a JSON object.")
        entry = {str(k): v for k, v in raw_entry.items()}
        ctx = f"signatures['{sig_key}']"

        raw_patterns = entry.get("patterns")
        if not isinstance(raw_patterns, list) or not raw_patterns:
            raise ValueError(f"{ctx} must define a non-empty 'patterns' list.")
        pattern_strings: list[str] = []
        for pat in raw_patterns:
            if not isinstance(pat, str) or not pat:
                raise ValueError(f"{ctx} contains a non-string or empty regex pattern.")
            pattern_strings.append(pat)

        compiled_patterns = tuple(re.compile(p, re.IGNORECASE) for p in pattern_strings)
        combined_pattern = re.compile(
            "|".join(f"(?:{p})" for p in pattern_strings),
            re.IGNORECASE,
        )

        sig_id = _require_str(entry, "id", ctx) if "id" in entry else sig_key
        status_hex = (
            _require_str(entry, "statusHex", ctx)
            if "statusHex" in entry
            else _require_str(entry, "code", ctx)
        )
        mitigation = (
            _require_str(entry, "immediateMitigation", ctx)
            if "immediateMitigation" in entry
            else _require_str(entry, "remedy", ctx)
        )
        protocol = _require_str(entry, "protocol", ctx) if "protocol" in entry else "zigbee"
        severity = _require_str(entry, "severity", ctx) if "severity" in entry else "critical"
        name = _require_str(entry, "name", ctx) if "name" in entry else sig_id
        title = _require_str(entry, "title", ctx)
        description = _require_str(entry, "description", ctx)
        rem_key_raw = entry.get("remediationKey")
        remediation_key = (
            rem_key_raw if isinstance(rem_key_raw, str) and rem_key_raw.strip() else None
        )

        rules.append(
            LogSignatureRule(
                signature_id=sig_id,
                status_hex=status_hex,
                name=name,
                protocol=protocol,
                title=title,
                description=description,
                subsystem=f"{protocol.upper()} ({status_hex})",
                severity=severity,
                remediation_key=remediation_key,
                patterns=compiled_patterns,
                combined_pattern=combined_pattern,
                silicon_root_cause=_require_str(entry, "siliconRootCause", ctx),
                immediate_mitigation=mitigation,
                immediate_workarounds=(mitigation,),
                zerostack_hardware_fix=_require_str(entry, "zeroStackFix", ctx),
                zero_stack_diag_url=_require_str(entry, "zeroStackDiagUrl", ctx),
            )
        )
    return tuple(rules)


LOG_SIGNATURE_RULES: tuple[LogSignatureRule, ...] = load_diagnostics_catalog()
REMEDIATION_META: dict[str, RemediationMetaEntry] = load_remediation_meta()
COMPAT_REGISTRY_RECORDS: tuple[CompatRegistryRecord, ...] = load_compat_registry()
COMPAT_REGISTRY_BY_ID: dict[str, CompatRegistryRecord] = {
    rec["id"]: rec for rec in COMPAT_REGISTRY_RECORDS
}


def query_compat_registry(
    *,
    record_id: str | None = None,
    vendor: str | None = None,
    layer: str | None = None,
    classification: str | None = None,
    policy: str | None = None,
    mt_command: str | None = None,
    nv_item: str | None = None,
    status_code: str | None = None,
    search_text: str | None = None,
) -> list[CompatRegistryRecord]:
    """Filter the 69-record `compatRegistry.json` dataset across structured fields."""
    norm_id = record_id.strip().upper() if record_id else None
    norm_vendor = vendor.strip().lower() if vendor else None
    norm_layer = layer.strip().upper() if layer else None
    norm_class = classification.strip().lower() if classification else None
    norm_policy = policy.strip().lower() if policy else None
    norm_mt = mt_command.strip().lower() if mt_command else None
    norm_nv = nv_item.strip().lower() if nv_item else None
    norm_status = status_code.strip().lower() if status_code else None
    norm_search = search_text.strip().lower() if search_text else None

    matches: list[CompatRegistryRecord] = []
    for rec in COMPAT_REGISTRY_RECORDS:
        if norm_id and rec["id"].upper() != norm_id:
            continue
        if norm_vendor and rec["vendor"].lower() != norm_vendor:
            continue
        if norm_layer and rec["layer"].upper() != norm_layer:
            continue
        if norm_class and rec["classification"].lower() != norm_class:
            continue
        if norm_policy and rec["policy"].lower() != norm_policy:
            continue
        if norm_mt and not any(norm_mt == c.lower() for c in rec["mt_commands"]):
            continue
        if norm_nv and not any(norm_nv == n.lower() for n in rec["nv_items"]):
            continue
        if norm_status and not any(norm_status == s.lower() for s in rec["status_codes"]):
            continue
        if norm_search:
            haystack = " ".join(
                (
                    rec["id"],
                    rec["title"],
                    rec["upstream_root_cause"],
                    rec["public_resolution"],
                    *rec["spec_citations"],
                    *rec["log_signatures"],
                )
            ).lower()
            if norm_search not in haystack:
                continue
        matches.append(rec)
    return matches


_PREFILTER_PATTERN_STR: str = (
    r"error|fail|timeout|timed|srsp|reset|status|code|dataconfirm|0x|buffer|"
    r"table_full|table\s+full|tablefull|no_route|no\s+route|network\s+route|"
    r"route\s+discovery|route\s+error|no\s+ack|no_ack|transaction|interview|"
    r"ember|ash_|ezsp|rxof|spinel|waitforwritable|network_busy|message_limit|"
    r"sendunicast|sendbroadcast|channel|discovery|consistent|conflict|disconnected|"
    r"mismatch|panid"
)
MASTER_SIGNATURE_PREFILTER_RE: re.Pattern[str] = re.compile(
    _PREFILTER_PATTERN_STR,
    re.IGNORECASE,
)
MASTER_LOG_SCAN_CS_RE: re.Pattern[str] = re.compile(
    f"{_PREFILTER_PATTERN_STR}|mqtt\\s+publish:|attributereport|gentime"
)
