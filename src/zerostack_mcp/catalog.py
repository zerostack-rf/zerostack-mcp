# Copyright (c) 2026 SMLIGHT
# SPDX-License-Identifier: Apache-2.0

"""Single-source-of-truth loader for bundled `diagnosticsCatalog.json`."""

from __future__ import annotations

import importlib.resources
import json
import re
from pathlib import Path

from zerostack_mcp.models import LogSignatureRule, RemediationMetaEntry


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
