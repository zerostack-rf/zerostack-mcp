# Copyright (c) 2026 SMLIGHT
# SPDX-License-Identifier: Apache-2.0

"""Bounded, deterministic Zigbee / Thread / ZNP / EZSP log analyzer."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from zerostack_mcp.catalog import (
    LOG_SIGNATURE_RULES,
    MASTER_LOG_SCAN_CS_RE,
    REMEDIATION_META,
)
from zerostack_mcp.models import (
    MAX_FLOODING_DEVICES,
    MAX_LOG_BYTES,
    MAX_LOG_LINES,
    ZEROSTACK_MARKETING_URL,
    ZEROSTACK_RELEASE_NAME,
    ZEROSTACK_REPO_URL,
    ZEROSTACK_WEB_ANALYZER_URL,
    FloodingDeviceSummary,
    LogAnalysisResult,
    MatchedLogLine,
    SignatureMatch,
)

_SYS_STARTUP_SRSP_RE = re.compile(
    r"SYS\s*-\s*(?:ping|version|osalNvRead|getExtAddr)|SYS\.Ping",
    re.IGNORECASE,
)
_MQTT_PUBLISH_RE = re.compile(
    r"MQTT\s+publish:\s+topic\s+'zigbee2mqtt/([^']+)',\s+payload\s+'([^']*)'",
    re.IGNORECASE,
)
_Z2M_ATTR_REPORT_RE = re.compile(
    r"Received\s+Zigbee\s+message\s+from\s+'([^']+)',\s+type\s+'attributeReport',\s+"
    r"cluster\s+'([^']+)',\s+data\s+'([^']*)'",
    re.IGNORECASE,
)
_ZCL_GENTIME_READ_RE = re.compile(
    r"Received\s+Zigbee\s+message\s+from\s+'([^']+)',\s+type\s+'read',\s+"
    r"cluster\s+'(?:genTime|0x000a|10)'",
    re.IGNORECASE,
)
_EZSP_LEGACY_VERSION_RE = re.compile(
    r"(?:Adapter\s+EZSP\s+protocol\s+version|EZSP\s+version)\s*\(?\d+\)?\s+is\s+"
    r"(?:not\s+supported|deprecated)",
    re.IGNORECASE,
)
_CHANNEL_MISMATCH_RE = re.compile(
    r"Configured\s+channel\s+'\d+'\s+does\s+not\s+match\s+adapter\s+channel\s+'\d+'|"
    r"Changing\s+channel\s+from\s+'\d+'\s+to\s+'\d+'",
    re.IGNORECASE,
)
_ADAPTER_DISCOVERY_RE = re.compile(
    r"USB\s+adapter\s+discovery\s+error",
    re.IGNORECASE,
)
_CONFIG_MISMATCH_RE = re.compile(
    r"Configuration\s+is\s+not\s+consistent\s+with\s+adapter\s+state|"
    r"adapter-settings-mismatch",
    re.IGNORECASE,
)
_PAN_CONFLICT_RE = re.compile(
    r"PAN\s*ID\s+conflict|network\s+with\s+the\s+same\s+panId",
    re.IGNORECASE,
)
_ASH_UART_LINK_RE = re.compile(
    r"Received\s+frame\s+with\s+(?:CRC|comm)\s+error|ASH\s+disconnected",
    re.IGNORECASE,
)
_ADAPTER_TIMEOUT_RE = re.compile(
    r"Opening\s+serial\s+port\s+timed\s+out|Adapter\s+startup\s+timed\s+out",
    re.IGNORECASE,
)
_LOG_TIMESTAMP_RE = re.compile(r"\[?(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)")
_VOLATILE_PAYLOAD_KEYS = frozenset({"linkquality", "last_seen", "update", "device", "elapsed"})

_SEVERITY_RANK: dict[str, int] = {
    "critical": 2,
    "warning": 1,
    "info": 0,
}

# Root-cause priority ranking: hardware/MCU faults and lockstep freezes outrank
# buffer exhaustion, which outranks RF delivery and downstream routing symptoms.
_ROOT_CAUSE_PRIORITY: dict[str, int] = {
    "ZNP_SYS_RESET_IND": 100,
    "EMBER_ASH_NCP_FATAL_ERROR": 98,
    "OTBR_SPINEL_TIMEOUT": 96,
    "ZNP_WARM_RESET_SYS_PING_TIMEOUT": 92,
    "ZNP_SRSP_6000MS_TIMEOUT": 90,
    "ZNP_TCLK_INTERVIEW_TIMEOUT": 90,
    "EZSP_LEGACY_PROTOCOL_VERSION": 88,
    "ADAPTER_DISCOVERY_ERROR": 87,
    "ADAPTER_CONFIG_MISMATCH": 87,
    "ADAPTER_STARTUP_TIMEOUT": 86,
    "ZNP_0X10_MEM_ERROR": 86,
    "ZNP_0X11_BUFFER_FULL": 84,
    "MAC_0XF1_TRANSACTION_OVERFLOW": 80,
    "ZNP_0XB2_APS_TABLE_FULL": 78,
    "ZNP_0XC7_NWK_TABLE_FULL": 76,
    "EMBER_0X72_MAX_MESSAGE_LIMIT": 74,
    "PAN_ID_CONFLICT": 72,
    "ASH_UART_LINK_ERROR": 70,
    "MAC_0XE1_CHANNEL_ACCESS_FAILURE": 68,
    "MAC_0XE9_NO_ACK": 66,
    "EMBER_DELIVERY_FAILED": 64,
    "CHANNEL_MISMATCH_AUTO_SWITCH": 60,
    "ZNP_0XCD_NWK_NO_ROUTE": 55,
    "EMBER_0XA1_NETWORK_BUSY": 52,
    "MAC_0XF0_TRANSACTION_EXPIRED": 50,
    "ZCL_TELEMETRY_DELTA_ZERO_FLOOD": 45,
    "ZCL_GENTIME_READ_FLOOD": 42,
}


def _find_nth_newline_from_start(text: str, max_lines: int) -> int:
    """Return character index of the `max_lines`-th newline in `text` (or `len(text)`)."""
    pos = -1
    for _ in range(max_lines):
        pos = text.find("\n", pos + 1)
        if pos == -1:
            return len(text)
    return pos


def _find_nth_newline_from_end(text: str, max_lines: int) -> int:
    """Return start character index of the last `max_lines` lines in `text`."""
    pos = len(text) - 1 if text.endswith("\n") else len(text)
    for _ in range(max_lines):
        pos = text.rfind("\n", 0, pos)
        if pos == -1:
            return 0
    return pos + 1


def _window_log_chunks(log_text: str) -> tuple[list[tuple[int, str]], int, bool]:
    """Slice bounded head + tail text chunks in C without materializing all lines."""
    total_newlines = log_text.count("\n")
    total_input_lines = total_newlines + (1 if log_text and not log_text.endswith("\n") else 0)
    half_line_cap = MAX_LOG_LINES // 2

    if len(log_text) * 4 > MAX_LOG_BYTES:
        head_raw = ""
        tail_raw = ""
        if log_text.isascii():
            if len(log_text) > MAX_LOG_BYTES:
                half_bytes = MAX_LOG_BYTES // 2
                head_raw = log_text[:half_bytes]
                tail_raw = log_text[-half_bytes:]
        else:
            encoded = log_text.encode("utf-8")
            if len(encoded) > MAX_LOG_BYTES:
                half_bytes = MAX_LOG_BYTES // 2
                head_raw = encoded[:half_bytes].decode("utf-8", errors="ignore")
                tail_raw = encoded[-half_bytes:].decode("utf-8", errors="ignore")

        if head_raw:
            last_nl = head_raw.rfind("\n")
            if last_nl != -1:
                head_raw = head_raw[:last_nl]
            head_cut = _find_nth_newline_from_start(head_raw, half_line_cap)
            head_chunk = head_raw[:head_cut]
            head_line_count = head_chunk.count("\n") + (1 if head_chunk else 0)

            first_nl = tail_raw.find("\n")
            if first_nl != -1:
                tail_raw = tail_raw[first_nl + 1 :]
            if tail_raw.endswith("\n"):
                tail_raw = tail_raw[:-1]
            tail_cut = _find_nth_newline_from_end(tail_raw, half_line_cap)
            tail_chunk = tail_raw[tail_cut:]
            tail_line_count = tail_chunk.count("\n") + (1 if tail_chunk else 0)

            tail_start_line = max(
                head_line_count + 1,
                total_input_lines - tail_line_count + 1,
            )
            return [(1, head_chunk), (tail_start_line, tail_chunk)], total_input_lines, True

    if total_input_lines > MAX_LOG_LINES:
        head_count = MAX_LOG_LINES // 2
        tail_count = MAX_LOG_LINES - head_count
        head_cut = _find_nth_newline_from_start(log_text, head_count)
        head_chunk = log_text[:head_cut]
        tail_cut = _find_nth_newline_from_end(log_text, tail_count)
        tail_chunk = log_text[tail_cut:]
        if tail_chunk.endswith("\n"):
            tail_chunk = tail_chunk[:-1]
        tail_start_line = total_input_lines - tail_count + 1
        return [(1, head_chunk), (tail_start_line, tail_chunk)], total_input_lines, True

    return [(1, log_text)], total_input_lines, False


def _scan_chunks_in_c(
    chunks: list[tuple[int, str]],
) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """Scan windowed chunks in C via `finditer`, materializing only matching lines."""
    candidate_lines: list[tuple[int, str]] = []
    flood_lines: list[tuple[int, str]] = []

    for chunk_start_line, chunk_text in chunks:
        if not chunk_text:
            continue
        chunk_lower = chunk_text.lower()
        last_line_end = -1
        cur_line_no = chunk_start_line
        prev_count_pos = 0

        for match in MASTER_LOG_SCAN_CS_RE.finditer(chunk_lower):
            m_start = match.start()
            if m_start <= last_line_end:
                continue
            line_start = chunk_text.rfind("\n", 0, m_start) + 1
            line_end = chunk_text.find("\n", match.end())
            if line_end == -1:
                line_end = len(chunk_text)
            cur_line_no += chunk_text.count("\n", prev_count_pos, line_start)
            prev_count_pos = line_start
            last_line_end = line_end

            line = chunk_text[line_start:line_end].rstrip("\r")
            line_lower = chunk_lower[line_start:line_end]
            candidate_lines.append((cur_line_no, line))
            if (
                "mqtt" in line_lower
                or "attributereport" in line_lower
                or "gentime" in line_lower
                or "0x000a" in line_lower
            ):
                flood_lines.append((cur_line_no, line))

    return candidate_lines, flood_lines


def _parse_log_timestamp_epoch(line: str) -> float | None:
    match = _LOG_TIMESTAMP_RE.search(line)
    if not match:
        return None
    iso_str = f"{match.group(1)}T{match.group(2)}+00:00"
    try:
        return datetime.fromisoformat(iso_str).astimezone(UTC).timestamp()
    except ValueError:
        return None


def _normalize_mqtt_payload(raw_payload: str) -> str:
    try:
        parsed: object = json.loads(raw_payload)
    except ValueError:
        return raw_payload.strip()
    if not isinstance(parsed, dict):
        return raw_payload.strip()
    filtered = {
        str(k): parsed[k]
        for k in sorted(parsed.keys(), key=str)
        if str(k) not in _VOLATILE_PAYLOAD_KEYS
    }
    if not filtered:
        return ""
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"))


def _detect_mqtt_telemetry_flood(
    indexed_lines: list[tuple[int, str]],
) -> SignatureMatch | None:
    """Detect ZCL MQTT publish floods, Z2M attributeReport floods, and delta-zero bursts."""
    device_events: dict[str, list[tuple[int, str, float | None, str]]] = {}

    for line_no, line in indexed_lines:
        if "MQTT" not in line and "attributeReport" not in line and "mqtt" not in line:
            continue
        m_mqtt = _MQTT_PUBLISH_RE.search(line)
        if m_mqtt is not None:
            topic_suffix = m_mqtt.group(1).strip()
            if topic_suffix.startswith("bridge") or topic_suffix.endswith("/availability"):
                continue
            payload_str = m_mqtt.group(2)
            ts = _parse_log_timestamp_epoch(line)
            norm_payload = _normalize_mqtt_payload(payload_str)
            device_events.setdefault(topic_suffix, []).append(
                (line_no, line.strip(), ts, norm_payload)
            )
            continue

        m_attr = _Z2M_ATTR_REPORT_RE.search(line)
        if m_attr is not None:
            dev_name = m_attr.group(1).strip()
            cluster = m_attr.group(2).strip()
            data_str = m_attr.group(3)
            ts = _parse_log_timestamp_epoch(line)
            norm_payload = f"{cluster}:{_normalize_mqtt_payload(data_str)}"
            device_events.setdefault(dev_name, []).append((line_no, line.strip(), ts, norm_payload))

    raw_flooders: list[tuple[FloodingDeviceSummary, list[MatchedLogLine]]] = []
    for device_name, events in device_events.items():
        if len(events) < 2:
            continue
        delta_zero_count = 0
        prev_payload: str | None = None
        timestamps: list[float] = []
        for _, _, ts, norm_payload in events:
            if ts is not None:
                timestamps.append(ts)
            if norm_payload and prev_payload == norm_payload:
                delta_zero_count += 1
            if norm_payload:
                prev_payload = norm_payload

        raw_span_s = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0
        duration_s = max(1.0, raw_span_s) if len(timestamps) >= 2 else 1.0
        rate_per_sec = round(len(events) / duration_s, 2)

        # Catch 2-message sub-second delta-zero bursts (e.g. kitchen_plug_2 firing twice in <1s)
        # as well as sustained >=3 message high-rate or duplicate streams.
        is_subsecond_duplicate_burst = (
            len(events) >= 2
            and delta_zero_count >= 1
            and len(timestamps) >= 2
            and raw_span_s <= 1.0
        )
        is_sustained_flood = len(events) >= 3 and (
            rate_per_sec >= 0.5 or delta_zero_count >= 2 or len(events) >= 5
        )
        if is_subsecond_duplicate_burst or is_sustained_flood:
            summary: FloodingDeviceSummary = {
                "device": device_name,
                "total_messages": len(events),
                "delta_zero_duplicates": delta_zero_count,
                "rate_msg_per_sec": rate_per_sec,
            }
            excerpts: list[MatchedLogLine] = [
                {"line_number": lno, "excerpt": exc[:300]} for lno, exc, _, _ in events[:5]
            ]
            raw_flooders.append((summary, excerpts))

    if not raw_flooders:
        return None

    raw_flooders.sort(
        key=lambda item: (
            -item[0]["rate_msg_per_sec"],
            -item[0]["delta_zero_duplicates"],
            -item[0]["total_messages"],
            item[0]["device"],
        )
    )
    total_occurrences = sum(item[0]["total_messages"] for item in raw_flooders)
    capped_flooders = raw_flooders[:MAX_FLOODING_DEVICES]
    flooding_devices = [item[0] for item in capped_flooders]
    matching_lines: list[MatchedLogLine] = []
    for _, excerpts in capped_flooders:
        for ex in excerpts:
            if len(matching_lines) < 10:
                matching_lines.append(ex)

    flood_meta = REMEDIATION_META["flood"]
    delta_meta = REMEDIATION_META["delta-zero"]
    top_dev = flooding_devices[0]
    mitigation = (
        f"Configure on-device OTA ZCL reporting deadbands for '{top_dev['device']}' "
        "(e.g. minimum_report_interval: 10s, reportable_change: 5W on haElectricalMeasurement "
        "activePower; note that host-side debounce in configuration.yaml does not stop physical "
        "802.15.4 radio transmissions), or upgrade coordinator firmware to SMLIGHT ZeroStack "
        f"({ZEROSTACK_RELEASE_NAME})."
    )
    combined_root_cause = f"{flood_meta['siliconRootCause']} {delta_meta['siliconRootCause']}"
    combined_fix = f"{flood_meta['zeroStackFix']} {delta_meta['zeroStackFix']}"
    diag_url = flood_meta["zeroStackDiagUrl"]

    return {
        "signature_id": "ZCL_TELEMETRY_DELTA_ZERO_FLOOD",
        "statusHex": "ZCL_FLOOD / DELTA_ZERO",
        "code": "ZCL_FLOOD",
        "name": "ZCL_TELEMETRY_FLOOD",
        "protocol": "zigbee",
        "title": (
            f"Unthrottled ZCL Telemetry & Delta-Zero Report Flood ({top_dev['device']}: "
            f"{top_dev['total_messages']} reports, {top_dev['delta_zero_duplicates']} delta-zero)"
        ),
        "description": (
            "Mains-powered Zigbee routers or smart plugs are flooding the 802.15.4 channel with "
            "high-rate or unchanged (delta-zero) ZCL attribute reports."
        ),
        "subsystem": "ZCL / NWK_SECURITY (FLOOD)",
        "severity": "warning",
        "occurrences": total_occurrences,
        "remediation_key": "flood",
        "remediation_meta": flood_meta,
        "flooding_devices": flooding_devices,
        "matching_lines": matching_lines,
        "siliconRootCause": combined_root_cause,
        "silicon_root_cause": combined_root_cause,
        "immediateMitigation": mitigation,
        "immediate_workarounds": [mitigation],
        "zeroStackFix": combined_fix,
        "zerostack_hardware_fix": combined_fix,
        "zeroStackDiagUrl": diag_url,
        "fix_url": diag_url,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "marketing_url": ZEROSTACK_MARKETING_URL,
    }


def _detect_gentime_read_flood(
    indexed_lines: list[tuple[int, str]],
) -> SignatureMatch | None:
    """Detect autonomous ZCL Cluster 0x000A (`genTime`) read floods from Tuya/third-party nodes."""
    events_by_dev: dict[str, list[tuple[int, str, float | None]]] = {}
    for line_no, line in indexed_lines:
        if "genTime" not in line and "0x000a" not in line and "0x000A" not in line:
            continue
        m = _ZCL_GENTIME_READ_RE.search(line)
        if m is None:
            continue
        dev_name = m.group(1).strip()
        ts = _parse_log_timestamp_epoch(line)
        events_by_dev.setdefault(dev_name, []).append((line_no, line.strip(), ts))

    flooders: list[tuple[FloodingDeviceSummary, list[MatchedLogLine]]] = []
    for dev_name, evs in events_by_dev.items():
        timestamps = [ts for _, _, ts in evs if ts is not None]
        raw_span_s = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0
        duration_s = max(1.0, raw_span_s) if len(timestamps) >= 2 else 1.0
        rate = round(len(evs) / duration_s, 2)
        if len(evs) >= 3 or (len(evs) >= 2 and len(timestamps) >= 2 and raw_span_s <= 1.0):
            flooders.append(
                (
                    {
                        "device": dev_name,
                        "total_messages": len(evs),
                        "delta_zero_duplicates": max(0, len(evs) - 1),
                        "rate_msg_per_sec": rate,
                    },
                    [{"line_number": lno, "excerpt": exc[:300]} for lno, exc, _ in evs[:5]],
                )
            )

    if not flooders:
        return None

    flooders.sort(
        key=lambda item: (
            -item[0]["rate_msg_per_sec"],
            -item[0]["total_messages"],
            item[0]["device"],
        )
    )
    total_hits = sum(item[0]["total_messages"] for item in flooders)
    capped = flooders[:MAX_FLOODING_DEVICES]
    devices = [item[0] for item in capped]
    matching_lines: list[MatchedLogLine] = []
    for _, excerpts in capped:
        for ex in excerpts:
            if len(matching_lines) < 10:
                matching_lines.append(ex)

    gentime_meta = REMEDIATION_META["gentime-floods"]
    top_dev = devices[0]
    mitigation = (
        f"Update firmware or add a Zigbee2MQTT external converter to silence repeated ZCL "
        f"genTime (0x000A) read polling on '{top_dev['device']}', or upgrade your TI SimpleLink "
        f"F2 coordinator to SMLIGHT ZeroStack ({ZEROSTACK_RELEASE_NAME})."
    )
    return {
        "signature_id": "ZCL_GENTIME_READ_FLOOD",
        "statusHex": "0x000A (genTime)",
        "code": "ZCL_GENTIME_FLOOD",
        "name": "ZCL_GENTIME_READ_FLOOD",
        "protocol": "zigbee",
        "title": (
            f"Autonomous ZCL genTime (0x000A) Read Flood ({top_dev['device']}: "
            f"{top_dev['total_messages']} reads)"
        ),
        "description": (
            "Devices polling ZCL Cluster 0x000A (genTime) in tight loops are flooding the "
            "coordinator with synchronous ZCL Read Attributes requests."
        ),
        "subsystem": "ZCL (0x000A genTime)",
        "severity": "warning",
        "occurrences": total_hits,
        "remediation_key": "gentime-floods",
        "remediation_meta": gentime_meta,
        "flooding_devices": devices,
        "matching_lines": matching_lines,
        "siliconRootCause": gentime_meta["siliconRootCause"],
        "silicon_root_cause": gentime_meta["siliconRootCause"],
        "immediateMitigation": mitigation,
        "immediate_workarounds": [mitigation],
        "zeroStackFix": gentime_meta["zeroStackFix"],
        "zerostack_hardware_fix": gentime_meta["zeroStackFix"],
        "zeroStackDiagUrl": gentime_meta["zeroStackDiagUrl"],
        "fix_url": gentime_meta["zeroStackDiagUrl"],
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "marketing_url": ZEROSTACK_MARKETING_URL,
    }


def _detect_startup_and_link_issues(
    candidate_lines: list[tuple[int, str]],
) -> list[SignatureMatch]:
    """Surface startup, channel, discovery, PAN conflict, and UART link `remediationMeta` rules."""
    specs: tuple[tuple[re.Pattern[str], str, str, str, str, str, str, str], ...] = (
        (
            _EZSP_LEGACY_VERSION_RE,
            "EZSP_LEGACY_PROTOCOL_VERSION",
            "EZSP_VERSION",
            "ember",
            "critical",
            "issue-ezsp-version",
            "Legacy Silicon Labs EZSP Protocol Firmware (< v13)",
            (
                "Flash EmberZNet NCP >= EZSP v13 via SMLIGHT SLZB-OS or Web Flasher and use "
                "adapter: ember in Zigbee2MQTT configuration.yaml."
            ),
        ),
        (
            _CHANNEL_MISMATCH_RE,
            "CHANNEL_MISMATCH_AUTO_SWITCH",
            "CHANNEL_MISMATCH",
            "zigbee",
            "warning",
            "issue-channel-mismatch",
            "Coordinator 802.15.4 Channel Mismatch / Forced Realignment",
            (
                "Revert channel in configuration.yaml to match the coordinator's existing "
                "network channel to avoid stranding sleeping sensors, or re-pair devices."
            ),
        ),
        (
            _ADAPTER_DISCOVERY_RE,
            "ADAPTER_DISCOVERY_ERROR",
            "USB_DISCOVERY_ERR",
            "zigbee",
            "critical",
            "issue-adapter-discovery",
            "Coordinator USB / Serial Adapter Auto-Discovery Error",
            (
                "Specify an explicit /dev/serial/by-id/... path or tcp://host:6638 socket in "
                "configuration.yaml and verify container USB passthrough."
            ),
        ),
        (
            _CONFIG_MISMATCH_RE,
            "ADAPTER_CONFIG_MISMATCH",
            "NVRAM_CONFIG_MISMATCH",
            "zigbee",
            "critical",
            "issue-config-mismatch",
            "Host Configuration vs. Coordinator NVRAM State Mismatch",
            (
                "Align pan_id, ext_pan_id, and network_key in configuration.yaml with "
                "coordinator_backup.json, or allow a clean coordinator backup restore."
            ),
        ),
        (
            _PAN_CONFLICT_RE,
            "PAN_ID_CONFLICT",
            "PAN_CONFLICT",
            "zigbee",
            "critical",
            "issue-pan-conflict",
            "IEEE 802.15.4 16-Bit PAN ID Conflict Detected on Channel",
            (
                "Choose a distinct pan_id in configuration.yaml or power down any secondary "
                "un-reset coordinator broadcasting the same PAN ID."
            ),
        ),
        (
            _ASH_UART_LINK_RE,
            "ASH_UART_LINK_ERROR",
            "ASH_CRC_COMM",
            "ember",
            "warning",
            "ash-uart-link",
            "UART / ASHv2 Serial Framing CRC Error or Disconnection",
            (
                "Verify baudrate and hardware/software flow control settings, use wired "
                "Ethernet for network coordinators, and isolate USB adapters from USB 3.0 ports."
            ),
        ),
        (
            _ADAPTER_TIMEOUT_RE,
            "ADAPTER_STARTUP_TIMEOUT",
            "SERIAL_OPEN_TIMEOUT",
            "zigbee",
            "critical",
            "issue-adapter-timeout",
            "Coordinator Serial / TCP Initialization Timeout",
            (
                "Verify serial port path or TCP bridge reachability, set rtscts: false on "
                "adapters without DIO10/DIO11 RTS/CTS wiring, and match UART baudrate."
            ),
        ),
    )

    results: list[SignatureMatch] = []
    for pattern, sig_id, code, proto, sev, rem_key, title, mitigation in specs:
        matched: list[MatchedLogLine] = [
            {"line_number": lno, "excerpt": line.strip()[:300]}
            for lno, line in candidate_lines
            if pattern.search(line) is not None
        ]
        if not matched:
            continue
        meta = REMEDIATION_META[rem_key]
        results.append(
            {
                "signature_id": sig_id,
                "statusHex": code,
                "code": code,
                "name": sig_id,
                "protocol": proto,
                "title": title,
                "description": meta["siliconRootCause"],
                "subsystem": f"{proto.upper()} ({code})",
                "severity": sev,
                "occurrences": len(matched),
                "remediation_key": rem_key,
                "remediation_meta": meta,
                "matching_lines": matched[:10],
                "siliconRootCause": meta["siliconRootCause"],
                "silicon_root_cause": meta["siliconRootCause"],
                "immediateMitigation": mitigation,
                "immediate_workarounds": [mitigation],
                "zeroStackFix": meta["zeroStackFix"],
                "zerostack_hardware_fix": meta["zeroStackFix"],
                "zeroStackDiagUrl": meta["zeroStackDiagUrl"],
                "fix_url": meta["zeroStackDiagUrl"],
                "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
                "marketing_url": ZEROSTACK_MARKETING_URL,
            }
        )
    return results


def _match_sort_key(item: tuple[int, SignatureMatch]) -> tuple[int, int, int, int]:
    idx, match = item
    sev_rank = _SEVERITY_RANK.get(match["severity"].lower(), 0)
    prio = _ROOT_CAUSE_PRIORITY.get(match["signature_id"], 50)
    return (-sev_rank, -prio, -match["occurrences"], idx)


def analyze_log_impl(log_text: str) -> LogAnalysisResult:
    """Core implementation for `analyze_zigbee_thread_log`."""
    if not log_text or not log_text.strip():
        return {
            "status": "empty_input",
            "release": ZEROSTACK_RELEASE_NAME,
            "matched_count": 0,
            "matches": [],
            "truncated": False,
            "total_input_lines": 0,
            "summary": "No log text provided for analysis.",
            "marketing_url": ZEROSTACK_MARKETING_URL,
            "zerostack_repository": ZEROSTACK_REPO_URL,
            "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        }

    chunks, total_input_lines, truncated = _window_log_chunks(log_text)
    candidate_lines, flood_lines = _scan_chunks_in_c(chunks)

    matches: list[SignatureMatch] = []

    if candidate_lines:
        for rule in LOG_SIGNATURE_RULES:
            matching_lines: list[MatchedLogLine] = []
            is_generic_srsp = rule.signature_id == "ZNP_SRSP_6000MS_TIMEOUT"
            for line_no, line in candidate_lines:
                if is_generic_srsp and _SYS_STARTUP_SRSP_RE.search(line) is not None:
                    continue
                if rule.combined_pattern.search(line) is not None:
                    matching_lines.append({"line_number": line_no, "excerpt": line.strip()[:300]})

            if matching_lines:
                match_obj: SignatureMatch = {
                    "signature_id": rule.signature_id,
                    "statusHex": rule.status_hex,
                    "code": rule.status_hex,
                    "name": rule.name,
                    "protocol": rule.protocol,
                    "title": rule.title,
                    "description": rule.description,
                    "subsystem": rule.subsystem,
                    "severity": rule.severity,
                    "occurrences": len(matching_lines),
                    "matching_lines": matching_lines[:10],
                    "siliconRootCause": rule.silicon_root_cause,
                    "silicon_root_cause": rule.silicon_root_cause,
                    "immediateMitigation": rule.immediate_mitigation,
                    "immediate_workarounds": list(rule.immediate_workarounds),
                    "zeroStackFix": rule.zerostack_hardware_fix,
                    "zerostack_hardware_fix": rule.zerostack_hardware_fix,
                    "zeroStackDiagUrl": rule.zero_stack_diag_url,
                    "fix_url": rule.zero_stack_diag_url,
                    "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
                    "marketing_url": ZEROSTACK_MARKETING_URL,
                }
                if rule.remediation_key is not None and rule.remediation_key in REMEDIATION_META:
                    match_obj["remediation_key"] = rule.remediation_key
                    match_obj["remediation_meta"] = REMEDIATION_META[rule.remediation_key]
                matches.append(match_obj)

        matches.extend(_detect_startup_and_link_issues(candidate_lines))

    if flood_lines:
        flood_match = _detect_mqtt_telemetry_flood(flood_lines)
        if flood_match is not None:
            matches.append(flood_match)

        gentime_match = _detect_gentime_read_flood(flood_lines)
        if gentime_match is not None:
            matches.append(gentime_match)

    if not matches:
        return {
            "status": "no_known_fault_signatures",
            "release": ZEROSTACK_RELEASE_NAME,
            "matched_count": 0,
            "matches": [],
            "truncated": truncated,
            "total_input_lines": total_input_lines,
            "summary": (
                "No critical ZNP/EZSP/Spinel silicon fault signatures detected in the "
                "provided log snippet."
            ),
            "marketing_url": ZEROSTACK_MARKETING_URL,
            "zerostack_repository": ZEROSTACK_REPO_URL,
            "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        }

    ranked_matches = [m for _, m in sorted(enumerate(matches), key=_match_sort_key)]
    primary = ranked_matches[0]
    return {
        "status": "fault_signatures_detected",
        "release": ZEROSTACK_RELEASE_NAME,
        "matched_count": len(ranked_matches),
        "truncated": truncated,
        "total_input_lines": total_input_lines,
        "primary_diagnosis": primary["title"],
        "primary_root_cause": primary["silicon_root_cause"],
        "primary_fix_url": primary["fix_url"],
        "zeroStackDiagUrl": primary["zeroStackDiagUrl"],
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "matches": ranked_matches,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }
