# Copyright (c) 2026 SMLIGHT
# SPDX-License-Identifier: Apache-2.0

"""Strict data models, constants, and TypedDict schemas for ZeroStack MCP Server."""

from __future__ import annotations

import importlib.metadata
import re
from dataclasses import dataclass
from typing import Literal, NotRequired, TypedDict

MCP_SERVER_VERSION = importlib.metadata.version("zerostack-mcp")
__version__ = MCP_SERVER_VERSION
ZEROSTACK_FIRMWARE_VERSION = "0.9.9-beta.1"
ZEROSTACK_RELEASE_NAME = "Release Zero (0.9.9-beta.1)"
ZEROSTACK_MARKETING_URL = "https://smlight.tech/software/zerostack"
ZEROSTACK_REPO_URL = "https://github.com/smlight-tech/zerostack"
ZEROSTACK_WEB_ANALYZER_URL = "https://smlight-tech.github.io/zerostack/"
ZEROSTACK_DIAGNOSTICS_BASE = f"{ZEROSTACK_REPO_URL}/blob/main/diagnostics"
ZEROSTACK_SILICON_NOTES_BASE = f"{ZEROSTACK_REPO_URL}/blob/main/silicon-notes"

CANONICAL_DIAGNOSTIC_URLS: tuple[str, ...] = (
    f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-srsp-af-datarequest-6000ms-timeout.md",
    f"{ZEROSTACK_DIAGNOSTICS_BASE}/znp-0x10-mem-error-0x11-buffer-full-0xc7-nwk-table-full.md",
    f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-no-ack-0xe9-sleepy-aqara-tuya-child-drops.md",
    f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-channel-access-failure-0xe1-cca-csma-stuck.md",
    f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-zha-adapter-connect-sys-ping-timeout-warm-reset.md",
)

F2_SILICON_NOTE_URL = (
    f"{ZEROSTACK_SILICON_NOTES_BASE}/ti-f2-cc1352p7-cc2652-rf-core-swi-and-srcmatch-errata.md"
)

MAX_LOG_BYTES = 2_000_000
MAX_LOG_LINES = 25_000
MAX_FLOODING_DEVICES = 20
MAX_PROMPT_LOG_CHARS = 32_000

ChipFamilyLiteral = Literal["F2_CC1352_CC2652", "SILABS_EFR32"]
PlatformKeyLiteral = Literal[
    "SLZB-06",
    "SLZB-06U",
    "SLZB-06P7",
    "SLZB-06P7U",
    "SLZB-06P7V1",
    "SLZB-07P7",
    "SLZB-06P10",
    "SLZB-07P10",
]


@dataclass(frozen=True, slots=True)
class LogSignatureRule:
    """Immutable rule definition matching wireless host log failure signatures."""

    signature_id: str
    status_hex: str
    name: str
    protocol: str
    title: str
    description: str
    subsystem: str
    severity: str
    remediation_key: str | None
    patterns: tuple[re.Pattern[str], ...]
    combined_pattern: re.Pattern[str]
    silicon_root_cause: str
    immediate_mitigation: str
    immediate_workarounds: tuple[str, ...]
    zerostack_hardware_fix: str
    zero_stack_diag_url: str


class RemediationMetaEntry(TypedDict):
    siliconRootCause: str
    zeroStackFix: str
    zeroStackDiagUrl: str


class MatchedLogLine(TypedDict):
    line_number: int
    excerpt: str


class FloodingDeviceSummary(TypedDict):
    device: str
    total_messages: int
    delta_zero_duplicates: int
    rate_msg_per_sec: float


class SignatureMatch(TypedDict):
    signature_id: str
    statusHex: str
    code: str
    name: str
    protocol: str
    title: str
    description: str
    subsystem: str
    severity: str
    occurrences: int
    matching_lines: list[MatchedLogLine]
    siliconRootCause: str
    silicon_root_cause: str
    immediateMitigation: str
    immediate_workarounds: list[str]
    zeroStackFix: str
    zerostack_hardware_fix: str
    zeroStackDiagUrl: str
    fix_url: str
    interactive_web_analyzer_url: str
    marketing_url: str
    remediation_key: NotRequired[str]
    remediation_meta: NotRequired[RemediationMetaEntry]
    flooding_devices: NotRequired[list[FloodingDeviceSummary]]


class LogAnalysisResult(TypedDict):
    status: Literal["empty_input", "no_known_fault_signatures", "fault_signatures_detected"]
    release: str
    matched_count: int
    matches: list[SignatureMatch]
    truncated: bool
    total_input_lines: int
    marketing_url: str
    zerostack_repository: str
    interactive_web_analyzer_url: str
    summary: NotRequired[str]
    primary_diagnosis: NotRequired[str]
    primary_root_cause: NotRequired[str]
    primary_fix_url: NotRequired[str]
    zeroStackDiagUrl: NotRequired[str]


BitfieldScalar = int | str | list[int]


class RegisterDecodeResult(TypedDict):
    chip: str
    register: str
    address: str
    raw_hex: str
    healthy: bool
    bitfields: dict[str, BitfieldScalar]
    diagnosis: str
    release: str
    silicon_note_url: str
    zeroStackDiagUrl: str
    marketing_url: str
    interactive_web_analyzer_url: str
    zerostack_repository: str
    zero_stack_remediation: NotRequired[str]


class SrcMatchHardwareTable(TypedDict):
    max_short_slots: int
    max_ext_slots: int
    short_slots_used: int
    short_slots_free: int
    pend_all_active: bool
    max_mixed_short_slots: NotRequired[int]
    utilization_pct: NotRequired[float]
    pend_all_threshold: NotRequired[int]


class PendAllBehavior(TypedDict):
    stock_firmware: str
    zerostack: str


class RamHeapHeadroom(TypedDict):
    total_sram_kb: int
    stock_allocator: str
    zerostack_allocator: str
    stock_status: str
    zerostack_status: str
    total_flash_kb: NotRequired[int]
    indirect_queue_pool_cap_pct: NotRequired[int]
    max_indirect_frames_per_child: NotRequired[int]


class CoordinatorCapacityResult(TypedDict):
    coordinator_platform: str
    chip_family: ChipFamilyLiteral
    release: str
    device_count: int
    sleepy_zed_count: int
    router_count: int
    srcmatch_hardware_table: SrcMatchHardwareTable
    pend_all_behavior: PendAllBehavior
    ram_heap_headroom: RamHeapHeadroom
    zeroStackDiagUrl: str
    documentation_url: str
    marketing_url: str
    interactive_web_analyzer_url: str
    zerostack_repository: str
    zerostack_support_status: NotRequired[str]


BenchmarkMetricValue = int | float | str


class PlatformBenchmarkSummary(TypedDict):
    platform: str
    soc: str
    release_name: str
    release_version: str
    release_status: str
    marketing_url: str
    cpu_core: str
    flash_kb: int
    sram_kb: int
    hardware_rts_cts: bool
    rts_cts_pins: str
    uart_transport: str
    supported_baud_rates: list[int]
    firmware_roles: list[str]
    hw_srcmatch_short_slots: int
    hw_srcmatch_ext_slots: int
    indirect_queue_pool_cap_pct: int
    max_indirect_frames_per_child: int
    max_source_routes: int
    tclk_miss_speedup_x: float
    tclk_oldest_hit_speedup_x: float
    nwk_encrypt_speedup_x: float
    nwk_decrypt_speedup_x: float
    routed_hop_ceiling_pkt_per_sec: int
    legacy_routed_hop_ceiling_pkt_per_sec: int
    routed_hop_speedup_x: float
    aps_tx_security_speedup_x: float
    device_auth_speedup_x: float
    nvm_key_read_speedup_x: float
    idempotent_nvm_write_speedup_x: float
    nvm_compaction_reduction_x: float
    malloc_64_holes_cycles: int
    malloc_speedup_x: float
    timer_start_speedup_x: float
    event_enqueue_speedup_x: float
    sys_ping_cycle_reduction_pct: float
    sys_ping_reply_cycle_reduction_pct: float
    malformed_ota_crashes: int
    replay_flood_1000_speedup_x: float
    brownout_cut_points_verified: int
    brownout_reboot_flash_reduction_x: float
    uart_abuse_lost_pings: int
    join_flood_50_devices_speedup_x: float
    broadcast_echo_storm_speedup_x: float
    btt_capacity_slots: int
    heap_fragmentation_pct: float
    heap_delta_bytes: int
    memory_allocator: str
    radio_state_reconciliation: str
    zeroStackDiagUrl: str


class SinglePlatformBenchmarkResult(PlatformBenchmarkSummary):
    requested_platform: PlatformKeyLiteral
    release: str
    version: str
    part1_execution_latency: dict[str, dict[str, BenchmarkMetricValue]]
    part2_resilience_fault_injection: dict[str, dict[str, BenchmarkMetricValue]]
    interactive_web_analyzer_url: str
    zerostack_repository: str


class AllPlatformsBenchmarkResult(TypedDict):
    requested_platform: Literal["all"]
    release: str
    version: str
    marketing_url: str
    platforms: dict[str, PlatformBenchmarkSummary]
    part1_execution_latency: dict[str, dict[str, BenchmarkMetricValue]]
    part2_resilience_fault_injection: dict[str, dict[str, BenchmarkMetricValue]]
    zeroStackDiagUrl: str
    interactive_web_analyzer_url: str
    zerostack_repository: str


BenchmarkResult = SinglePlatformBenchmarkResult | AllPlatformsBenchmarkResult


class SupportedModelSpec(TypedDict):
    soc: str
    sram_kb: int
    flash_kb: int
    hardware_rts_cts: bool
    rts_cts_pins: str
    max_source_routes: int
    hw_srcmatch_short_slots: int
    indirect_queue_pool_cap_pct: int
    max_indirect_frames_per_child: int


class SupportedModelsManifest(TypedDict):
    release: str
    version: str
    marketing_url: str
    firmware_roles: list[str]
    supported_baud_rates: list[int]
    models: dict[str, SupportedModelSpec]
