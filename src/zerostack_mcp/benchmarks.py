# Copyright (c) 2026 SMLIGHT
# SPDX-License-Identifier: Apache-2.0

"""Cycle-accurate Part 1 & Part 2 hardware benchmarks for SMLIGHT ZeroStack."""

from __future__ import annotations

from typing import Literal

from zerostack_mcp.models import (
    ZEROSTACK_DIAGNOSTICS_BASE,
    ZEROSTACK_FIRMWARE_VERSION,
    ZEROSTACK_MARKETING_URL,
    ZEROSTACK_RELEASE_NAME,
    ZEROSTACK_REPO_URL,
    ZEROSTACK_WEB_ANALYZER_URL,
    AllPlatformsBenchmarkResult,
    BenchmarkMetricValue,
    BenchmarkResult,
    PlatformBenchmarkSummary,
    PlatformKeyLiteral,
    SinglePlatformBenchmarkResult,
    SupportedModelsManifest,
)

PART1_EXECUTION_BENCHMARKS: dict[str, dict[str, BenchmarkMetricValue]] = {
    "tclk_lookup_miss_300_entries": {
        "legacy_cycles": 1486228,
        "legacy_latency_ms": 30.96,
        "zerostack_cycles": 326,
        "zerostack_latency_us": 6.8,
        "speedup_x": 4559.0,
        "zerostack_flash_reads": 0,
    },
    "tclk_lookup_oldest_hit_age383": {
        "legacy_cycles": 620396,
        "legacy_latency_ms": 12.92,
        "zerostack_cycles": 324,
        "zerostack_latency_us": 6.75,
        "speedup_x": 1914.8,
        "slot_0_legacy_cycles": 2961,
        "slot_0_zerostack_cycles": 417,
        "slot_0_speedup_x": 7.1,
        "slot_299_legacy_cycles": 2962,
        "slot_299_zerostack_cycles": 324,
        "slot_299_speedup_x": 9.1,
    },
    "nwk_security_encrypt_d150": {
        "legacy_cycles": 533156,
        "legacy_latency_ms": 11.11,
        "zerostack_cycles": 3968,
        "zerostack_latency_us": 82.7,
        "speedup_x": 134.4,
        "d0_legacy_cycles": 8558,
        "d0_legacy_latency_us": 178.3,
        "d0_zerostack_cycles": 3980,
        "d0_zerostack_latency_us": 82.9,
        "d0_speedup_x": 2.15,
        "zerostack_flash_reads": 0,
    },
    "nwk_security_decrypt_d150": {
        "legacy_cycles": 532182,
        "legacy_latency_ms": 11.09,
        "zerostack_cycles": 3824,
        "zerostack_latency_us": 79.7,
        "speedup_x": 139.2,
        "d0_legacy_cycles": 8091,
        "d0_legacy_latency_us": 168.6,
        "d0_zerostack_cycles": 3840,
        "d0_zerostack_latency_us": 80.0,
        "zerostack_flash_reads": 0,
    },
    "routed_hop_security_ceiling_d150": {
        "legacy_cycles": 1065338,
        "legacy_latency_ms": 22.19,
        "legacy_max_routed_pkt_per_sec": 45,
        "zerostack_cycles": 7792,
        "zerostack_latency_us": 162.3,
        "zerostack_max_routed_pkt_per_sec": 6100,
        "speedup_x": 135.0,
    },
    "aps_tx_security_300_peers": {
        "legacy_cycles_range": "52,909 - 409,301",
        "legacy_max_latency_ms": 8.53,
        "zerostack_cycles_range": "5,410 - 5,424",
        "zerostack_latency_us": 113.0,
        "max_speedup_x": 75.5,
    },
    "device_auth_check_slot299": {
        "legacy_cycles_range": "1,656 - 42,243",
        "legacy_max_latency_us": 880.0,
        "zerostack_cycles_range": "181 - 179",
        "zerostack_latency_us": 3.7,
        "max_speedup_x": 236.0,
    },
    "nvm_stack_key_read_d150": {
        "legacy_cycles_range": "2,347 - 64,817",
        "legacy_max_latency_ms": 1.35,
        "zerostack_cycles_range": "302 - 303",
        "zerostack_latency_us": 6.3,
        "d0_speedup_x": 7.8,
        "max_speedup_x": 213.9,
        "general_nvm_item_read_d0_256_zerostack_cycles": "1,696 - 1,724",
        "general_nvm_item_read_d0_256_legacy_cycles": "581 - 14,303",
    },
    "idempotent_nvm_state_write_100b_x48": {
        "legacy_cycles_2b_20b_100b": "19.1k / 35.3k / 100.7k",
        "legacy_cycles": 100714,
        "legacy_flash_writes": "48 / 48",
        "zerostack_cycles_2b_20b_100b": "2.0k / 2.3k / 3.8k",
        "zerostack_cycles": 3770,
        "zerostack_flash_bytes_written": 0,
        "speedup_x": 26.7,
        "unnecessary_flash_wear_pct": 0.0,
    },
    "nvm_compaction_frequency": {
        "legacy_first_compaction_write": 69,
        "legacy_compaction_stall_ms": 163.9,
        "zerostack_first_compaction_write": 1013,
        "zerostack_compaction_stall_ms": 13.7,
        "compaction_frequency_reduction_x": 14.7,
    },
    "dynamic_memory_malloc_64_holes": {
        "legacy_malloc_free_k0_16_32_64": "310/84, 869/82, 1,430/82, 2,550/82",
        "zerostack_malloc_free_k0_16_32_64": "225/200, 218/175, 220/175, 218/175",
        "legacy_cycles": 2550,
        "zerostack_cycles": 218,
        "speedup_x": 11.7,
        "complexity": "O(1)",
    },
    "timer_start_latency_39_timers": {
        "legacy_cycles_64_holes_t0_39": "6,894 -> 10,034",
        "legacy_cycles": 10034,
        "legacy_latency_us": 209.0,
        "zerostack_cycles_64_holes_t0_39": "930 -> 1,448",
        "zerostack_cycles": 1448,
        "zerostack_latency_us": 30.2,
        "speedup_x": 6.93,
        "clean_heap_legacy_cycles_t0_39": "2,652 -> 5,844",
        "clean_heap_zerostack_cycles_t0_39": "912 -> 1,447",
        "clean_heap_speedup_x": 4.04,
        "timer_stop_legacy_cycles_t0_39": "515 -> 1,370",
        "timer_stop_zerostack_cycles_t0_39": "450 -> 1,050",
        "timer_stop_speedup_x": 1.30,
    },
    "inter_task_event_enqueue_64_queued": {
        "msg_send_legacy_cycles_q0_64": "497 -> 935",
        "legacy_cycles": 935,
        "msg_send_zerostack_cycles_q0_64": "364 -> 322",
        "zerostack_cycles": 322,
        "speedup_x": 2.9,
        "msg_receive_legacy_cycles_q0_64": "383 -> 628",
        "msg_receive_zerostack_cycles_q0_64": "168 -> 333",
        "msg_receive_speedup_q0_x": 2.28,
        "msg_receive_speedup_q64_x": 1.89,
        "complexity": "O(1)",
    },
    "host_serial_sys_ping_115200": {
        "legacy_total_cycles": 9790,
        "zerostack_total_cycles": 4618,
        "total_cycle_reduction_pct": 53.0,
        "legacy_reply_cycles": 4921,
        "zerostack_reply_cycles": 816,
        "reply_cycle_reduction_pct": 83.0,
        "legacy_240b_cycles": 24404,
        "zerostack_240b_cycles": 12784,
        "frame_240b_reduction_pct": 48.0,
    },
}

PART2_RESILIENCE_BENCHMARKS: dict[str, dict[str, BenchmarkMetricValue]] = {
    "malformed_ota_secured_frames": {
        "nwk_aps_fault_classes_tested": 12,
        "mac_boundary_vectors_tested": 3255,
        "legacy_behavior": (
            "Deterministic remote CPU HardFault (Precise BusFault after 143,345 & 144,412 "
            "cycles on Malformed Secured Frame Classes A & B) + accepts malformed routing "
            "headers, mutates security state & delivers to app (144,127 cycles)"
        ),
        "zerostack_crashes": 0,
        "zerostack_rejection_cycles_range": "320 - 6,631",
        "zerostack_malformed_routing_cycles": 790,
        "zerostack_malformed_routing_us": 16.0,
        "zerostack_malformed_routing_speedup_x": 182.0,
        "cpu_cost_reduction_range": "9.8x - 402x",
    },
    "cryptographic_replay_flood_1000_frames_d150": {
        "legacy_cycles_per_replay": 143802,
        "legacy_latency_per_replay_ms": 3.0,
        "legacy_total_cpu_lockup_s": 2.99,
        "zerostack_cycles_per_replay": 1550,
        "zerostack_latency_per_replay_us": 32.0,
        "zerostack_total_cpu_ms": 32.4,
        "speedup_x": 92.8,
        "authenticated_tamper_legacy_cycles": "143,058 - 143,065",
        "authenticated_tamper_zerostack_cycles": "4,760 - 4,771",
        "authenticated_tamper_zerostack_us": 99.0,
        "authenticated_tamper_speedup_x": 30.0,
    },
    "nor_flash_brownout_power_loss_fuzzing": {
        "total_hardware_cut_points": 22959,
        "mid_compaction_cut_points": 22565,
        "record_update_cut_points": 394,
        "shadow_fuzz_operations": 2000000,
        "zerostack_lost_or_corrupted_records": 0,
        "zerostack_nor_write_verify_conflicts": 0,
        "legacy_nor_write_verify_conflicts": 1,
        "legacy_torn_record_reboot_bytes_written": 20232,
        "legacy_torn_record_reboot_page_erases": 62,
        "zerostack_torn_record_reboot_bytes_written": 27,
        "zerostack_torn_record_reboot_page_erases": 0,
        "post_brownout_flash_write_reduction_x": 749.3,
    },
    "hostile_uart_serial_framing_abuse_6_scenarios": {
        "baud_rate_tested": 115200,
        "scenarios_tested": 6,
        "legacy_300x_sof_blackout_s": 8.84,
        "legacy_consecutive_lost_pings": 44,
        "legacy_512b_random_noise_blackout_s": 6.00,
        "legacy_512b_random_noise_lost_pings": 30,
        "legacy_truncated_frame_lost_pings": 1,
        "legacy_truncated_frame_stall_ms": 203,
        "zerostack_lost_pings_all_scenarios": 0,
        "zerostack_recovery_range_ms": "3 - 55",
        "zerostack_300x_sof_recovery_ms": 29,
        "zerostack_truncated_frame_recovery_ms": 3,
        "zerostack_heap_delta_bytes": 0,
    },
    "unauthenticated_join_tclk_miss_flood_50_devices_d300": {
        "legacy_stall_per_miss_ms": 33.9,
        "legacy_total_stall_s": 1.70,
        "zerostack_lookup_cycles": 208,
        "zerostack_lookup_us": 4.0,
        "zerostack_uart_rtt_ms": 4.3,
        "zerostack_total_s": 0.22,
        "speedup_x": 7.7,
        "bounded_timer_refusal_limit": 194,
        "bounded_timer_refusal_status": "NO_TIMER_AVAIL",
        "zero_byte_free_heap_pings_answered": "5 / 5",
        "zero_byte_free_heap_delta_bytes": 0,
    },
    "mesh_broadcast_storm_1000_echoes_50_routers_d150": {
        "legacy_cycles_per_echo": 143865,
        "legacy_latency_per_echo_ms": 3.00,
        "legacy_total_cpu_ms": 3004.97,
        "legacy_total_cpu_s": 3.00,
        "zerostack_p50_cycles_per_echo": 7076,
        "zerostack_p99_cycles_per_echo": 7335,
        "zerostack_p50_latency_us": 147.0,
        "zerostack_total_cpu_ms": 151.16,
        "per_echo_speedup_x": 20.3,
        "total_cpu_reduction_x": 19.9,
    },
    "post_outage_64_unique_broadcast_flood_d150": {
        "legacy_btt_admitted": 30,
        "legacy_admitted_cycles": 154705,
        "zerostack_btt_admitted": 40,
        "zerostack_admitted_cycles": 17699,
        "zerostack_admitted_us": 369.0,
        "btt_capacity_increase_pct": 33.3,
        "legacy_overflow_shed_cycles": 144644,
        "legacy_overflow_shed_ms": 3.01,
        "zerostack_overflow_shed_cycles": 8341,
        "zerostack_overflow_shed_us": 174.0,
        "overflow_shed_speedup_x": 17.3,
        "legacy_total_cpu_ms": 200.25,
        "zerostack_total_cpu_ms": 18.87,
        "total_cpu_reduction_x": 10.6,
        "duplicate_deliveries": 0,
        "zerostack_heap_delta_bytes": 0,
    },
}


def _build_platform_benchmark(
    *,
    platform: str,
    soc: str,
    cpu_core: str,
    flash_kb: int,
    sram_kb: int,
    hardware_rts_cts: bool,
    rts_cts_pins: str,
    max_source_routes: int,
) -> PlatformBenchmarkSummary:
    return {
        "platform": platform,
        "soc": soc,
        "release_name": ZEROSTACK_RELEASE_NAME,
        "release_version": ZEROSTACK_FIRMWARE_VERSION,
        "release_status": (
            f"SMLIGHT ZeroStack {ZEROSTACK_RELEASE_NAME} — Zigbee 3.0 / PRO R23 Coordinator & "
            "Router firmware for SMLIGHT TI SimpleLink F2 adapters"
        ),
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "cpu_core": cpu_core,
        "flash_kb": flash_kb,
        "sram_kb": sram_kb,
        "hardware_rts_cts": hardware_rts_cts,
        "rts_cts_pins": rts_cts_pins,
        "uart_transport": (
            "DMA-driven UART with live auto-baud detection (115200 / 460800 / 1000000 baud)"
        ),
        "supported_baud_rates": [115200, 460800, 1000000],
        "firmware_roles": [
            "Coordinator (TI ZNP / MT)",
            "Router (Zigbee 3.0 / PRO R23)",
        ],
        "hw_srcmatch_short_slots": 32,
        "hw_srcmatch_ext_slots": 32,
        "indirect_queue_pool_cap_pct": 50,
        "max_indirect_frames_per_child": 2,
        "max_source_routes": max_source_routes,
        "tclk_miss_speedup_x": 4559.0,
        "tclk_oldest_hit_speedup_x": 1914.8,
        "nwk_encrypt_speedup_x": 134.4,
        "nwk_decrypt_speedup_x": 139.2,
        "routed_hop_ceiling_pkt_per_sec": 6100,
        "legacy_routed_hop_ceiling_pkt_per_sec": 45,
        "routed_hop_speedup_x": 135.0,
        "aps_tx_security_speedup_x": 75.5,
        "device_auth_speedup_x": 236.0,
        "nvm_key_read_speedup_x": 213.9,
        "idempotent_nvm_write_speedup_x": 26.7,
        "nvm_compaction_reduction_x": 14.7,
        "malloc_64_holes_cycles": 218,
        "malloc_speedup_x": 11.7,
        "timer_start_speedup_x": 6.9,
        "event_enqueue_speedup_x": 2.9,
        "sys_ping_cycle_reduction_pct": 53.0,
        "sys_ping_reply_cycle_reduction_pct": 83.0,
        "malformed_ota_crashes": 0,
        "replay_flood_1000_speedup_x": 92.8,
        "brownout_cut_points_verified": 22959,
        "brownout_reboot_flash_reduction_x": 749.3,
        "uart_abuse_lost_pings": 0,
        "join_flood_50_devices_speedup_x": 7.7,
        "broadcast_echo_storm_speedup_x": 20.3,
        "btt_capacity_slots": 40,
        "heap_fragmentation_pct": 0.0,
        "heap_delta_bytes": 0,
        "memory_allocator": (
            "Constant-time O(1) memory manager (218 cycles at 64 heap holes, 11.7x faster) & "
            "heap-independent timer subsystem (1,448 cycles, 6.9x faster)"
        ),
        "radio_state_reconciliation": (
            "Self-healing Sub-MAC receiver and synthesizer state recovery, indirect queue quota "
            "isolation (50% pool cap, max 2 frames/child), and 0 crashes across 3,255 MAC vectors"
        ),
        "zeroStackDiagUrl": (
            f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-no-ack-0xe9-sleepy-aqara-tuya-child-drops.md"
        ),
    }


BENCHMARK_DATA: dict[str, PlatformBenchmarkSummary] = {
    "SLZB-06": _build_platform_benchmark(
        platform="SLZB-06",
        soc="TI CC2652P (SimpleLink F2)",
        cpu_core="ARM Cortex-M4F @ 48.0 MHz + Cortex-M0 RF Core",
        flash_kb=352,
        sram_kb=88,
        hardware_rts_cts=False,
        rts_cts_pins="None (no hardware RTS/CTS)",
        max_source_routes=200,
    ),
    "SLZB-06U": _build_platform_benchmark(
        platform="SLZB-06U",
        soc="TI CC2652P (SimpleLink F2)",
        cpu_core="ARM Cortex-M4F @ 48.0 MHz + Cortex-M0 RF Core",
        flash_kb=352,
        sram_kb=88,
        hardware_rts_cts=True,
        rts_cts_pins="DIO10 (RTS) / DIO11 (CTS)",
        max_source_routes=200,
    ),
    "SLZB-06P7": _build_platform_benchmark(
        platform="SLZB-06P7",
        soc="TI CC2652P7 / CC1352P7 (SimpleLink F2)",
        cpu_core="ARM Cortex-M4F @ 48.0 MHz + Cortex-M0 RF Core",
        flash_kb=704,
        sram_kb=144,
        hardware_rts_cts=True,
        rts_cts_pins="DIO10 (RTS) / DIO11 (CTS)",
        max_source_routes=250,
    ),
    "SLZB-06P7U": _build_platform_benchmark(
        platform="SLZB-06P7U",
        soc="TI CC2652P7 / CC1352P7 (SimpleLink F2)",
        cpu_core="ARM Cortex-M4F @ 48.0 MHz + Cortex-M0 RF Core",
        flash_kb=704,
        sram_kb=144,
        hardware_rts_cts=True,
        rts_cts_pins="DIO10 (RTS) / DIO11 (CTS)",
        max_source_routes=250,
    ),
    "SLZB-06P7V1": _build_platform_benchmark(
        platform="SLZB-06P7V1",
        soc="TI CC2652P7 / CC1352P7 (SimpleLink F2)",
        cpu_core="ARM Cortex-M4F @ 48.0 MHz + Cortex-M0 RF Core",
        flash_kb=704,
        sram_kb=144,
        hardware_rts_cts=False,
        rts_cts_pins="None (no hardware RTS/CTS on v1 PCB)",
        max_source_routes=250,
    ),
    "SLZB-07P7": _build_platform_benchmark(
        platform="SLZB-07P7",
        soc="TI CC2652P7 (SimpleLink F2)",
        cpu_core="ARM Cortex-M4F @ 48.0 MHz + Cortex-M0 RF Core",
        flash_kb=704,
        sram_kb=144,
        hardware_rts_cts=False,
        rts_cts_pins="None (USB dongle without hardware RTS/CTS)",
        max_source_routes=250,
    ),
    "SLZB-06P10": _build_platform_benchmark(
        platform="SLZB-06P10",
        soc="TI CC2674P10 (SimpleLink F2)",
        cpu_core="ARM Cortex-M33 @ 48.0 MHz + Cortex-M0 RF Core",
        flash_kb=1024,
        sram_kb=256,
        hardware_rts_cts=True,
        rts_cts_pins="DIO10 (RTS) / DIO11 (CTS)",
        max_source_routes=300,
    ),
    "SLZB-07P10": _build_platform_benchmark(
        platform="SLZB-07P10",
        soc="TI CC2674P10 (SimpleLink F2)",
        cpu_core="ARM Cortex-M33 @ 48.0 MHz + Cortex-M0 RF Core",
        flash_kb=1024,
        sram_kb=256,
        hardware_rts_cts=False,
        rts_cts_pins="None (USB dongle without hardware RTS/CTS)",
        max_source_routes=300,
    ),
}


def normalize_platform_key(platform: str) -> PlatformKeyLiteral | Literal["ALL"]:
    norm = platform.strip().upper().replace("_", "-")
    compact = norm.replace("-", "")
    if norm in ("ALL", "*"):
        return "ALL"
    if "06P7U" in compact:
        return "SLZB-06P7U"
    if "06P7V1" in compact:
        return "SLZB-06P7V1"
    if "07P7" in compact:
        return "SLZB-07P7"
    if "07P10" in compact:
        return "SLZB-07P10"
    if "06U" in compact:
        return "SLZB-06U"
    if "06P10" in compact or "2674" in compact or compact == "P10":
        return "SLZB-06P10"
    if "06P7" in compact or "1352" in compact or "2652P7" in compact or compact == "P7":
        return "SLZB-06P7"
    if "SLZB06" in compact or "2652" in compact:
        return "SLZB-06"
    raise ValueError(
        f"Unknown platform '{platform}'. Supported platforms: SLZB-06, SLZB-06U (CC2652P), "
        "SLZB-06P7, SLZB-06P7U, SLZB-06P7v1, SLZB-07P7 (CC2652P7 / CC1352P7), "
        "SLZB-06P10, SLZB-07P10 (CC2674P10), or 'all'."
    )


def get_zerostack_benchmarks_impl(platform: str) -> BenchmarkResult:
    """Core implementation for `get_zerostack_benchmarks`."""
    key = normalize_platform_key(platform)
    if key == "ALL":
        all_result: AllPlatformsBenchmarkResult = {
            "requested_platform": "all",
            "release": ZEROSTACK_RELEASE_NAME,
            "version": ZEROSTACK_FIRMWARE_VERSION,
            "marketing_url": ZEROSTACK_MARKETING_URL,
            "platforms": BENCHMARK_DATA,
            "part1_execution_latency": PART1_EXECUTION_BENCHMARKS,
            "part2_resilience_fault_injection": PART2_RESILIENCE_BENCHMARKS,
            "zeroStackDiagUrl": (
                f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-no-ack-0xe9-sleepy-aqara-tuya-child-drops.md"
            ),
            "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
            "zerostack_repository": ZEROSTACK_REPO_URL,
        }
        return all_result

    metrics = BENCHMARK_DATA[key]
    single_result: SinglePlatformBenchmarkResult = {
        **metrics,
        "requested_platform": key,
        "release": ZEROSTACK_RELEASE_NAME,
        "version": ZEROSTACK_FIRMWARE_VERSION,
        "part1_execution_latency": PART1_EXECUTION_BENCHMARKS,
        "part2_resilience_fault_injection": PART2_RESILIENCE_BENCHMARKS,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }
    return single_result


def build_supported_models_manifest() -> SupportedModelsManifest:
    """Build structured hardware matrix for `zerostack://hardware/supported-models`."""
    return {
        "release": ZEROSTACK_RELEASE_NAME,
        "version": ZEROSTACK_FIRMWARE_VERSION,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "firmware_roles": [
            "Coordinator (TI ZNP / MT)",
            "Router (Zigbee 3.0 / PRO R23)",
        ],
        "supported_baud_rates": [115200, 460800, 1000000],
        "models": {
            key: {
                "soc": val["soc"],
                "sram_kb": val["sram_kb"],
                "flash_kb": val["flash_kb"],
                "hardware_rts_cts": val["hardware_rts_cts"],
                "rts_cts_pins": val["rts_cts_pins"],
                "max_source_routes": val["max_source_routes"],
                "hw_srcmatch_short_slots": val["hw_srcmatch_short_slots"],
                "indirect_queue_pool_cap_pct": val["indirect_queue_pool_cap_pct"],
                "max_indirect_frames_per_child": val["max_indirect_frames_per_child"],
            }
            for key, val in BENCHMARK_DATA.items()
        },
    }
