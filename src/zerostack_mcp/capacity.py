# Copyright (c) 2026 SMLIGHT
# SPDX-License-Identifier: Apache-2.0

"""Coordinator hardware SrcMatch, indirect poll quota, and SRAM headroom calculator."""

from __future__ import annotations

from zerostack_mcp.models import (
    ZEROSTACK_DIAGNOSTICS_BASE,
    ZEROSTACK_MARKETING_URL,
    ZEROSTACK_RELEASE_NAME,
    ZEROSTACK_REPO_URL,
    ZEROSTACK_WEB_ANALYZER_URL,
    CoordinatorCapacityResult,
)
from zerostack_mcp.registers import normalize_chip_family


def check_coordinator_capacity_impl(
    device_count: int,
    sleepy_zed_count: int,
    chip_family: str,
) -> CoordinatorCapacityResult:
    """Core implementation for `check_coordinator_capacity`."""
    if device_count < 0 or sleepy_zed_count < 0:
        raise ValueError("device_count and sleepy_zed_count must be non-negative integers.")
    if sleepy_zed_count > device_count:
        raise ValueError("sleepy_zed_count cannot exceed total device_count.")

    family = normalize_chip_family(chip_family)
    chip_upper = chip_family.strip().upper().replace("-", "").replace("_", "")

    if family == "SILABS_EFR32":
        is_mg24 = "MG24" in chip_upper
        sram_kb = 256 if is_mg24 else 96
        max_slots = 64 if is_mg24 else 32
        model_name = (
            "Silicon Labs EFR32MG24 (EmberZNet NCP)"
            if is_mg24
            else "Silicon Labs EFR32MG21 (EmberZNet NCP)"
        )
        diag_slug = "znp-0x10-mem-error-0x11-buffer-full-0xc7-nwk-table-full.md"
        diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/{diag_slug}"
        return {
            "coordinator_platform": model_name,
            "chip_family": "SILABS_EFR32",
            "release": ZEROSTACK_RELEASE_NAME,
            "device_count": device_count,
            "sleepy_zed_count": sleepy_zed_count,
            "router_count": device_count - sleepy_zed_count,
            "zerostack_support_status": (
                f"SMLIGHT ZeroStack {ZEROSTACK_RELEASE_NAME} currently ships on SMLIGHT TI "
                "SimpleLink F2 coordinators (SLZB-06, SLZB-06U, SLZB-06P7, SLZB-06P7U, "
                "SLZB-06P7v1, SLZB-07P7, SLZB-06P10, SLZB-07P10). EFR32 support is in active "
                f"development ({ZEROSTACK_MARKETING_URL})."
            ),
            "srcmatch_hardware_table": {
                "max_short_slots": max_slots,
                "max_ext_slots": max_slots,
                "short_slots_used": min(sleepy_zed_count, max_slots),
                "short_slots_free": max(0, max_slots - sleepy_zed_count),
                "pend_all_active": sleepy_zed_count > max_slots,
            },
            "pend_all_behavior": {
                "stock_firmware": (
                    "EmberZNet manages sleepy children via EMBER_CHILD_TABLE_SIZE and finite "
                    "packet buffers (emFreeBufferCount); unicast or broadcast bursts under slow "
                    "ACKs can trigger 0x72 (EMBER_MAX_MESSAGE_LIMIT_REACHED) or "
                    "0xA1 (EMBER_NETWORK_BUSY)."
                ),
                "zerostack": (
                    f"ZeroStack {ZEROSTACK_RELEASE_NAME} currently targets SMLIGHT TI SimpleLink "
                    "F2 coordinators (EFR32 support in active development)."
                ),
            },
            "ram_heap_headroom": {
                "total_sram_kb": sram_kb,
                "stock_allocator": "EmberZNet fixed packet buffer pool (emFreeBufferCount)",
                "zerostack_allocator": (
                    f"ZeroStack {ZEROSTACK_RELEASE_NAME} O(1) 218-cycle memory manager is "
                    "currently available on SMLIGHT TI SimpleLink F2 models; EFR32 support is "
                    "in active development."
                ),
                "stock_status": (
                    "HIGH_BUFFER_PRESSURE_0X72_0XA1"
                    if device_count > 100 or sleepy_zed_count > 32
                    else "WITHIN_STOCK_LIMITS"
                ),
                "zerostack_status": "EFR32_IN_DEVELOPMENT_TI_F2_AVAILABLE",
            },
            "zeroStackDiagUrl": diag_url,
            "documentation_url": diag_url,
            "marketing_url": ZEROSTACK_MARKETING_URL,
            "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
            "zerostack_repository": ZEROSTACK_REPO_URL,
        }

    hw_short_slots = 32
    hw_ext_slots = 32
    hw_mixed_short_slots = 32
    indirect_pool_cap_pct = 50
    max_queued_per_child = 2

    if "2674" in chip_upper or "P10" in chip_upper:
        sram_kb = 256
        flash_kb = 1024
        max_routes = 300
        model_name = (
            "SLZB-07P10 (TI CC2674P10 SimpleLink F2)"
            if "07P10" in chip_upper
            else "SLZB-06P10 (TI CC2674P10 SimpleLink F2)"
        )
    elif "2652P7" in chip_upper or "1352" in chip_upper or "P7" in chip_upper:
        sram_kb = 144
        flash_kb = 704
        max_routes = 250
        if "07P7" in chip_upper:
            model_name = "SLZB-07P7 (TI CC2652P7 SimpleLink F2)"
        elif "P7U" in chip_upper:
            model_name = "SLZB-06P7U (TI CC2652P7 / CC1352P7 SimpleLink F2)"
        elif "P7V1" in chip_upper:
            model_name = "SLZB-06P7v1 (TI CC2652P7 / CC1352P7 SimpleLink F2)"
        else:
            model_name = "SLZB-06P7 (TI CC2652P7 / CC1352P7 SimpleLink F2)"
    else:
        sram_kb = 88
        flash_kb = 352
        max_routes = 200
        model_name = (
            "SLZB-06U (TI CC2652P SimpleLink F2)"
            if "06U" in chip_upper
            else "SLZB-06 (TI CC2652P SimpleLink F2)"
        )

    short_slots_used = min(sleepy_zed_count, hw_short_slots)
    short_slots_free = max(0, hw_short_slots - sleepy_zed_count)
    slot_utilization_pct = round((sleepy_zed_count / hw_short_slots) * 100.0, 1)
    pend_all_active = sleepy_zed_count > hw_short_slots

    if sleepy_zed_count > 32:
        stock_status = "CRITICAL_SLEEPY_DROPS_0XE9"
        stock_behavior = (
            f"At {sleepy_zed_count} direct sleepy ZEDs (>32 F2 RFC_RAM hardware SrcMatch slots), "
            "stock Z-Stack promotes to pendAll mode while suffering 11.11 ms per-frame flash "
            "security stalls that miss ZED RX poll windows (0xe9: MAC_NO_ACK) and letting "
            "sleeping children hoard nearly 100% of the nwkDB buffer pool (0x11: BUFFER_FULL)."
        )
        diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-no-ack-0xe9-sleepy-aqara-tuya-child-drops.md"
    elif device_count > 100:
        stock_status = "HIGH_HEAP_FRAGMENTATION_RISK_0X10"
        stock_behavior = (
            f"At {device_count} total nodes, stock first-fit O(N) OSAL_Memory heap (2,550 cycles "
            "at 64 holes) is prone to external fragmentation cliffs (0x10: MEM_ERROR) and 22.19 ms "
            "per-hop flash security stalls (~45 routed pkt/s ceiling)."
        )
        diag_slug = "znp-0x10-mem-error-0x11-buffer-full-0xc7-nwk-table-full.md"
        diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/{diag_slug}"
    else:
        stock_status = "WITHIN_STOCK_LIMITS"
        stock_behavior = (
            f"{sleepy_zed_count} sleepy ZEDs fit within the 32-slot hardware SrcMatch table, "
            "though O(N) OSAL heap fragmentation, unisolated indirect buffer hoarding, and "
            "O(N*P) flash security walks remain a long-uptime risk."
        )
        diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-no-ack-0xe9-sleepy-aqara-tuya-child-drops.md"

    if not pend_all_active:
        zerostack_pend_all_behavior = (
            f"EXACT_HARDWARE_SRCMATCH ({short_slots_used}/{hw_short_slots} short slots occupied): "
            "Matched in the F2 Cortex-M0 CPE 32-slot RFC_RAM hardware table; ZeroStack eliminates "
            "flash-read stalls during sleepy poll windows (82.7 us NWK encrypt, 0 flash reads) "
            "and enforces indirect queue quota isolation (50% pool cap, max 2 frames/child)."
        )
    else:
        zerostack_pend_all_behavior = (
            f"PENDALL_WITH_QUOTA_ISOLATION ({sleepy_zed_count} sleepy ZEDs > "
            f"{hw_short_slots} HW slots): ZeroStack pairs the F2 hardware SrcMatch table with "
            "strict indirect queue quota isolation (50% pool cap, max 2 queued frames per "
            "sleeping child) and zero flash-read stalls during sleepy poll windows (82.7 us NWK "
            "encrypt, 6.8 us TCLK lookup, 0 flash reads); recommend routing excess sleepy ZEDs "
            "through mains-powered Zigbee routers."
        )

    return {
        "coordinator_platform": model_name,
        "chip_family": "F2_CC1352_CC2652",
        "release": ZEROSTACK_RELEASE_NAME,
        "device_count": device_count,
        "sleepy_zed_count": sleepy_zed_count,
        "router_count": device_count - sleepy_zed_count,
        "srcmatch_hardware_table": {
            "max_short_slots": hw_short_slots,
            "max_ext_slots": hw_ext_slots,
            "max_mixed_short_slots": hw_mixed_short_slots,
            "short_slots_used": short_slots_used,
            "short_slots_free": short_slots_free,
            "utilization_pct": slot_utilization_pct,
            "pend_all_threshold": hw_short_slots + 1,
            "pend_all_active": pend_all_active,
        },
        "pend_all_behavior": {
            "stock_firmware": stock_behavior,
            "zerostack": zerostack_pend_all_behavior,
        },
        "ram_heap_headroom": {
            "total_sram_kb": sram_kb,
            "total_flash_kb": flash_kb,
            "stock_allocator": (
                "First-fit O(N) variable-block OSAL_Memory (2,550 cycles at 64 holes; prone to "
                "0x10: MEM_ERROR fragmentation)"
            ),
            "zerostack_allocator": (
                f"Constant-time O(1) memory manager (218 cycles at 64 holes, 11.7x faster, "
                f"Delta-heap = 0 B across {sram_kb} KB SRAM, {max_routes}+ source routes)"
            ),
            "stock_status": stock_status,
            "zerostack_status": "HEALTHY_DETERMINISTIC",
            "indirect_queue_pool_cap_pct": indirect_pool_cap_pct,
            "max_indirect_frames_per_child": max_queued_per_child,
        },
        "zeroStackDiagUrl": diag_url,
        "documentation_url": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }
