# Copyright (c) 2026 SMLIGHT
# SPDX-License-Identifier: Apache-2.0

"""Hardware register decoders for TI SimpleLink F2 and Silicon Labs EFR32 radios."""

from __future__ import annotations

from zerostack_mcp.models import (
    F2_SILICON_NOTE_URL,
    ZEROSTACK_DIAGNOSTICS_BASE,
    ZEROSTACK_MARKETING_URL,
    ZEROSTACK_RELEASE_NAME,
    ZEROSTACK_REPO_URL,
    ZEROSTACK_WEB_ANALYZER_URL,
    ChipFamilyLiteral,
    RegisterDecodeResult,
)

F2_CMD_IEEE_RX_STATUS_MAP: dict[int, tuple[str, bool, str]] = {
    0x0000: ("IDLE", False, "Command structure is idle (not yet submitted to RF Core)."),
    0x0001: ("PENDING", True, "Command is queued on RF Core waiting for trigger."),
    0x0002: (
        "ACTIVE",
        True,
        "HEALTHY: Background CMD_IEEE_RX is actively listening on the 802.15.4 channel.",
    ),
    0x0400: (
        "DONE_OK",
        True,
        (
            "Command completed normally (DONE_OK). Ensure background RX is re-armed if "
            "rxOnWhenIdle is true."
        ),
    ),
    0x0807: (
        "DONE_ABORT",
        False,
        (
            "FAULT (DONE_ABORT = 0x0807): Background receiver was aborted by an ED scan, "
            "channel change, or synth recalibration and was not re-armed, causing 0xe1: "
            "MAC_CHANNEL_ACCESS_FAILURE. SMLIGHT ZeroStack (Release Zero 0.9.9-beta.1) enforces "
            "self-healing Sub-MAC receiver and synthesizer state recovery."
        ),
    ),
    0x2801: (
        "ERROR_PAR",
        False,
        (
            "FAULT (ERROR_PAR = 0x2801): Invalid IEEE 802.15.4 command parameter or corrupted "
            "SrcMatch pointer."
        ),
    ),
    0x2802: (
        "ERROR_RXBUF",
        False,
        (
            "FAULT (ERROR_RXBUF = 0x2802): RF Core circular rfc_dataEntry_t RX queue exhausted "
            "(DATA_ENTRY_UNFINISHED == 4 saturation)."
        ),
    ),
    0x2805: (
        "ERROR_FAILED_SYNTH",
        False,
        (
            "FAULT (ERROR_FAILED_SYNTH = 0x2805): Frequency synthesizer failed to lock during "
            "RX startup."
        ),
    ),
}


def parse_int_value(raw: str) -> int:
    cleaned = raw.strip().lower().replace("_", "")
    if cleaned.startswith("0x"):
        return int(cleaned, 16)
    if any(c in cleaned for c in "abcdef"):
        return int(cleaned, 16)
    return int(cleaned, 0)


def normalize_chip_family(chip: str) -> ChipFamilyLiteral:
    norm = chip.strip().upper().replace("-", "").replace("_", "")
    if any(k in norm for k in ("EFR32", "MG21", "MG24", "SILABS", "EMBER", "SLZB06M", "06M")):
        return "SILABS_EFR32"
    if norm in ("F2", "P7", "P10") or any(
        k in norm
        for k in (
            "CC1352",
            "CC2652",
            "CC2674",
            "CC26XX",
            "CC13XX",
            "SLZB06",
            "SLZB07",
        )
    ):
        return "F2_CC1352_CC2652"
    raise ValueError(
        f"Unsupported chip '{chip}'. Expected TI SimpleLink F2 (CC2652P / CC2652P7 / CC1352P7 / "
        "CC2674P10 across SLZB-06, SLZB-06U, SLZB-06P7, SLZB-06P7U, SLZB-06P7v1, SLZB-07P7, "
        "SLZB-06P10, SLZB-07P10) or Silicon Labs EFR32."
    )


def _decode_f2_cmd_ieee_rx(val: int) -> RegisterDecodeResult:
    status16 = val & 0xFFFF
    name, healthy, desc = F2_CMD_IEEE_RX_STATUS_MAP.get(
        status16,
        (
            f"UNKNOWN_STATUS_0x{status16:04X}",
            False,
            (
                f"Unhandled RF Core command status 0x{status16:04x}; background receiver is "
                "not ACTIVE (0x0002)."
            ),
        ),
    )
    diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-channel-access-failure-0xe1-cca-csma-stuck.md"
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "CMD_IEEE_RX",
        "address": "RF_cmdIEEERx.status",
        "raw_hex": f"0x{status16:04x}",
        "healthy": healthy,
        "bitfields": {
            "STATUS_CODE": f"0x{status16:04x}",
            "STATUS_NAME": name,
            "IS_ACTIVE (0x0002)": int(status16 == 0x0002),
            "IS_ERROR (Bit 13)": int(bool(status16 & 0x2000)),
        },
        "diagnosis": desc,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_f2_cmd_ieee_csma(val: int) -> RegisterDecodeResult:
    status16 = val & 0xFFFF
    healthy = status16 in (0x0001, 0x0002, 0x0400, 0x2400)
    busy_fail = status16 == 0x2401
    no_rx_error = bool(status16 & 0x2800)

    if busy_fail:
        diagnosis = (
            "CCA BUSY (IEEE_DONE_BUSY = 0x2401): CSMA/CA failed across all backoff slots "
            "(0xe1: MAC_CHANNEL_ACCESS_FAILURE). Check whether background CMD_IEEE_RX was aborted."
        )
    elif no_rx_error:
        diagnosis = (
            f"CSMA COMMAND ERROR (0x{status16:04x}): Foreground CMD_IEEE_CSMA rejected because "
            "background CMD_IEEE_RX is not running."
        )
    else:
        diagnosis = f"CMD_IEEE_CSMA status 0x{status16:04x} (healthy={healthy})."

    diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-channel-access-failure-0xe1-cca-csma-stuck.md"
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "CMD_IEEE_CSMA",
        "address": "RF_cmdIEEECsma.status",
        "raw_hex": f"0x{status16:04x}",
        "healthy": healthy and not busy_fail,
        "bitfields": {
            "STATUS_CODE": f"0x{status16:04x}",
            "IEEE_DONE_BUSY (0x2401)": int(busy_fail),
            "IS_ERROR (Bit 13)": int(bool(status16 & 0x2000)),
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_f2_rfc_dbell(val: int) -> RegisterDecodeResult:
    last_cmd_done = bool(val & 0x00000001)
    last_fg_cmd_done = bool(val & 0x00000002)
    fg_cmd_done = bool(val & 0x00000004)
    rx_ok = bool(val & (1 << 16))
    rx_buf_full = bool(val & (1 << 22))
    healthy = last_cmd_done and last_fg_cmd_done

    if healthy:
        diagnosis = (
            "HEALTHY: RFC_DBELL:RFCPEIEN has both LAST_CMD_DONE (Bit 0) and "
            "LAST_FG_CMD_DONE (Bit 1) interrupts armed."
        )
    else:
        diagnosis = (
            "RF INTERRUPT STRIPPED (RFC_DBELL:RFCPEIEN & 0x03 != 0x03): Background/Foreground "
            "CPE command-done interrupts were stripped during foreground command termination or "
            "RF_FsmEventLastCommandDone SWI race, stalling the Sub-MAC state machine."
        )

    diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-channel-access-failure-0xe1-cca-csma-stuck.md"
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "RFC_DBELL",
        "address": "0x40041014",
        "raw_hex": f"0x{val:08x}",
        "healthy": healthy,
        "bitfields": {
            "LAST_CMD_DONE (Bit 0)": int(last_cmd_done),
            "LAST_FG_CMD_DONE (Bit 1)": int(last_fg_cmd_done),
            "FG_CMD_DONE (Bit 2)": int(fg_cmd_done),
            "RX_OK (Bit 16)": int(rx_ok),
            "RX_BUF_FULL (Bit 22)": int(rx_buf_full),
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_f2_srcmatch(val: int) -> RegisterDecodeResult:
    mask32 = val & 0xFFFFFFFF
    active_slots = [idx for idx in range(32) if (mask32 & (1 << idx))]
    occupied_count = len(active_slots)
    exhausted = occupied_count >= 32

    if exhausted:
        diagnosis = (
            "SRCMATCH TABLE FULL (32/32 slots occupied, mask=0xffffffff): All 32 hardware "
            "short-address source-matching slots in the F2 Cortex-M0 CPE RFC_RAM table are "
            "occupied; beyond 32 direct sleepy ZEDs, the radio sets pendAll (FP=1 on all ACKs). "
            "On stock Z-Stack, 11.11 ms per-frame flash security stalls delay indirect frame "
            "dequeue past the ZED's RX poll window and sleeping ZEDs can hoard nearly 100% of "
            "the nwkDB buffer pool. SMLIGHT ZeroStack (Release Zero 0.9.9-beta.1) eliminates "
            "flash-read stalls during sleepy poll windows (82.7 us NWK encrypt, 0 flash reads) "
            "and enforces indirect queue quota isolation (50% pool cap, max 2 queued frames per "
            "sleeping child)."
        )
    else:
        diagnosis = (
            f"HEALTHY ({occupied_count}/32 hardware SrcMatch slots occupied, "
            f"{32 - occupied_count} slots free before pendAll promotion)."
        )

    diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-no-ack-0xe9-sleepy-aqara-tuya-child-drops.md"
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "SRCMATCH",
        "address": "RFC_RAM:srcMatchShortEntry",
        "raw_hex": f"0x{mask32:08x}",
        "healthy": not exhausted,
        "bitfields": {
            "OCCUPIED_SLOTS": occupied_count,
            "FREE_SLOTS": 32 - occupied_count,
            "TABLE_SATURATED_32_OF_32": int(exhausted),
            "ACTIVE_SLOT_INDICES": active_slots,
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_f2_vims_stat(val: int) -> RegisterDecodeResult:
    mode = val & 0x03
    inv = bool(val & 0x04)
    mode_changing = bool(val & 0x08)
    gpram_enabled = mode == 0x00
    cache_enabled = mode == 0x01

    diagnosis = (
        f"VIMS:STAT mode={mode} (CACHE_ENABLED={int(cache_enabled)}, "
        f"GPRAM_MODE={int(gpram_enabled)}, MODE_CHANGING={int(mode_changing)})."
    )
    diag_url = (
        f"{ZEROSTACK_DIAGNOSTICS_BASE}/znp-0x10-mem-error-0x11-buffer-full-0xc7-nwk-table-full.md"
    )
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "VIMS_STAT",
        "address": "0x40034000",
        "raw_hex": f"0x{val:08x}",
        "healthy": not mode_changing,
        "bitfields": {
            "MODE (Bits 1:0)": mode,
            "CACHE_ENABLED": int(cache_enabled),
            "GPRAM_ENABLED": int(gpram_enabled),
            "INV (Bit 2)": int(inv),
            "MODE_CHANGING (Bit 3)": int(mode_changing),
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_f2_prcm_rfcmodehwopt(val: int) -> RegisterDecodeResult:
    avail_modes = val & 0xFF
    ieee_supported = bool(avail_modes & 0x02)
    diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-channel-access-failure-0xe1-cca-csma-stuck.md"
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "PRCM_RFCMODEHWOPT",
        "address": "0x400821d0",
        "raw_hex": f"0x{val:08x}",
        "healthy": ieee_supported,
        "bitfields": {
            "AVAIL_MODES (Bits 7:0)": f"0x{avail_modes:02x}",
            "IEEE_802154_ENABLED (Bit 1)": int(ieee_supported),
        },
        "diagnosis": (
            "HEALTHY: PRCM_RFCMODEHWOPT confirms IEEE 802.15.4 CPE mode is enabled in hardware."
            if ieee_supported
            else "FAULT: IEEE 802.15.4 mode bit (Bit 1) is not enabled in PRCM_RFCMODEHWOPT."
        ),
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_efr32_eusart0(val: int) -> RegisterDecodeResult:
    txc = bool(val & 0x01)
    txfl = bool(val & 0x02)
    rxfl = bool(val & 0x04)
    rxof = bool(val & 0x08)
    rxuf = bool(val & 0x10)
    txof = bool(val & 0x20)
    ferr = bool(val & 0x40)
    healthy = not (rxof or txof or ferr)

    if rxof:
        diagnosis = (
            "UART RX FIFO OVERRUN (EUSART0:IF.RXOF Bit 3 = 1): Hardware EUSART0 receive FIFO "
            "overflowed while interrupts were masked, triggering ASH_NCP_FATAL_ERROR / "
            "EZSP_ERROR_OVERFLOW. Verify UART/Ethernet bridge stability and hardware RTS/CTS "
            "flow control. (Note: SMLIGHT ZeroStack Release Zero 0.9.9-beta.1 currently ships on "
            "SMLIGHT TI SimpleLink F2 coordinators with 0 lost pings across hostile UART framing "
            "storms; EFR32 ZeroStack support is in active development.)"
        )
    else:
        diagnosis = (
            f"HEALTHY: EUSART0:IF status 0x{val:08x} (RXOF=0, FERR=0). "
            "(Note: SMLIGHT ZeroStack Release Zero 0.9.9-beta.1 ships on SMLIGHT TI SimpleLink F2 "
            "coordinators; EFR32 support is in active development.)"
        )

    diag_url = (
        f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-zha-adapter-connect-sys-ping-timeout-warm-reset.md"
    )
    return {
        "chip": "Silicon Labs EFR32 (EFR32MG21 / EFR32MG24)",
        "register": "EUSART0_IF",
        "address": "EUSART0:IF",
        "raw_hex": f"0x{val:08x}",
        "healthy": healthy,
        "bitfields": {
            "TXC (Bit 0)": int(txc),
            "TXFL (Bit 1)": int(txfl),
            "RXFL (Bit 2)": int(rxfl),
            "RXOF (Bit 3)": int(rxof),
            "RXUF (Bit 4)": int(rxuf),
            "TXOF (Bit 5)": int(txof),
            "FERR (Bit 6)": int(ferr),
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "zero_stack_remediation": (
            "SMLIGHT ZeroStack Release Zero (0.9.9-beta.1) currently ships on SMLIGHT TI "
            "SimpleLink F2 coordinators (SLZB-06, SLZB-06U, SLZB-06P7, SLZB-06P7U, SLZB-06P7v1, "
            "SLZB-07P7, SLZB-06P10, SLZB-07P10), while EFR32 support is in active development. "
            f"See {ZEROSTACK_MARKETING_URL}"
        ),
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def decode_silicon_register_impl(
    chip: str,
    register_or_addr: str,
    hex_value: str,
) -> RegisterDecodeResult:
    """Core implementation for `decode_silicon_register`."""
    family = normalize_chip_family(chip)
    val = parse_int_value(hex_value)
    reg_norm = register_or_addr.strip().upper().replace(":", "_")

    if family == "SILABS_EFR32" or "EUSART" in reg_norm:
        return _decode_efr32_eusart0(val)

    if "CMD_IEEE_RX" in reg_norm or "IEEERX" in reg_norm or "RX_STATUS" in reg_norm:
        return _decode_f2_cmd_ieee_rx(val)
    if "CMD_IEEE_CSMA" in reg_norm or "IEEECSMA" in reg_norm or "CSMA" in reg_norm:
        return _decode_f2_cmd_ieee_csma(val)
    if (
        "RFC_DBELL" in reg_norm
        or "RFCPEIEN" in reg_norm
        or "40041014" in reg_norm
        or "40041" in reg_norm
    ):
        return _decode_f2_rfc_dbell(val)
    if (
        "SRCMATCH" in reg_norm
        or "SRC_MATCH" in reg_norm
        or "RFC_RAM" in reg_norm
        or "20001060" in reg_norm
    ):
        return _decode_f2_srcmatch(val)
    if "VIMS" in reg_norm or "40034000" in reg_norm:
        return _decode_f2_vims_stat(val)
    if "PRCM" in reg_norm or "400821D0" in reg_norm:
        return _decode_f2_prcm_rfcmodehwopt(val)

    raise ValueError(
        f"Unknown SimpleLink F2 register '{register_or_addr}'. Supported F2 registers: "
        "CMD_IEEE_RX, CMD_IEEE_CSMA, RFC_DBELL (0x40041014), RFC_RAM/SrcMatch, VIMS, PRCM."
    )
