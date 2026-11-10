# Copyright (c) 2026 SMLIGHT
# SPDX-License-Identifier: Apache-2.0

"""Hardware register decoders for TI SimpleLink F2, Silicon Labs EFR32, and ARM Cortex-M."""

from __future__ import annotations

import re
from typing import Literal

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

RegisterChipFamily = Literal["F2_CC1352_CC2652", "SILABS_EFR32", "ARM_CORTEX_M"]

F2_IOC_PORT_MAP: dict[int, str] = {
    0x00: "GPIO",
    0x07: "AON_CLK32K",
    0x08: "AUX_IO",
    0x09: "SSI0_RX",
    0x0A: "SSI0_TX",
    0x0B: "SSI0_FSS",
    0x0C: "SSI0_CLK",
    0x0D: "I2C_MSSDA",
    0x0E: "I2C_MSSCL",
    0x0F: "UART0_RX",
    0x10: "UART0_TX",
    0x11: "UART0_CTS",
    0x12: "UART0_RTS",
    0x13: "UART1_RX",
    0x14: "UART1_TX",
    0x15: "UART1_CTS",
    0x16: "UART1_RTS",
    0x20: "CPU_SWV",
    0x2E: "RFC_TRC",
    0x2F: "RFC_GPO0",
    0x30: "RFC_GPO1",
    0x31: "RFC_GPO2",
    0x32: "RFC_GPO3",
    0x33: "RFC_GPI0",
    0x34: "RFC_GPI1",
    0x39: "SPI2_RX",
    0x3A: "SPI2_TX",
    0x3B: "SPI2_CS",
    0x3C: "SPI2_CLK",
    0x3D: "SPI3_RX",
    0x3E: "SPI3_TX",
    0x3F: "SPI3_CS",
    0x40: "SPI3_CLK",
    0x41: "UART2_RX",
    0x42: "UART2_TX",
    0x43: "UART2_CTS",
    0x44: "UART2_RTS",
    0x45: "UART3_RX",
    0x46: "UART3_TX",
    0x47: "UART3_CTS",
    0x48: "UART3_RTS",
    0x49: "I2C1_MSSDA",
    0x4A: "I2C1_MSSCL",
}

F2_IOC_PULL_MAP: dict[int, str] = {
    0: "RESERVED_0",
    1: "PULL_DOWN",
    2: "PULL_UP",
    3: "NO_PULL",
}

F2_RESET_SRC_MAP: dict[int, tuple[str, bool, str]] = {
    0: ("PWR_ON", True, "Clean Power-On Reset (POR)."),
    1: ("PIN_RESET", True, "External hardware reset pin assertion."),
    2: (
        "VDDS_LOSS",
        False,
        "BROWNOUT FAULT (VDDS_LOSS = 2): External 3.3V VDDS supply dropped below BOD threshold.",
    ),
    3: (
        "VDD_LOSS",
        False,
        "BROWNOUT FAULT (VDD_LOSS = 3): Internal digital core VDD rail drooped.",
    ),
    4: (
        "VDDR_LOSS",
        False,
        (
            "BROWNOUT FAULT (VDDR_LOSS = 4): Regulated VDDR rail drooped during high-current PA "
            "TX burst or DCDC recharge pulse."
        ),
    ),
    5: (
        "CLK_LOSS",
        False,
        "CLOCK LOSS FAULT (CLK_LOSS = 5): SCLK_LF / SCLK_HF crystal oscillator clock loss.",
    ),
    6: ("SYSRESET", True, "Software-initiated cold system reset (SYSRESET)."),
    7: (
        "WARMRESET",
        False,
        (
            "UNEXPECTED WARM RESET (WARMRESET = 7): Watchdog timeout, Cortex-M SYSRESETREQ "
            "converted to warm reset, or unrecovered assert caused AREQ - SYS - resetInd."
        ),
    ),
}

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
    0x0404: (
        "DONE_STOPPED",
        False,
        "Background CMD_IEEE_RX stopped via CMD_STOP.",
    ),
    0x0405: (
        "DONE_ABORT",
        False,
        (
            "FAULT (DONE_ABORT = 0x0405): Background receiver was aborted via CMD_ABORT or "
            "channel switch and was not re-armed, causing 0xe1: MAC_CHANNEL_ACCESS_FAILURE. "
            "SMLIGHT ZeroStack (Release Zero 0.9.9-beta.1) enforces self-healing Sub-MAC "
            "receiver and synthesizer state recovery."
        ),
    ),
    0x0807: (
        "ERROR_NO_SETUP",
        False,
        (
            "FAULT (ERROR_NO_SETUP = 0x0807 / legacy DONE_ABORT): Radio operation command "
            "rejected because CMD_RADIO_SETUP was not executed or background RX aborted after "
            "an ED scan / synth recalibration without re-arming, causing 0xe1: "
            "MAC_CHANNEL_ACCESS_FAILURE. SMLIGHT ZeroStack (Release Zero 0.9.9-beta.1) enforces "
            "self-healing Sub-MAC receiver and synthesizer state recovery."
        ),
    ),
    0x0808: (
        "ERROR_NO_FS",
        False,
        "FAULT (ERROR_NO_FS = 0x0808): Command requires frequency synthesizer, but FS is off.",
    ),
    0x0809: (
        "ERROR_SYNTH_PROG",
        False,
        "FAULT (ERROR_SYNTH_PROG = 0x0809): Synthesizer programming failed during startup.",
    ),
    0x080B: (
        "ERROR_RXOVF",
        False,
        "FAULT (ERROR_RXOVF = 0x080B): RF Core receiver overflowed during operation.",
    ),
    0x2400: (
        "IEEE_DONE_OK",
        True,
        "IEEE 802.15.4 operation ended normally.",
    ),
    0x2402: (
        "IEEE_DONE_STOPPED",
        False,
        "FAULT (IEEE_DONE_STOPPED = 0x2402): IEEE 802.15.4 background RX stopped.",
    ),
    0x2407: (
        "IEEE_DONE_ABORT",
        False,
        (
            "FAULT (IEEE_DONE_ABORT = 0x2407): IEEE 802.15.4 background operation aborted by "
            "command or channel switch without re-arming, causing 0xe1: "
            "MAC_CHANNEL_ACCESS_FAILURE. SMLIGHT ZeroStack (Release Zero 0.9.9-beta.1) enforces "
            "self-healing Sub-MAC receiver and synthesizer state recovery."
        ),
    ),
    0x2800: (
        "IEEE_ERROR_PAR",
        False,
        (
            "FAULT (IEEE_ERROR_PAR = 0x2800): Illegal IEEE 802.15.4 command parameter or "
            "corrupted SrcMatch pointer."
        ),
    ),
    0x2801: (
        "IEEE_ERROR_NO_SETUP",
        False,
        (
            "FAULT (IEEE_ERROR_NO_SETUP = 0x2801): Radio was not set up in IEEE 802.15.4 "
            "compatible mode."
        ),
    ),
    0x2802: (
        "IEEE_ERROR_NO_FS",
        False,
        (
            "FAULT (IEEE_ERROR_NO_FS = 0x2802): Synth was not programmed or foreground command "
            "submitted without active background CMD_IEEE_RX."
        ),
    ),
    0x2803: (
        "IEEE_ERROR_SYNTH_PROG",
        False,
        (
            "FAULT (IEEE_ERROR_SYNTH_PROG = 0x2803): Synthesizer programming failed during "
            "IEEE 802.15.4 operation."
        ),
    ),
    0x2804: (
        "IEEE_ERROR_RXOVF",
        False,
        (
            "FAULT (IEEE_ERROR_RXOVF = 0x2804): RF Core circular rfc_dataEntry_t RX queue "
            "overflowed (DATA_ENTRY_UNFINISHED == 4 saturation)."
        ),
    ),
    0x2805: (
        "IEEE_ERROR_TXUNF",
        False,
        "FAULT (IEEE_ERROR_TXUNF = 0x2805): IEEE 802.15.4 transmitter underflowed.",
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
    cmd_done = bool(val & (1 << 0))
    last_cmd_done = bool(val & (1 << 1))
    fg_cmd_done = bool(val & (1 << 2))
    last_fg_cmd_done = bool(val & (1 << 3))
    tx_done = bool(val & (1 << 4))
    tx_ack = bool(val & (1 << 5))
    rx_ok = bool(val & (1 << 16))
    rx_buf_full = bool(val & (1 << 22))
    rx_aborted = bool(val & (1 << 26))
    synth_no_lock = bool(val & (1 << 28))
    internal_error = bool(val & (1 << 31))
    healthy = last_cmd_done and last_fg_cmd_done

    if healthy:
        diagnosis = (
            "HEALTHY: RFC_DBELL:RFCPEIEN has both LAST_COMMAND_DONE (Bit 1) and "
            "LAST_FG_COMMAND_DONE (Bit 3) interrupts armed."
        )
    else:
        diagnosis = (
            "RF INTERRUPT STRIPPED (RFC_DBELL:RFCPEIEN & 0x0A != 0x0A): Background/Foreground "
            "CPE command-done interrupts (LAST_COMMAND_DONE Bit 1, LAST_FG_COMMAND_DONE Bit 3) "
            "were stripped during foreground command termination or RF_FsmEventLastCommandDone "
            "SWI race, stalling the Sub-MAC state machine."
        )

    diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-channel-access-failure-0xe1-cca-csma-stuck.md"
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "RFC_DBELL",
        "address": "0x40041014",
        "raw_hex": f"0x{val:08x}",
        "healthy": healthy,
        "bitfields": {
            "COMMAND_DONE (Bit 0)": int(cmd_done),
            "LAST_COMMAND_DONE (Bit 1)": int(last_cmd_done),
            "FG_COMMAND_DONE (Bit 2)": int(fg_cmd_done),
            "LAST_FG_COMMAND_DONE (Bit 3)": int(last_fg_cmd_done),
            "TX_DONE (Bit 4)": int(tx_done),
            "TX_ACK (Bit 5)": int(tx_ack),
            "RX_OK (Bit 16)": int(rx_ok),
            "RX_BUF_FULL (Bit 22)": int(rx_buf_full),
            "RX_ABORTED (Bit 26)": int(rx_aborted),
            "SYNTH_NO_LOCK (Bit 28)": int(synth_no_lock),
            "INTERNAL_ERROR (Bit 31)": int(internal_error),
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


def _is_f2_cc26x4(chip_raw: str) -> bool:
    return any(k in chip_raw.upper() for k in ("2674", "1354", "26X4", "13X4", "P10"))


def _decode_f2_vims_stat(val: int) -> RegisterDecodeResult:
    mode = val & 0x03
    inv = bool(val & (1 << 2))
    mode_changing = bool(val & (1 << 3))
    sysbus_lb_dis = bool(val & (1 << 4))
    idcode_lb_dis = bool(val & (1 << 5))
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
            "SYSBUS_LB_DIS (Bit 4)": int(sysbus_lb_dis),
            "IDCODE_LB_DIS (Bit 5)": int(idcode_lb_dis),
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_f2_prcm_rfcmodehwopt(
    val: int, chip_raw: str = "", reg_raw: str = ""
) -> RegisterDecodeResult:
    avail_modes = val & 0xFF
    ieee_supported = bool(avail_modes & 0x02)
    reg_upper = reg_raw.upper()
    if "480821D" in reg_upper:
        addr_hex = "0x480821d4"
    elif "580821D" in reg_upper or _is_f2_cc26x4(chip_raw):
        addr_hex = "0x580821d4"
    else:
        addr_hex = "0x400821d4"
    diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/mac-channel-access-failure-0xe1-cca-csma-stuck.md"
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "PRCM_RFCMODEHWOPT",
        "address": addr_hex,
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


def _decode_efr32_eusart0(val: int, reg_raw: str = "") -> RegisterDecodeResult:
    word32 = val & 0xFFFFFFFF
    txc = bool(word32 & (1 << 0))
    txfl = bool(word32 & (1 << 1))
    rxfl = bool(word32 & (1 << 2))
    rxfull = bool(word32 & (1 << 3))
    rxof = bool(word32 & (1 << 4))
    rxuf = bool(word32 & (1 << 5))
    txof = bool(word32 & (1 << 6))
    txuf = bool(word32 & (1 << 7))
    perr = bool(word32 & (1 << 8))
    ferr = bool(word32 & (1 << 9))
    healthy = not (rxof or rxuf or txof or txuf or perr or ferr)
    addr_hex = "0x4b01004c" if "4B01004C" in reg_raw.upper() else "0x5b01004c"

    if rxof:
        diagnosis = (
            "UART RX FIFO OVERRUN (EUSART0:IF.RXOF Bit 4 = 1): Hardware EUSART0 receive FIFO "
            "overflowed while interrupts were masked, triggering ASH_NCP_FATAL_ERROR / "
            "EZSP_ERROR_OVERFLOW. Verify UART/Ethernet bridge stability and hardware RTS/CTS "
            "flow control. (Note: SMLIGHT ZeroStack Release Zero 0.9.9-beta.1 currently ships on "
            "SMLIGHT TI SimpleLink F2 coordinators with 0 lost pings across hostile UART framing "
            "storms; EFR32 ZeroStack support is in active development.)"
        )
    elif not healthy:
        diagnosis = (
            f"EUSART0 INTERRUPT FAULT (EUSART0:IF = 0x{word32:08x}; FERR={int(ferr)}, "
            f"PERR={int(perr)}, TXOF={int(txof)}, RXUF={int(rxuf)}, TXUF={int(txuf)}): Hardware "
            "EUSART0 encountered an ASHv2 serial framing or FIFO error."
        )
    else:
        diagnosis = (
            f"HEALTHY: EUSART0:IF status 0x{word32:08x} (RXOF=0, FERR=0, PERR=0). "
            "(Note: SMLIGHT ZeroStack Release Zero 0.9.9-beta.1 ships on SMLIGHT TI SimpleLink F2 "
            "coordinators; EFR32 support is in active development.)"
        )

    diag_url = (
        f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-zha-adapter-connect-sys-ping-timeout-warm-reset.md"
    )
    return {
        "chip": "Silicon Labs EFR32 (EFR32MG24 EUSART0)",
        "register": "EUSART0_IF",
        "address": addr_hex,
        "raw_hex": f"0x{word32:08x}",
        "healthy": healthy,
        "bitfields": {
            "TXC (Bit 0)": int(txc),
            "TXFL (Bit 1)": int(txfl),
            "RXFL (Bit 2)": int(rxfl),
            "RXFULL (Bit 3)": int(rxfull),
            "RXOF (Bit 4)": int(rxof),
            "RXUF (Bit 5)": int(rxuf),
            "TXOF (Bit 6)": int(txof),
            "TXUF (Bit 7)": int(txuf),
            "PERR (Bit 8)": int(perr),
            "FERR (Bit 9)": int(ferr),
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


def _normalize_register_chip(chip: str) -> RegisterChipFamily:
    norm = chip.strip().upper().replace("-", "").replace("_", "")
    if norm in (
        "ARM",
        "CORTEXM",
        "CORTEXM4",
        "CORTEXM4F",
        "CORTEXM33",
        "ARMV7M",
        "ARMV8M",
        "SCB",
    ):
        return "ARM_CORTEX_M"
    return normalize_chip_family(chip)


def _decode_f2_uart0_fr(val: int) -> RegisterDecodeResult:
    word32 = val & 0xFFFFFFFF
    cts = bool(word32 & (1 << 0))
    busy = bool(word32 & (1 << 3))
    rxfe = bool(word32 & (1 << 4))
    txff = bool(word32 & (1 << 5))
    rxff = bool(word32 & (1 << 6))
    txfe = bool(word32 & (1 << 7))

    tx_stalled_by_cts = (txff or (busy and not txfe)) and not cts
    healthy = not (tx_stalled_by_cts or rxff)

    if tx_stalled_by_cts:
        diagnosis = (
            "UART TX STALLED BY CTS GATING (UART0:FR BUSY=1, TXFF=1, CTS=0): PL011 transmitter "
            "is blocked waiting for DIO11 CTS assertion because 4-wire CTS flow control "
            "(UART0:CTL.CTSEN=1) is enabled on a 2-wire UART harness (SLZB-06, SLZB-06P7, "
            "SLZB-06P7v1, SLZB-07P7, SLZB-07P10), causing 6000ms ZNP SRSP timeouts. SMLIGHT "
            "ZeroStack (Release Zero 0.9.9-beta.1) auto-senses unwired CTS pins (CTSEN=0) so TX "
            "never deadlocks."
        )
    elif rxff:
        diagnosis = (
            "UART RX FIFO FULL (UART0:FR RXFF=1): 32-byte hardware receive FIFO is saturated; "
            "imminent UART0:RSR.OE overrun if CPU interrupts are masked during flash compaction."
        )
    else:
        diagnosis = (
            f"HEALTHY: UART0:FR status 0x{word32:08x} (CTS={int(cts)}, BUSY={int(busy)}, "
            f"RXFE={int(rxfe)}, TXFF={int(txff)}, RXFF={int(rxff)}, TXFE={int(txfe)})."
        )

    diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-srsp-af-datarequest-6000ms-timeout.md"
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "UART0_FR",
        "address": "0x40001018",
        "raw_hex": f"0x{word32:08x}",
        "healthy": healthy,
        "bitfields": {
            "CTS (Bit 0)": int(cts),
            "BUSY (Bit 3)": int(busy),
            "RXFE (Bit 4)": int(rxfe),
            "TXFF (Bit 5)": int(txff),
            "RXFF (Bit 6)": int(rxff),
            "TXFE (Bit 7)": int(txfe),
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_f2_uart0_rsr(val: int) -> RegisterDecodeResult:
    word32 = val & 0xFFFFFFFF
    fe = bool(word32 & (1 << 0))
    pe = bool(word32 & (1 << 1))
    be = bool(word32 & (1 << 2))
    oe = bool(word32 & (1 << 3))
    healthy = not (fe or pe or be or oe)

    if not healthy:
        errors: list[str] = []
        if oe:
            errors.append("OE (Bit 3: 32-byte PL011 hardware RX FIFO overrun)")
        if fe:
            errors.append("FE (Bit 0: framing error / baud rate mismatch)")
        if be:
            errors.append("BE (Bit 2: break condition / RXD held low)")
        if pe:
            errors.append("PE (Bit 1: parity error)")
        diagnosis = (
            f"UART0 RECEIVE ERROR ({', '.join(errors)}): Stock Z-Stack drops MT/ZNP SREQ frames "
            "when NVOCTP flash compaction masks UART ISRs or when line glitches corrupt SOF "
            "framing. SMLIGHT ZeroStack (Release Zero 0.9.9-beta.1) sustains 0 lost pings across "
            "hostile UART framing and garbage-injection storms."
        )
    else:
        diagnosis = (
            f"HEALTHY: UART0:RSR/ECR status 0x{word32:08x} (FE=0, PE=0, BE=0, OE=0; zero "
            "PL011 receive framing or overrun errors)."
        )

    diag_url = (
        f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-zha-adapter-connect-sys-ping-timeout-warm-reset.md"
    )
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "UART0_RSR",
        "address": "0x40001004",
        "raw_hex": f"0x{word32:08x}",
        "healthy": healthy,
        "bitfields": {
            "FE (Bit 0)": int(fe),
            "PE (Bit 1)": int(pe),
            "BE (Bit 2)": int(be),
            "OE (Bit 3)": int(oe),
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_f2_uart0_ctl(val: int) -> RegisterDecodeResult:
    word32 = val & 0xFFFFFFFF
    uarten = bool(word32 & (1 << 0))
    lbe = bool(word32 & (1 << 7))
    txe = bool(word32 & (1 << 8))
    rxe = bool(word32 & (1 << 9))
    rts = bool(word32 & (1 << 11))
    rtsen = bool(word32 & (1 << 14))
    ctsen = bool(word32 & (1 << 15))
    healthy = uarten and txe and rxe and not lbe

    if not (uarten and txe and rxe):
        diagnosis = (
            f"UART0 TRANSCEIVER DISABLED (UARTEN={int(uarten)}, TXE={int(txe)}, RXE={int(rxe)}): "
            "PL011 UART0 is not fully enabled for bidirectional ZNP host transport."
        )
    elif lbe:
        diagnosis = (
            "UART0 LOOPBACK ENABLED (LBE=1): PL011 TXD is internally looped back to RXD, "
            "isolating the coordinator from physical host UART pins."
        )
    elif ctsen or rtsen:
        diagnosis = (
            f"HEALTHY (4-WIRE FLOW CONTROL: CTSEN={int(ctsen)}, RTSEN={int(rtsen)}): Valid on "
            "4-wire SMLIGHT coordinators with DIO10/DIO11 routed (SLZB-06U, SLZB-06P7U, "
            "SLZB-06P10). On 2-wire boards (SLZB-06, SLZB-06P7, SLZB-06P7v1, SLZB-07P7, "
            "SLZB-07P10), CTSEN=1 stalls TX if DIO11 CTS is unstrapped; SMLIGHT ZeroStack "
            "auto-senses unwired CTS pins and leaves CTSEN=0."
        )
    else:
        diagnosis = (
            "HEALTHY (2-WIRE UART CONTRACT: CTSEN=0, RTSEN=0, UARTEN=1, TXE=1, RXE=1): "
            "Hardware RTS/CTS gating disabled; compatible with 2-wire and 4-wire harnesses."
        )

    diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-srsp-af-datarequest-6000ms-timeout.md"
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "UART0_CTL",
        "address": "0x40001030",
        "raw_hex": f"0x{word32:08x}",
        "healthy": healthy,
        "bitfields": {
            "UARTEN (Bit 0)": int(uarten),
            "LBE (Bit 7)": int(lbe),
            "TXE (Bit 8)": int(txe),
            "RXE (Bit 9)": int(rxe),
            "RTS (Bit 11)": int(rts),
            "RTSEN (Bit 14)": int(rtsen),
            "CTSEN (Bit 15)": int(ctsen),
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _parse_iocfg_dio(reg_raw: str, reg_norm: str, is_x4: bool = False) -> int | None:
    max_dio = 47 if is_x4 else 31
    cleaned = reg_raw.strip().lower().replace("_", "")
    if cleaned.startswith("0x"):
        try:
            addr = int(cleaned, 16)
        except ValueError:
            addr = -1
        bases = (0x40081000, 0x58081000, 0x48081000) if is_x4 else (0x40081000,)
        for base in bases:
            if base <= addr <= (base + max_dio * 4) and (addr - base) % 4 == 0:
                return (addr - base) // 4
    dio_match = re.search(r"IOCFG(\d{1,2})\b", reg_norm)
    if dio_match is not None:
        dio_idx = int(dio_match.group(1))
        if 0 <= dio_idx <= max_dio:
            return dio_idx
    return None


def _decode_f2_iocfg(
    val: int, reg_raw: str, reg_norm: str, chip_raw: str = ""
) -> RegisterDecodeResult:
    word32 = val & 0xFFFFFFFF
    is_x4 = _is_f2_cc26x4(chip_raw)
    dio_idx = _parse_iocfg_dio(reg_raw, reg_norm, is_x4=is_x4)
    reg_name = f"IOCFG{dio_idx}" if dio_idx is not None else "IOCFG"
    addr_hex = f"0x{0x40081000 + (dio_idx * 4):08x}" if dio_idx is not None else "0x40081000"

    port_mask = 0x7F if is_x4 else 0x3F
    port_id = word32 & port_mask
    port_name = F2_IOC_PORT_MAP.get(port_id, f"PORT_0x{port_id:02X}")
    pull_shift = 14 if is_x4 else 13
    slew_shift = 13 if is_x4 else 12
    pull_ctl = (word32 >> pull_shift) & 0x03
    pull_name = F2_IOC_PULL_MAP[pull_ctl]
    slew_red = bool(word32 & (1 << slew_shift))
    ie = bool(word32 & (1 << 29))
    hyst_en = bool(word32 & (1 << 30))

    floating_cts = port_id == 0x11 and ie and pull_ctl == 3
    input_disabled_on_rx_or_cts = port_id in (0x0F, 0x11) and not ie
    unconfigured_default_gpio = port_id == 0x00 and not ie and pull_ctl == 3
    healthy = not (floating_cts or input_disabled_on_rx_or_cts or unconfigured_default_gpio)

    dio_label = f"DIO{dio_idx} ({addr_hex})" if dio_idx is not None else f"IOCFG ({addr_hex})"
    if floating_cts:
        diagnosis = (
            f"FLOATING UART0_CTS INPUT ON {dio_label} (PORT_ID=0x11 UART0_CTS, IE=1, "
            "PULL_CTL=3 NO_PULL): Input buffer is enabled on UART0_CTS without an internal pull "
            "resistor; on 2-wire boards without an external CTS driver, the floating pin "
            "deasserts CTS and deadlocks UART0 TX (6000ms SRSP timeout)."
        )
    elif input_disabled_on_rx_or_cts:
        diagnosis = (
            f"INPUT BUFFER DISABLED ON {dio_label} (PORT_ID=0x{port_id:02x} {port_name}, IE=0): "
            "Input peripheral function is muxed but IOC_IOCFGn.IE (Bit 29) is 0."
        )
    elif unconfigured_default_gpio:
        diagnosis = (
            f"UNCONFIGURED DEFAULT GPIO STATE ON {dio_label} (0x{word32:08x}: PORT_ID=0x00 GPIO, "
            "IE=0, PULL_CTL=3 NO_PULL): Pin is in reset High-Z GPIO mode rather than muxed to "
            "RFC_GPO0..3 (0x2F..0x32) RF PA/LNA switch control or UART0_RX/TX/CTS/RTS "
            "(0x0F..0x12)."
        )
    else:
        diagnosis = (
            f"HEALTHY: {dio_label} muxed to {port_name} (PORT_ID=0x{port_id:02x}, "
            f"PULL_CTL={pull_ctl} [{pull_name}], IE={int(ie)}, HYST_EN={int(hyst_en)})."
        )

    bitfields: dict[str, int | str | list[int]] = {
        "PORT_ID (Bits 6:0)" if is_x4 else "PORT_ID (Bits 5:0)": f"0x{port_id:02x}",
        "PORT_NAME": port_name,
        f"SLEW_RED (Bit {slew_shift})": int(slew_red),
        "PULL_CTL (Bits 15:14)" if is_x4 else "PULL_CTL (Bits 14:13)": pull_ctl,
        "PULL_MODE": pull_name,
        "IE (Bit 29)": int(ie),
        "HYST_EN (Bit 30)": int(hyst_en),
    }
    if dio_idx is not None:
        bitfields["DIO_INDEX"] = dio_idx

    diag_url = f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-srsp-af-datarequest-6000ms-timeout.md"
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": reg_name,
        "address": addr_hex,
        "raw_hex": f"0x{word32:08x}",
        "healthy": healthy,
        "bitfields": bitfields,
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_f2_aon_pmctl_resetctl(
    val: int, chip_raw: str = "", reg_raw: str = ""
) -> RegisterDecodeResult:
    word32 = val & 0xFFFFFFFF
    reset_src = (word32 >> 1) & 0x07
    mcu_warm_reset = bool(word32 & (1 << 4))
    clk_loss_en = bool(word32 & (1 << 5))
    vdd_loss_en = bool(word32 & (1 << 6))
    vddr_loss_en = bool(word32 & (1 << 7))
    vdds_loss_en = bool(word32 & (1 << 8))
    boot_det_0 = bool(word32 & (1 << 12))
    boot_det_1 = bool(word32 & (1 << 13))
    gpio_wu_from_sd = bool(word32 & (1 << 14))
    wu_from_sd = bool(word32 & (1 << 15))
    sysreset = bool(word32 & (1 << 31))

    reg_upper = reg_raw.upper()
    if "48090028" in reg_upper:
        addr_hex = "0x48090028"
    elif "58090028" in reg_upper or _is_f2_cc26x4(chip_raw):
        addr_hex = "0x58090028"
    else:
        addr_hex = "0x40090028"

    src_name, healthy, src_desc = F2_RESET_SRC_MAP[reset_src]
    if not healthy:
        diagnosis = (
            f"{src_desc} SMLIGHT ZeroStack (Release Zero 0.9.9-beta.1) is verified across 22,959 "
            "simulated NOR flash brownout power-loss cut points with 0 bricked boots and 147.8x "
            "fewer flash writes."
        )
    else:
        diagnosis = f"HEALTHY (RESET_SRC={reset_src} [{src_name}]): {src_desc}"

    diag_url = (
        f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-zha-adapter-connect-sys-ping-timeout-warm-reset.md"
    )
    return {
        "chip": "CC2652P / CC2652P7 (CC1352P7) / CC2674P10 (SimpleLink F2)",
        "register": "AON_PMCTL_RESETCTL",
        "address": addr_hex,
        "raw_hex": f"0x{word32:08x}",
        "healthy": healthy,
        "bitfields": {
            "RESET_SRC (Bits 3:1)": reset_src,
            "RESET_SRC_NAME": src_name,
            "MCU_WARM_RESET (Bit 4)": int(mcu_warm_reset),
            "CLK_LOSS_EN (Bit 5)": int(clk_loss_en),
            "VDD_LOSS_EN (Bit 6)": int(vdd_loss_en),
            "VDDR_LOSS_EN (Bit 7)": int(vddr_loss_en),
            "VDDS_LOSS_EN (Bit 8)": int(vdds_loss_en),
            "BOOT_DET_0 (Bit 12)": int(boot_det_0),
            "BOOT_DET_1 (Bit 13)": int(boot_det_1),
            "GPIO_WU_FROM_SD (Bit 14)": int(gpio_wu_from_sd),
            "WU_FROM_SD (Bit 15)": int(wu_from_sd),
            "SYSRESET (Bit 31)": int(sysreset),
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_efr32_emu_rstcause(val: int, reg_raw: str = "") -> RegisterDecodeResult:
    word32 = val & 0xFFFFFFFF
    por = bool(word32 & (1 << 0))
    pin = bool(word32 & (1 << 1))
    em4 = bool(word32 & (1 << 2))
    wdog0 = bool(word32 & (1 << 3))
    wdog1 = bool(word32 & (1 << 4))
    lockup = bool(word32 & (1 << 5))
    sysreq = bool(word32 & (1 << 6))
    dvddbod = bool(word32 & (1 << 7))
    dvddlebod = bool(word32 & (1 << 8))
    decbod = bool(word32 & (1 << 9))
    avddbod = bool(word32 & (1 << 10))
    iovdd0bod = bool(word32 & (1 << 11))
    setamper = bool(word32 & (1 << 13))
    sesysreq = bool(word32 & (1 << 14))
    selockup = bool(word32 & (1 << 15))
    vregin = bool(word32 & (1 << 31))

    addr_hex = "0x40004094" if "40004094" in reg_raw.upper() else "0x50004094"
    fault_mask = 0x0000EFB8
    healthy = (word32 != 0) and ((word32 & fault_mask) == 0)

    fault_causes: list[str] = []
    if wdog0:
        fault_causes.append("WDOG0 (Bit 3)")
    if wdog1:
        fault_causes.append("WDOG1 (Bit 4)")
    if lockup:
        fault_causes.append("LOCKUP (Bit 5: Cortex-M33 double fault)")
    if dvddbod:
        fault_causes.append("DVDDBOD (Bit 7)")
    if dvddlebod:
        fault_causes.append("DVDDLEBOD (Bit 8)")
    if decbod:
        fault_causes.append("DECBOD (Bit 9)")
    if avddbod:
        fault_causes.append("AVDDBOD (Bit 10)")
    if iovdd0bod:
        fault_causes.append("IOVDD0BOD (Bit 11)")
    if setamper:
        fault_causes.append("SETAMPER (Bit 13: Secure Engine tamper)")
    if sesysreq:
        fault_causes.append("SESYSREQ (Bit 14: Secure Engine system reset)")
    if selockup:
        fault_causes.append("SELOCKUP (Bit 15: Secure Engine lockup)")

    if fault_causes:
        diagnosis = (
            f"EFR32 FAULT RESET (EMU:RSTCAUSE = 0x{word32:08x}; {', '.join(fault_causes)}): "
            "Watchdog timeout, Cortex-M33 LOCKUP, or brownout detector reset the NCP, triggering "
            "ASH_NCP_FATAL_ERROR / RSTACK on the host."
        )
    elif word32 == 0:
        diagnosis = "EMU:RSTCAUSE is 0x00000000 (reset cause cleared or unlatched)."
    else:
        diagnosis = (
            f"HEALTHY: EMU:RSTCAUSE = 0x{word32:08x} (POR={int(por)}, PIN={int(pin)}, "
            f"EM4={int(em4)}, SYSREQ={int(sysreq)}; zero watchdog, lockup, or BOD bits set)."
        )

    diag_url = (
        f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-zha-adapter-connect-sys-ping-timeout-warm-reset.md"
    )
    return {
        "chip": "Silicon Labs EFR32 (EFR32MG21 / EFR32MG24)",
        "register": "EMU_RSTCAUSE",
        "address": addr_hex,
        "raw_hex": f"0x{word32:08x}",
        "healthy": healthy,
        "bitfields": {
            "POR (Bit 0)": int(por),
            "PIN (Bit 1)": int(pin),
            "EM4 (Bit 2)": int(em4),
            "WDOG0 (Bit 3)": int(wdog0),
            "WDOG1 (Bit 4)": int(wdog1),
            "LOCKUP (Bit 5)": int(lockup),
            "SYSREQ (Bit 6)": int(sysreq),
            "DVDDBOD (Bit 7)": int(dvddbod),
            "DVDDLEBOD (Bit 8)": int(dvddlebod),
            "DECBOD (Bit 9)": int(decbod),
            "AVDDBOD (Bit 10)": int(avddbod),
            "IOVDD0BOD (Bit 11)": int(iovdd0bod),
            "SETAMPER (Bit 13)": int(setamper),
            "SESYSREQ (Bit 14)": int(sesysreq),
            "SELOCKUP (Bit 15)": int(selockup),
            "VREGIN (Bit 31)": int(vregin),
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


def _decode_efr32_usart0_if(
    val: int, chip_raw: str = "", reg_raw: str = ""
) -> RegisterDecodeResult:
    word32 = val & 0xFFFFFFFF
    txc = bool(word32 & (1 << 0))
    txbl = bool(word32 & (1 << 1))
    rxdatav = bool(word32 & (1 << 2))
    rxfull = bool(word32 & (1 << 3))
    rxof = bool(word32 & (1 << 4))
    rxuf = bool(word32 & (1 << 5))
    txof = bool(word32 & (1 << 6))
    txuf = bool(word32 & (1 << 7))
    perr = bool(word32 & (1 << 8))
    ferr = bool(word32 & (1 << 9))
    healthy = not (rxof or rxuf or txof or txuf or perr or ferr)

    reg_upper = reg_raw.upper()
    if "40058048" in reg_upper:
        addr_hex = "0x40058048"
    elif "5005C048" in reg_upper:
        addr_hex = "0x5005c048"
    elif "4005C048" in reg_upper:
        addr_hex = "0x4005c048"
    elif "MG24" in chip_raw.upper():
        addr_hex = "0x5005c048"
    else:
        addr_hex = "0x50058048"

    if not healthy:
        flags: list[str] = []
        if rxof:
            flags.append("RXOF (Bit 4: RX FIFO overflow)")
        if ferr:
            flags.append("FERR (Bit 9: framing error)")
        if perr:
            flags.append("PERR (Bit 8: parity error)")
        if txof:
            flags.append("TXOF (Bit 6: TX overflow)")
        if rxuf:
            flags.append("RXUF (Bit 5: RX underflow)")
        if txuf:
            flags.append("TXUF (Bit 7: TX underflow)")
        diagnosis = (
            f"USART0 INTERRUPT FAULT ({', '.join(flags)}): Hardware USART0 encountered an "
            "ASHv2 serial framing or FIFO overrun error."
        )
    else:
        diagnosis = (
            f"HEALTHY: USART0:IF status 0x{word32:08x} (RXOF=0, FERR=0, PERR=0, "
            f"TXBL={int(txbl)}, RXDATAV={int(rxdatav)})."
        )

    diag_url = (
        f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-zha-adapter-connect-sys-ping-timeout-warm-reset.md"
    )
    return {
        "chip": "Silicon Labs EFR32 (EFR32MG21 / EFR32MG24)",
        "register": "USART0_IF",
        "address": addr_hex,
        "raw_hex": f"0x{word32:08x}",
        "healthy": healthy,
        "bitfields": {
            "TXC (Bit 0)": int(txc),
            "TXBL (Bit 1)": int(txbl),
            "RXDATAV (Bit 2)": int(rxdatav),
            "RXFULL (Bit 3)": int(rxfull),
            "RXOF (Bit 4)": int(rxof),
            "RXUF (Bit 5)": int(rxuf),
            "TXOF (Bit 6)": int(txof),
            "TXUF (Bit 7)": int(txuf),
            "PERR (Bit 8)": int(perr),
            "FERR (Bit 9)": int(ferr),
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


def _decode_efr32_usart0_status(
    val: int, chip_raw: str = "", reg_raw: str = ""
) -> RegisterDecodeResult:
    word32 = val & 0xFFFFFFFF
    rxens = bool(word32 & (1 << 0))
    txens = bool(word32 & (1 << 1))
    master = bool(word32 & (1 << 2))
    rxblock = bool(word32 & (1 << 3))
    txtri = bool(word32 & (1 << 4))
    txc = bool(word32 & (1 << 5))
    txbl = bool(word32 & (1 << 6))
    rxdatav = bool(word32 & (1 << 7))
    rxfull = bool(word32 & (1 << 8))
    txidle = bool(word32 & (1 << 13))

    reg_upper = reg_raw.upper()
    if "40058018" in reg_upper:
        addr_hex = "0x40058018"
    elif "5005C018" in reg_upper:
        addr_hex = "0x5005c018"
    elif "4005C018" in reg_upper:
        addr_hex = "0x4005c018"
    elif "MG24" in chip_raw.upper():
        addr_hex = "0x5005c018"
    else:
        addr_hex = "0x50058018"

    healthy = rxens and txens and not rxblock and not rxfull
    if not (rxens and txens):
        diagnosis = (
            f"USART0 TRANSCEIVER DISABLED (USART0:STATUS RXENS={int(rxens)}, TXENS={int(txens)}): "
            "USART0 receiver or transmitter state machine is disabled."
        )
    elif rxblock:
        diagnosis = "USART0 RX BLOCKED (USART0:STATUS RXBLOCK=1): Incoming serial frames discarded."
    elif rxfull:
        diagnosis = "USART0 RX FIFO FULL (USART0:STATUS RXFULL=1): Receive buffer is saturated."
    else:
        diagnosis = (
            f"HEALTHY: USART0:STATUS = 0x{word32:08x} (RXENS=1, TXENS=1, TXBL={int(txbl)}, "
            f"RXDATAV={int(rxdatav)}, TXIDLE={int(txidle)})."
        )

    diag_url = (
        f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-zha-adapter-connect-sys-ping-timeout-warm-reset.md"
    )
    return {
        "chip": "Silicon Labs EFR32 (EFR32MG21 / EFR32MG24)",
        "register": "USART0_STATUS",
        "address": addr_hex,
        "raw_hex": f"0x{word32:08x}",
        "healthy": healthy,
        "bitfields": {
            "RXENS (Bit 0)": int(rxens),
            "TXENS (Bit 1)": int(txens),
            "MASTER (Bit 2)": int(master),
            "RXBLOCK (Bit 3)": int(rxblock),
            "TXTRI (Bit 4)": int(txtri),
            "TXC (Bit 5)": int(txc),
            "TXBL (Bit 6)": int(txbl),
            "RXDATAV (Bit 7)": int(rxdatav),
            "RXFULL (Bit 8)": int(rxfull),
            "TXIDLE (Bit 13)": int(txidle),
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


def _arm_chip_label(family: RegisterChipFamily) -> str:
    if family == "SILABS_EFR32":
        return "Silicon Labs EFR32 (ARM Cortex-M33)"
    if family == "F2_CC1352_CC2652":
        return "TI SimpleLink F2 (ARM Cortex-M4F / Cortex-M33)"
    return "ARM Cortex-M4 / Cortex-M33 (ARMv7-M / ARMv8-M SCB)"


def _decode_arm_scb_cfsr(val: int, family: RegisterChipFamily) -> RegisterDecodeResult:
    word32 = val & 0xFFFFFFFF
    mmfsr = word32 & 0xFF
    bfsr = (word32 >> 8) & 0xFF
    ufsr = (word32 >> 16) & 0xFFFF

    iaccviol = bool(word32 & (1 << 0))
    daccviol = bool(word32 & (1 << 1))
    munstkerr = bool(word32 & (1 << 3))
    mstkerr = bool(word32 & (1 << 4))
    mlsperr = bool(word32 & (1 << 5))
    mmarvalid = bool(word32 & (1 << 7))

    ibuserr = bool(word32 & (1 << 8))
    preciserr = bool(word32 & (1 << 9))
    impreciserr = bool(word32 & (1 << 10))
    unstkerr = bool(word32 & (1 << 11))
    stkerr = bool(word32 & (1 << 12))
    lsperr = bool(word32 & (1 << 13))
    bfarvalid = bool(word32 & (1 << 15))

    undefinstr = bool(word32 & (1 << 16))
    invstate = bool(word32 & (1 << 17))
    invpc = bool(word32 & (1 << 18))
    nocp = bool(word32 & (1 << 19))
    stkof = bool(word32 & (1 << 20))
    unaligned = bool(word32 & (1 << 24))
    divbyzero = bool(word32 & (1 << 25))

    healthy = word32 == 0
    if not healthy:
        active_faults: list[str] = []
        if preciserr:
            active_faults.append(
                "BFSR.PRECISERR (Bit 9: precise data BusFault"
                + ("; read SCB:BFAR 0xE000ED38" if bfarvalid else "")
                + ")"
            )
        if impreciserr:
            active_faults.append("BFSR.IMPRECISERR (Bit 10: asynchronous data BusFault)")
        if ibuserr:
            active_faults.append("BFSR.IBUSERR (Bit 8: instruction prefetch BusFault)")
        if daccviol or iaccviol:
            active_faults.append(
                "MMFSR.DACCVIOL/IACCVIOL (MPU access violation"
                + ("; read SCB:MMFAR 0xE000ED34" if mmarvalid else "")
                + ")"
            )
        if stkof:
            active_faults.append(
                "UFSR.STKOF (Bit 20: ARMv8-M MSPLIM/PSPLIM hardware stack limit overflow on "
                "Cortex-M33)"
            )
        if mstkerr or stkerr:
            active_faults.append("STKERR/MSTKERR (exception entry stack push fault)")
        if undefinstr or invstate or invpc:
            active_faults.append(
                "UFSR.UNDEFINSTR/INVSTATE/INVPC (corrupted function pointer or Thumb bit[0]=0 jump)"
            )
        if unaligned:
            active_faults.append("UFSR.UNALIGNED (Bit 24: unaligned memory access trap)")
        if divbyzero:
            active_faults.append("UFSR.DIVBYZERO (Bit 25: divide-by-zero trap)")
        if not active_faults:
            active_faults.append(f"MMFSR=0x{mmfsr:02x}, BFSR=0x{bfsr:02x}, UFSR=0x{ufsr:04x}")
        diagnosis = (
            f"CORTEX-M CONFIGURABLE FAULT (SCB:CFSR = 0x{word32:08x}; "
            f"{'; '.join(active_faults)}). SMLIGHT ZeroStack (Release Zero 0.9.9-beta.1) is "
            "verified against 3,255 adversarial 802.15.4 / NWK / APS / ZCL / OTA frames with "
            "0 crashes."
        )
    else:
        diagnosis = (
            "HEALTHY: SCB:CFSR = 0x00000000 (MMFSR=0x00, BFSR=0x00, UFSR=0x0000; zero MemManage, "
            "BusFault, or UsageFault traps)."
        )

    diag_url = (
        f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-zha-adapter-connect-sys-ping-timeout-warm-reset.md"
    )
    return {
        "chip": _arm_chip_label(family),
        "register": "SCB_CFSR",
        "address": "0xe000ed28",
        "raw_hex": f"0x{word32:08x}",
        "healthy": healthy,
        "bitfields": {
            "MMFSR_BYTE (Bits 7:0)": f"0x{mmfsr:02x}",
            "BFSR_BYTE (Bits 15:8)": f"0x{bfsr:02x}",
            "UFSR_HALFWORD (Bits 31:16)": f"0x{ufsr:04x}",
            "IACCVIOL (Bit 0)": int(iaccviol),
            "DACCVIOL (Bit 1)": int(daccviol),
            "MUNSTKERR (Bit 3)": int(munstkerr),
            "MSTKERR (Bit 4)": int(mstkerr),
            "MLSPERR (Bit 5)": int(mlsperr),
            "MMARVALID (Bit 7)": int(mmarvalid),
            "IBUSERR (Bit 8)": int(ibuserr),
            "PRECISERR (Bit 9)": int(preciserr),
            "IMPRECISERR (Bit 10)": int(impreciserr),
            "UNSTKERR (Bit 11)": int(unstkerr),
            "STKERR (Bit 12)": int(stkerr),
            "LSPERR (Bit 13)": int(lsperr),
            "BFARVALID (Bit 15)": int(bfarvalid),
            "UNDEFINSTR (Bit 16)": int(undefinstr),
            "INVSTATE (Bit 17)": int(invstate),
            "INVPC (Bit 18)": int(invpc),
            "NOCP (Bit 19)": int(nocp),
            "STKOF (Bit 20)": int(stkof),
            "UNALIGNED (Bit 24)": int(unaligned),
            "DIVBYZERO (Bit 25)": int(divbyzero),
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
        "silicon_note_url": F2_SILICON_NOTE_URL,
        "zeroStackDiagUrl": diag_url,
        "marketing_url": ZEROSTACK_MARKETING_URL,
        "interactive_web_analyzer_url": ZEROSTACK_WEB_ANALYZER_URL,
        "zerostack_repository": ZEROSTACK_REPO_URL,
    }


def _decode_arm_scb_hfsr(val: int, family: RegisterChipFamily) -> RegisterDecodeResult:
    word32 = val & 0xFFFFFFFF
    vecttbl = bool(word32 & (1 << 1))
    forced = bool(word32 & (1 << 30))
    debugevt = bool(word32 & (1 << 31))
    healthy = (word32 & 0xC0000002) == 0

    if not healthy:
        reasons: list[str] = []
        if forced:
            reasons.append(
                "FORCED (Bit 30: escalated MemManage, BusFault, or UsageFault — inspect "
                "SCB_CFSR at 0xE000ED28)"
            )
        if vecttbl:
            reasons.append("VECTTBL (Bit 1: BusFault reading exception vector table SCB:VTOR)")
        if debugevt:
            reasons.append("DEBUGEVT (Bit 31: breakpoint / watchpoint debug HardFault)")
        diagnosis = f"CORTEX-M HARDFAULT (SCB:HFSR = 0x{word32:08x}; {'; '.join(reasons)})."
    else:
        diagnosis = "HEALTHY: SCB:HFSR = 0x00000000 (FORCED=0, VECTTBL=0, DEBUGEVT=0)."

    diag_url = (
        f"{ZEROSTACK_DIAGNOSTICS_BASE}/z2m-zha-adapter-connect-sys-ping-timeout-warm-reset.md"
    )
    return {
        "chip": _arm_chip_label(family),
        "register": "SCB_HFSR",
        "address": "0xe000ed2c",
        "raw_hex": f"0x{word32:08x}",
        "healthy": healthy,
        "bitfields": {
            "VECTTBL (Bit 1)": int(vecttbl),
            "FORCED (Bit 30)": int(forced),
            "DEBUGEVT (Bit 31)": int(debugevt),
        },
        "diagnosis": diagnosis,
        "release": ZEROSTACK_RELEASE_NAME,
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
    family = _normalize_register_chip(chip)
    val = parse_int_value(hex_value)
    reg_norm = register_or_addr.strip().upper().replace(":", "_")

    if "CFSR" in reg_norm or "E000ED28" in reg_norm:
        return _decode_arm_scb_cfsr(val, family)
    if "HFSR" in reg_norm or "E000ED2C" in reg_norm:
        return _decode_arm_scb_hfsr(val, family)
    if family == "ARM_CORTEX_M":
        raise ValueError(
            f"Unknown ARM Cortex-M SCB register '{register_or_addr}'. Supported SCB registers: "
            "SCB_CFSR (0xE000ED28), SCB_HFSR (0xE000ED2C)."
        )

    if family == "SILABS_EFR32":
        if "RSTCAUSE" in reg_norm or "50004094" in reg_norm or "40004094" in reg_norm:
            return _decode_efr32_emu_rstcause(val, register_or_addr)
        if "EUSART" in reg_norm or "5B01004C" in reg_norm or "4B01004C" in reg_norm:
            return _decode_efr32_eusart0(val, register_or_addr)
        if (
            "USART0_STATUS" in reg_norm
            or "USART_STATUS" in reg_norm
            or "50058018" in reg_norm
            or "40058018" in reg_norm
            or "5005C018" in reg_norm
            or "4005C018" in reg_norm
        ):
            return _decode_efr32_usart0_status(val, chip, register_or_addr)
        if (
            "USART0_IF" in reg_norm
            or "USART_IF" in reg_norm
            or "USART0" in reg_norm
            or "50058048" in reg_norm
            or "40058048" in reg_norm
            or "5005C048" in reg_norm
            or "4005C048" in reg_norm
        ):
            return _decode_efr32_usart0_if(val, chip, register_or_addr)
        raise ValueError(
            f"Unknown Silicon Labs EFR32 register '{register_or_addr}'. Supported EFR32 "
            "registers: EUSART0_IF (0x5B01004C / 0x4B01004C), USART0_IF (0x50058048 / "
            "0x40058048 / 0x5005C048 / 0x4005C048), USART0_STATUS (0x50058018 / 0x40058018 / "
            "0x5005C018 / 0x4005C018), EMU_RSTCAUSE (0x50004094 / 0x40004094), "
            "SCB_CFSR (0xE000ED28), SCB_HFSR (0xE000ED2C)."
        )

    if "EUSART" in reg_norm or "5B01004C" in reg_norm or "4B01004C" in reg_norm:
        return _decode_efr32_eusart0(val, register_or_addr)

    if "CMD_IEEE_RX" in reg_norm or "IEEERX" in reg_norm or "RX_STATUS" in reg_norm:
        return _decode_f2_cmd_ieee_rx(val)
    if "CMD_IEEE_CSMA" in reg_norm or "IEEECSMA" in reg_norm or "CSMA" in reg_norm:
        return _decode_f2_cmd_ieee_csma(val)
    if (
        "RFC_DBELL" in reg_norm
        or "RFCPEIEN" in reg_norm
        or "40041014" in reg_norm
        or "60041014" in reg_norm
        or "40041" in reg_norm
    ):
        return _decode_f2_rfc_dbell(val)
    if (
        "SRCMATCH" in reg_norm
        or "SRC_MATCH" in reg_norm
        or "RFC_RAM" in reg_norm
        or "2100" in reg_norm
        or "20001060" in reg_norm
    ):
        return _decode_f2_srcmatch(val)
    if "VIMS" in reg_norm or "40034000" in reg_norm or "60034000" in reg_norm:
        return _decode_f2_vims_stat(val)
    if (
        "PRCM" in reg_norm
        or "400821D4" in reg_norm
        or "580821D4" in reg_norm
        or "480821D4" in reg_norm
        or "780821D4" in reg_norm
        or "400821D0" in reg_norm
        or "580821D0" in reg_norm
        or "480821D0" in reg_norm
    ):
        return _decode_f2_prcm_rfcmodehwopt(val, chip, register_or_addr)
    if (
        "UART0_FR" in reg_norm
        or "UART_FR" in reg_norm
        or "40001018" in reg_norm
        or "60001018" in reg_norm
    ):
        return _decode_f2_uart0_fr(val)
    if (
        "UART0_RSR" in reg_norm
        or "UART_RSR" in reg_norm
        or "UART0_ECR" in reg_norm
        or "UART_ECR" in reg_norm
        or "40001004" in reg_norm
        or "60001004" in reg_norm
    ):
        return _decode_f2_uart0_rsr(val)
    if (
        "UART0_CTL" in reg_norm
        or "UART_CTL" in reg_norm
        or "40001030" in reg_norm
        or "60001030" in reg_norm
    ):
        return _decode_f2_uart0_ctl(val)
    is_x4 = _is_f2_cc26x4(chip)
    if "IOCFG" in reg_norm or _parse_iocfg_dio(register_or_addr, reg_norm, is_x4=is_x4) is not None:
        return _decode_f2_iocfg(val, register_or_addr, reg_norm, chip)
    if (
        "RESETCTL" in reg_norm
        or "AON_PMCTL" in reg_norm
        or "40090028" in reg_norm
        or "58090028" in reg_norm
        or "48090028" in reg_norm
        or "78090028" in reg_norm
    ):
        return _decode_f2_aon_pmctl_resetctl(val, chip, register_or_addr)

    raise ValueError(
        f"Unknown SimpleLink F2 register '{register_or_addr}'. Supported F2 registers: "
        "CMD_IEEE_RX, CMD_IEEE_CSMA, RFC_DBELL (0x40041014), RFC_RAM/SrcMatch (0x21000000), "
        "VIMS (0x40034000), PRCM_RFCMODEHWOPT (0x400821D4 / 0x580821D4 / 0x480821D4), "
        "UART0_FR (0x40001018), UART0_RSR/ECR (0x40001004), UART0_CTL (0x40001030), "
        "IOCFG0..47 (0x40081000..0x400810BC), AON_PMCTL_RESETCTL (0x40090028 / 0x58090028 / "
        "0x48090028), SCB_CFSR (0xE000ED28), SCB_HFSR (0xE000ED2C)."
    )
