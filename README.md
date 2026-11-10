<p align="center">
  <a href="https://smlight.tech/software/zerostack">
    <img src="https://raw.githubusercontent.com/smlight-tech/zerostack/main/docs/assets/zerostack-hero-banner.png" alt="SMLIGHT ZeroStack — Deterministic Zigbee 3.0 Firmware & RF Diagnostics" width="800">
  </a>
</p>

# ZeroStack RF Diagnostics & Benchmark MCP Server (`zerostack-mcp`)

<!-- mcp-name: io.github.zerostack-rf/zerostack-mcp -->

> **Official ZeroStack Overview & Downloads**: [https://smlight.tech/software/zerostack](https://smlight.tech/software/zerostack)
> **Interactive Web Log Analyzer**: [https://smlight-tech.github.io/zerostack/](https://smlight-tech.github.io/zerostack/)
> **Technical Whitepaper — Part 1 (PDF)**: [Scaling Zigbee 3.0 / R23 Beyond the 100-Node Wall](https://smlight-tech.github.io/zerostack/whitepapers/zerostack-whitepaper-part-1.pdf)
> **MCP Server**: `v0.9.9` | **Target Firmware**: ZeroStack Release Zero (`0.9.9-beta.1`)

`zerostack-mcp` is an open-source **Model Context Protocol (MCP)** server that gives AI coding assistants and home-automation troubleshooting agents (Claude Desktop, Cursor, Windsurf, Cline, OpenAI Agents, Home Assistant AI agents) deterministic tools to:

1. **Diagnose Zigbee2MQTT (`z2m`), Home Assistant ZHA (`zigpy-znp`, `bellows`), and OpenThread RCP logs** (`analyze_zigbee_thread_log`).
2. **Decode hardware radio/UART status registers** (`decode_silicon_register`) for TI SimpleLink F2 (`CC2652P`, `CC2652P7`, `CC1352P7`, `CC2674P10`) and Silicon Labs EFR32 (`EFR32MG21`, `EFR32MG24`).
3. **Evaluate Zigbee/Thread mesh coordinator capacity and `SRCMATCH` hardware limits** (`check_coordinator_capacity`).
4. **Query verified hardware validation benchmarks (`DWT->CYCCNT` @ `48.0 MHz`)** (`get_zerostack_benchmarks`) comparing **ZeroStack Release Zero (`0.9.9-beta.1`)** against legacy TI Z-Stack (`ZNP 3.x`) across SMLIGHT `SLZB-06` and `SLZB-07` series coordinators.

---

## Quick Start

### Run with `uvx` (No Installation Required)

```json
{
  "mcpServers": {
    "zerostack-rf": {
      "command": "uvx",
      "args": ["zerostack-mcp"]
    }
  }
}
```

### Local Development Installation

```bash
git clone https://github.com/zerostack-rf/zerostack-mcp.git
cd zerostack-rf-mcp
uv sync
uv run pytest
uv run zerostack-mcp
```

---

## Supported Hardware — Release Zero (`0.9.9-beta.1`)

ZeroStack **Release Zero (`0.9.9-beta.1`)** supports the **TI SimpleLink F2** family across SMLIGHT `SLZB-06` and `SLZB-07` series coordinators (**Zigbee 3.0 / PRO R23 Coordinator & Router** firmware with DMA-driven UART and **Live Auto-Baud `115200` / `460800` / `1000000`**):

| Coordinator Model | Radio SoC | SRAM / Flash | Hardware RTS/CTS | Transport |
| :--- | :--- | :--- | :--- | :--- |
| **`SLZB-06`** | `TI CC2652P` | `88 KB` / `352 KB` | No | Ethernet / PoE / USB / Wi-Fi |
| **`SLZB-06U`** | `TI CC2652P` | `88 KB` / `352 KB` | Yes (`DIO10` / `DIO11`) | Ethernet / PoE / USB / Wi-Fi |
| **`SLZB-06P7`** / **`SLZB-06P7v1`** | `TI CC2652P7` / `CC1352P7` | `144 KB` / `704 KB` | No | Ethernet / PoE / USB / Wi-Fi |
| **`SLZB-06P7U`** | `TI CC2652P7` / `CC1352P7` | `144 KB` / `704 KB` | Yes (`DIO10` / `DIO11`) | Ethernet / PoE / USB / Wi-Fi |
| **`SLZB-07P7`** | `TI CC2652P7` | `144 KB` / `704 KB` | No | USB Dongle |
| **`SLZB-06P10`** | `TI CC2674P10` | `256 KB` / `1024 KB` | Yes (`DIO10` / `DIO11`) | Ethernet / PoE / USB / Wi-Fi |
| **`SLZB-07P10`** | `TI CC2674P10` | `256 KB` / `1024 KB` | No | USB Dongle |

> **Note on Silicon Labs EFR32 (`EFR32MG21` / `EFR32MG24`)**: `zerostack-mcp` includes diagnostic rules (`0x72`, `0xa1`, `ASH_NCP_FATAL_ERROR`) and `EUSART0_IF` register decoding for Silicon Labs EmberZNet / EZSP coordinators (`SLZB-06M`, `SLZB-06Mg24`, SkyConnect/ZBT-1). ZeroStack **Release Zero (`0.9.9-beta.1`)** ships on SMLIGHT TI SimpleLink F2 coordinators; Silicon Labs EFR32 support is in active development.

---

## Verified Hardware Validation Benchmarks (`TI CC1352P7` @ `48.0 MHz`, `DWT->CYCCNT`)

### Part 1: Deterministic Execution Latency (`1 µs = 48 cycles`)

| Subsystem / Operation | Legacy TI Z-Stack (`ZNP 3.x`) | ZeroStack `Release Zero (0.9.9-beta.1)` | Measured Improvement |
| :--- | :--- | :--- | :--- |
| **TCLK Lookup (300-entry table, miss / first contact)** | `1,486,228` cyc (`30.96 ms`) | **`326` cyc (`6.8 µs`)** | **4,559× faster** (`0` flash reads) |
| **TCLK Lookup (300-entry table, oldest-record hit, age 383)** | `620,396` cyc (`12.92 ms`) | **`324` cyc (`6.75 µs`)** | **1,915× faster** (`Slot 0`: **7.1×**, `Slot 299`: **9.1×**) |
| **Per-Frame NWK Encrypt (`D=150`)** | `533,156` cyc (`11.11 ms`) | **`3,968` cyc (`82.7 µs`)** | **134.4× faster** (O(1), `0` flash reads) |
| **Per-Frame NWK Decrypt (`D=150`)** | `532,182` cyc (`11.09 ms`) | **`3,824` cyc (`79.7 µs`)** | **139.2× faster** (O(1), `0` flash reads) |
| **Routed Hop Security Ceiling (`D=150`, Decrypt + Encrypt)** | `22.19 ms` (`~45 pkt/s` ceiling) | **`162 µs` (`7,792` cyc, `>6,100 pkt/s`)** | **135× higher ceiling** |
| **Per-Frame APS TX Security (300-peer table, `D=0..100`)** | `52,909–409,301` cyc (`8.53 ms`) | **`5,410–5,424` cyc (`113 µs`)** | **Up to 75.5× faster** |
| **Device Authentication Check (`Slot 0 -> 299`)** | `1,656 -> 42,243` cyc (`880 µs`) | **`181 -> 179` cyc (`3.7 µs`)** | **236× faster** |
| **NVM Stack Key Read (`D = 0 -> 150`)** | `2,347 -> 64,817` cyc (`1.35 ms`) | **`302–303` cyc (`6.3 µs`)** | **213.9× faster** |
| **Idempotent NVM State Write (Unchanged `100 B`, 48 writes)** | `100,714` cyc (writes flash 48/48) | **`3,770` cyc (`0 B` flash 48/48)** | **26.7× faster + 0% flash wear** |
| **NVM Compaction Frequency** | Write **#69** (`163.9 ms` stall) | Write **#1,013** (`13.7 ms` stall) | **14.7× lower compaction frequency** |
| **Dynamic Memory Allocation (`malloc` @ `k=64` holes)** | `2,550` cyc | **`218` cyc (O(1) constant time)** | **11.7× faster** |
| **Timer Start Latency (`T=39` timers, 64 heap holes)** | `10,034` cyc (`209.0 µs`) | **`1,448` cyc (`30.2 µs`, heap-independent)** | **6.9× faster** |
| **Inter-Task Event Enqueue (`msgSend`, `Q=64` queued)** | `935` cyc | **`322` cyc (O(1) flat)** | **2.9× faster** |
| **Host Serial Round-Trip (`SYS_PING` @ `115,200` baud)** | `9,790` cyc (reply: `4,921` cyc) | **`4,618` cyc (reply: `816` cyc)** | **53% fewer total / 83% fewer reply** |

### Part 2: Adversarial Resilience & Fault Recovery

| Stress Vector | Legacy TI Z-Stack (`ZNP 3.x`) | ZeroStack `Release Zero (0.9.9-beta.1)` | Measured Improvement |
| :--- | :--- | :--- | :--- |
| **Malformed Secured OTA Frames (12 NWK/APS classes + 3,255 MAC vectors)** | **Remote CPU `HardFault`** (`Precise BusFault` after `143,345–144,412` cyc) | **`0` crashes (`320–6,631` cyc; `790` cyc / `16 µs` routing reject)** | **Zero remote crash + 9.8×–402× lower CPU** |
| **1,000-Frame Cryptographic Replay Flood (`D=150`)** | `143,802` cyc (`3.0 ms`)/replay (**`2.99 s` lockup**) | **`1,550` cyc (`32 µs`)/replay (`32.4 ms` total)** | **92.8× faster** (`30×` faster auth tamper reject) |
| **NOR Flash Brownout Fuzzing (`22,959` HW cuts + `2M` shadow ops)** | `1` verify conflict; torn-record reboot writes **`20,232 B` (`62` erases)** | **`0` corrupted records; torn reboot writes `27 B` (`0` erases)** | **749× lower post-brownout flash write volume** |
| **Hostile UART Framing Abuse (`115,200` baud, 6 scenarios)** | **`8.84 s` serial link blackout** (`44` lost pings on `300 × SOF`) | **`0` lost pings (`3–55 ms` wire-speed recovery, Δheap = 0 B)** | **Zero blackout** (`29 ms` on `300 × SOF`, `3 ms` truncated) |
| **50-Device Unauthenticated Join / TCLK Miss Flood (`D=300`)** | `33.9 ms`/miss (**`1.70 s` total stall**) | **`4 µs` (`208` cyc; `4.3 ms` UART RTT, `0.22 s` total)** | **7.7× faster end-to-end** |
| **1,000-Frame 50-Router Echo Amplification Storm (`D=150`)** | `143,865` cyc (`3.00 ms`)/echo (**`3.00 s` total CPU**) | **`7,076` cyc (`147 µs` p50, `151.16 ms` total CPU)** | **19.9× lower total CPU (20.3× faster/echo)** |
| **64-Frame Post-Outage Unique Broadcast Flood (`D=150`)** | Admits `30 / 64`, `200.25 ms` total, `3.01 ms` shed | **Admits `40 / 64` (`+33%` BTT), `18.87 ms` total, `174 µs` shed** | **10.6× lower CPU time (17.3× faster shed)** |

---

## MCP Tools, Resources & Prompts

### Tools
All tools include read-only, idempotent `ToolAnnotations` (`readOnlyHint=True`, `idempotentHint=True`, `destructiveHint=False`, `openWorldHint=False`):
- **`analyze_zigbee_thread_log(log_text)`**: Matches raw Z2M/ZHA/OpenThread logs against 16+ error signatures (including decimal Z2M MAC codes `225`/`233`/`240`/`241`, `0x10`, `0x11`, `0xC7`, `0xCD`, `0xA7`/`0xAD`, `6000ms` SRSP, and multi-line ZCL MQTT delta-zero telemetry floods).
- **`decode_silicon_register(chip, register_or_addr, hex_value)`**: Decodes TI SimpleLink F2 (`CMD_IEEE_RX`, `CMD_IEEE_CSMA`, `RFC_DBELL`, `RFC_RAM:SRCMATCH`, `VIMS`, `PRCM`) and Silicon Labs EFR32 (`EUSART0_IF`).
- **`check_coordinator_capacity(device_count, sleepy_zed_count, chip_family)`**: Evaluates TI SimpleLink F2 32-slot `SRCMATCH` hardware table utilization, indirect queue quota isolation (`50%` pool cap, max `2` frames/child), zero flash-read stalls during sleepy poll windows, and SRAM heap headroom.
- **`get_zerostack_benchmarks(platform)`**: Returns Part 1 and Part 2 hardware validation benchmarks for `SLZB-06`, `SLZB-06U`, `SLZB-06P7`, `SLZB-06P7U`, `SLZB-06P7V1`, `SLZB-07P7`, `SLZB-06P10`, `SLZB-07P10`, or `"all"`.

### Resources & Prompts
- `zerostack://benchmarks/summary` — Complete Part 1 & Part 2 `DWT->CYCCNT` benchmark dataset.
- `zerostack://hardware/supported-models` — Supported TI SimpleLink F2 hardware matrix for Release Zero (`0.9.9-beta.1`).
- `zerostack://diagnostics/catalog` — Full machine-readable ZeroStack diagnostics catalog.
- Prompt `diagnose_zigbee_log(log_text)` — Structured troubleshooting workflow for Zigbee2MQTT / ZHA logs.

## License

Apache License 2.0 (`Apache-2.0`) — Copyright (c) 2026 SMLIGHT / ZeroStack RF Engineering.
Learn more at [https://smlight.tech/software/zerostack](https://smlight.tech/software/zerostack).
