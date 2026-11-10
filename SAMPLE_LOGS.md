# Sample Zigbee2MQTT & ZHA Crash Logs for AI Diagnostic Testing

Use these realistic Zigbee2MQTT (`z2m`) and Home Assistant ZHA logs to test the **ZeroStack RF Diagnostics MCP Server (`zerostack-mcp`)** (`https://github.com/zerostack-rf/zerostack-mcp`) or the **ZeroStack Interactive Web Log Analyzer** (`https://smlight-tech.github.io/zerostack/`).

> **ZeroStack Official Overview & Firmware (`Release Zero (0.9.9-beta.1)`)**: [https://smlight.tech/software/zerostack](https://smlight.tech/software/zerostack)

---

## Prompt 1: Tuya Smart Plug Telemetry Flood + `6000ms` SRSP Timeout (`SLZB-06` / `CC2652P`)

> **"My Zigbee2MQTT network on an SLZB-06 (CC2652P) keeps freezing every evening when my Tuya smart plugs are active, and then crashes with `SRSP - AF - dataRequest after 6000ms`. Use `analyze_zigbee_thread_log` and `get_zerostack_benchmarks` to explain what is happening on the silicon and how ZeroStack Release Zero (`0.9.9-beta.1`) fixes it:"**

```text
info  2026-03-29 14:21:01: MQTT publish: topic 'zigbee2mqtt/living_room_plug_1', payload '{"current":0.42,"energy":12.4,"power":96,"voltage":231}'
info  2026-03-29 14:21:01: MQTT publish: topic 'zigbee2mqtt/living_room_plug_1', payload '{"current":0.42,"energy":12.4,"power":96,"voltage":231}'
info  2026-03-29 14:21:01: MQTT publish: topic 'zigbee2mqtt/living_room_plug_1', payload '{"current":0.42,"energy":12.4,"power":96,"voltage":231}'
info  2026-03-29 14:21:02: MQTT publish: topic 'zigbee2mqtt/kitchen_plug_2', payload '{"current":1.15,"energy":44.1,"power":265,"voltage":230}'
info  2026-03-29 14:21:02: MQTT publish: topic 'zigbee2mqtt/kitchen_plug_2', payload '{"current":1.15,"energy":44.1,"power":265,"voltage":230}'
error 2026-03-29 14:21:08: Publish 'set' 'state' to 'hallway_light' failed: 'Error: Data request failed with error: 'No network route' (205)'
error 2026-03-29 14:21:14: Adapter disconnected (Error: SRSP - AF - dataRequest after 6000ms)
```

---

## Prompt 2: Large Mesh (`180` Devices, `55` Aqara Sleepy Sensors) + `MAC no ack (233)`, `(240)`, `(241)`, `(225)`, `0x11` & `0x10`

> **"I have 180 Zigbee devices (including 55 battery-powered Aqara sensors) on an `SLZB-06P7`. Every time a group scene triggers, I get `MAC transaction expired (240)`, `MAC transaction overflow (241)`, `MAC channel access failure (225)`, `MAC no ack (233)` / `<sl_Status.MAC_NO_ACK_RECEIVED: 233>`, `0x11: BUFFER_FULL`, and `0x10: MEM_ERROR`. Run `analyze_zigbee_thread_log` and `check_coordinator_capacity` for `SLZB-06P7`."**

```text
error 2026-03-29 19:04:11: Publish 'set' 'state' to 'bedroom_sensor' failed: 'DataConfirm error: MAC transaction expired (240)'
error 2026-03-29 19:04:11: Publish 'get' 'state' to 'window_sensor_14' failed: 'DataConfirm error: MAC transaction overflow (241)'
error 2026-03-29 19:04:12: Publish 'set' 'brightness' to 'living_room_group' failed: 'SREQ '--> AF - dataRequest' failed with status '(0x10: MEM_ERROR)''
error 2026-03-29 19:04:12: Publish 'set' 'color_temp' to 'hallway_spots' failed: 'SREQ '--> AF - dataRequest' failed with status '(0x11: BUFFER_FULL)''
error 2026-03-29 19:04:13: Publish 'set' 'state' to 'patio_floodlight' failed: 'DataConfirm error: MAC channel access failure (225)'
error 2026-03-29 19:04:13: Publish 'set' 'state' to 'kitchen_spot_3' failed: 'DataConfirm error: 'MAC no ack' (233)'
error 2026-03-29 19:04:13: zigpy.exceptions.DeliveryError: [0x8a42:1:0x0006]: Message send failure: <sl_Status.MAC_NO_ACK_RECEIVED: 233>
error 2026-03-29 19:04:14: Publish 'set' 'state' to 'office_lamp' failed: 'DataConfirm failed with status: 0xC7 (NWK_TABLE_FULL)'
```

---

## Prompt 3: Device Pairing / Interview Failure at 150+ Devices (`TCLK` Timeout / `0xa7: APS_NO_ACK`)

> **"Now that my mesh has 165 devices, pairing any new Zigbee 3.0 device fails with `Failed to interview` and `APS no ack (167)` / `0xa7`. Use `analyze_zigbee_thread_log` and `get_zerostack_benchmarks` to explain the root cause."**

```text
error 2026-03-29 21:15:40: Failed to interview '0xa4c1389911223344', device has not successfully been paired
warn  2026-03-29 21:15:41: Request-Key timeout / Verify-Key timeout (0xa7: APS_NO_ACK / 'APS no ack' (167))
error 2026-03-29 21:15:47: zh:zstack:znp: (Error: SRSP - ZDO - extRouteDisc after 6000ms)
```