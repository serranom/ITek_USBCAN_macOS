# iTek USBCAN — USB Protocol Reference

Comprehensive command reference for the iTek USBCAN adapter
(VID `0x0471` / PID `0x1200`), reconciled against the **vendor's own
`usbcan.dll`** shipped in CANalyst 1.1.9.17.

## Provenance

Two independent sources feed this document:

1. **Live reverse-engineering** of the physical adapter (FW v791, HW v513) — the
   original basis for this driver (SM4 auth, endpoint map, 19-byte frame format).
2. **Static disassembly of `usbcan.dll`** (the WinUSB kernel DLL inside CANalyst
   1.1.9.17, PE32 x86). This is the **vendor's ground truth** for the `0x12`
   command family and, critically, for how the CAN **bitrate** is actually set.

Where the two disagree, the divergence is called out explicitly below. The
`usbcan.dll` command set is a **subset** of what FW v791 implements: the DLL
does *not* use SM4 auth or the config-readback command, but the device supports
them — so "not in the DLL" never means "not supported by the device".

> ⚠️ **The `0x12 0x03` bitrate path below is derived from disassembly and is
> pending on-hardware confirmation on the HIL bench.** Everything marked
> ✅ *confirmed* is corroborated by live device behaviour; everything marked
> 🔬 *RE-derived* comes from the DLL only.

## Transport

WinUSB (Windows) / libusb (macOS via this driver). Interface 0.

| Endpoint | Type | Dir | Purpose |
|---|---|---|---|
| `0x01` | Interrupt | OUT | **Command** TX |
| `0x81` | Interrupt | IN  | Command responses + TX ACK |
| `0x02` | Bulk | OUT | CAN frame TX |
| `0x82` | Bulk | IN  | CAN frame RX |

The DLL sends each command on EP `0x01` and reads the reply on EP `0x81`,
serialized under a critical section (`sub_10001b80`). This driver mirrors that
with a per-device lock around the `0x01`/`0x81` pair.

## Command framing

All control commands share the header:

```
byte 0 : 0x12          class (config/command)   [0x13 for SM4 auth]
byte 1 : <sub-command>
byte 2 : <payload length>
byte 3 : <flag / 0x00>
byte 4.. : payload
```

Responses echo on EP `0x81`; **success is indicated by `resp[2]` having bit 7
set** (`resp[2] & 0x80 != 0`). Observed success markers: InitCAN → `0x81`,
FW-version → `0x83`, CAN-count → `0x82` (i.e. `0x80 | data_len`).

## Command table

### Open handshake — board info  ✅ *confirmed (matches DLL `sub_15e0`; returns real values on FW v791)*

Sent in order at device open; each reply populates the `VCI_BOARD_INFO` struct.

| Sub | Bytes sent | Reply → field | Meaning |
|---|---|---|---|
| `0x01` | `12 01 01 01` | u16 → `hw_Version` | HW version |
| `0x12` | `12 12 01 01` | u16 → `fw_Version` (marker `0x83`) | FW version |
| `0x13` | `12 13 01 00` | u8 → `can_Num` (marker `0x82`) | # CAN channels |
| `0x14` | `12 14 01 00` | str → `str_Serial_Num[20]` | serial |
| `0x15` | `12 15 01 00` | str[len=`resp[2]&0x0F − 1`] → `str_hw_Type[40]` | HW type string |

*(This driver sends byte 3 = `0x00` for `0x01`/`0x12`; the DLL sends `0x01`.
Both work on FW v791 — byte 3 is effectively don't-care here.)*

### CAN channel init + start

| Op | Sub | Bytes sent | Success | Source |
|---|---|---|---|---|
| **Set timing + mode (bitrate!)** | `0x03` | `12 03 04 00  CM  BTR0 BTR1` | `resp[2]==0x81` | 🔬 RE (`VCI_InitCAN`) |
| **Set acceptance filter** | `0x04` | `12 04 0a 00  CM2  AccCode[BE4] AccMask[BE4]` | `resp[2]&0x80` | 🔬 RE (`VCI_InitCAN`) |
| Start channel | `0x0E` | `12 0e 02 00  (ch<<4)` | `resp[2]&0x80` | ✅ confirmed |
| Reset / stop channel | `0x0F` | `12 0f 02 00  (ch<<4)` | — | ✅ confirmed |

- `CM`  (InitCAN mode byte) = `(0x80 if listen-only) | (0x10 if channel 1)`
- `CM2` (filter mode byte)  = `(0x40 if listen-only) | (0x10 if channel 1)`
- Accept-all filter = `AccCode 0x00000000`, `AccMask 0xFFFFFFFF`.

`BTR0`/`BTR1` are **SJA1000-style bit-timing registers** (ZLG `Timing0`/`Timing1`
convention). Standard 16 MHz table:

| bitrate | BTR0 | BTR1 |
|---|---|---|
| 1 Mbps | `0x00` | `0x14` |
| 500 kbps | `0x00` | `0x1C` |
| **250 kbps** | **`0x01`** | **`0x1C`** |
| 125 kbps | `0x03` | `0x1C` |
| 100 kbps | `0x04` | `0x1C` |
| 50 kbps | `0x09` | `0x1C` |
| 20 kbps | `0x18` | `0x1C` |
| 10 kbps | `0x31` | `0x1C` |

### Device superset — used by this driver, *not* by `usbcan.dll`

| Op | Bytes | Status |
|---|---|---|
| SM4 auth | `13 B0 11 00  <challenge[16]>` → verify `resp[4:20]==SM4_ECB("itekon2012usbcan", challenge)` | ✅ required by FW v791 |
| Read config (bitrate readback) | `12 06 01 00` → SJA1000 BTR bytes at data[6]/data[7] | ✅ works on FW v791 |
| Read status | `12 0D 01 00` | ⚠️ used by driver, not seen in DLL |

### ❌ Superseded / incorrect (were in this driver, from the 2018 "grool" C ref)

| Op | Was | Reality |
|---|---|---|
| Set bitrate | `0x12 0x23` + 4-byte timing word | **Not implemented — NACKs.** Use `0x12 0x03` (InitCAN) above. |
| Set filter | `0x12 0x24` | Use `0x12 0x04` above. |

## CAN frame wire format (bulk EP `0x02`/`0x82`)

19 bytes, fixed. Up to **3 frames per bulk write** (57 bytes) — confirmed by the
DLL `VCI_Transmit` (it divides the frame count by 3 and batches).

```
[0:4]  TimeStamp  (big-endian, ms)
[4]    TimeFlag   (0=unused, 1=valid)
[5]    SendType   (0=normal, 1=single-shot)
[6]    Flags: bit7=ExtID  bit6=RTR  bit4=CANIndex  bits0-3=DLC
[7:11] CAN ID     (little-endian)
[11:19] Data      (zero-padded)
```

*(Internally the DLL uses a 0x48-byte `VCI_CAN_OBJ`; this is the packed on-wire
form after conversion.)*

## Practical consequence for the BKPK HIL bench

The bench runs **250 kbps classic CAN**. This adapter ships flash-defaulted to
**500 kbps**. The old belief — "bitrate can only be changed with ECANTools on
Windows" — was a side effect of sending the wrong opcode (`0x12 0x23`, which
NACKs). The vendor tool sets the rate every session via **`0x12 0x03`**, so this
driver can set 250 kbps directly from macOS: send
`12 03 04 00 00 01 1C` (channel 0, normal, 250k), then start. Confirm on the
bench against a known-250k node before trusting it.
