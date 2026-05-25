# iTek USBCAN macOS Driver

Pure-Python macOS driver for **iTek USBCAN** adapters (VID `0x0471`, PID `0x1200`) with full [python-can](https://python-can.readthedocs.io/) integration.

```python
import can

bus = can.Bus(interface='itek', channel=0, bitrate=500000)
bus.send(can.Message(arbitration_id=0x123, data=[1, 2, 3, 4]))
msg = bus.recv(timeout=1.0)
bus.shutdown()
```

## Why this exists

iTek (Shenzhen iTek Technology) ships USBCAN adapters with Windows-only drivers. There is no official macOS or Linux userspace driver. This project provides one, built entirely from protocol reverse-engineering and a reference C library.

## Installation

```bash
git clone https://github.com/serranom/ITek_USBCAN_macOS.git
cd ITek_USBCAN_macOS
pip install -e .
```

### Dependencies

- **pyusb** >= 1.0 (USB communication via libusb)
- **python-can** >= 4.0 (CAN bus abstraction layer)
- **gmssl** >= 3.2 (SM4 block cipher for device authentication)
- **libusb** (install via `brew install libusb` on macOS)

## Usage

### python-can interface

The driver registers as a python-can plugin. After `pip install -e .`:

```python
import can

# Open adapter on channel 0
bus = can.Bus(interface='itek', channel=0, bitrate=500000)
print(bus.channel_info)
# "iTek USBCAN ch0 @ 500K (SN:06026031049, HW:v513, FW:v791)"

# Send
bus.send(can.Message(arbitration_id=0x7DF, data=[0x02, 0x01, 0x00]))

# Receive
msg = bus.recv(timeout=1.0)

# Cleanup
bus.shutdown()
```

### Direct driver API

```python
from itek_can.driver import ITeKDevice

dev = ITeKDevice(device_index=0)
dev.authenticate()
info = dev.get_board_info()
dev.configure(channel=0, bitrate=500000)
dev.start(channel=0)

# Send a frame
import can
dev.send_message(can.Message(arbitration_id=0x123, data=[1, 2, 3]), channel=0)

# Receive (blocks up to timeout)
msg = dev.recv(channel=0, timeout=1.0)

dev.close()
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `channel` | int | 0 | CAN channel index (0 or 1) |
| `bitrate` | int | 500000 | Bitrate in bps (see note below) |
| `device` | int | 0 | USB device index (for multiple adapters) |
| `mode` | str | "normal" | `"normal"` or `"listen"` (listen-only) |

## Bitrate configuration

The driver reads the device's current bitrate from its SJA1000 bit-timing registers via the `GET_CONFIG` command and reports it in `channel_info`.

On **firmware v791** (and likely other recent versions), the `SET_BITRATE` USB command (`0x12 0x23`) is disabled by the firmware. The device uses whatever bitrate is stored in its flash memory. To change the stored bitrate, use **ECANTools** on Windows.

If you request a bitrate that doesn't match what the device is configured at, the driver logs a warning:

```
WARNING: SET_BITRATE rejected by firmware. Device is configured at 500000 bps
(requested 250000). Use ECANTools on Windows to change the stored bitrate.
```

On older firmware versions, `SET_BITRATE` may work normally, and the driver attempts it first.

### How bitrate readback works

The `GET_CONFIG` response (`0x12 0x06`) contains SJA1000-style bit-timing register bytes at data offsets 6-7:

| Byte | Register | Bit layout |
|------|----------|------------|
| data[7] | BTR0 | `[SJW1 SJW0 \| BRP5..BRP0]` |
| data[6] | BTR1 | `[SAM \| TSEG2_2..TSEG2_0 \| TSEG1_3..TSEG1_0]` |

The CAN peripheral clock is 36 MHz (STM32 APB1 at half of 72 MHz SYSCLK):

```
TQ       = 2 * BRP / 36 MHz
bit_time = (1 + TSEG1 + TSEG2) * TQ
bitrate  = 1 / bit_time
```

For the default 500K configuration: BTR0=`0x03` (BRP=4), BTR1=`0x95` (TSEG1=6, TSEG2=2) gives bit_time = 9 TQ = 2 us = 500,000 bps.

## Hardware details

### Device

| Property | Value |
|----------|-------|
| Vendor ID | `0x0471` |
| Product ID | `0x1200` |
| Manufacturer | iTEK INC. |
| Product | iTEK USBCAN |
| USB speed | Full-speed (12 Mbps) |
| Interface | Single interface, vendor class (0xFF) |
| CAN channels | 1 (firmware reports 1, hardware may have 2) |

### USB endpoints

| Endpoint | Type | Direction | Max packet | Purpose |
|----------|------|-----------|------------|---------|
| 0x01 | Interrupt | OUT | 64 B | Command TX |
| 0x81 | Interrupt | IN | 64 B | Command responses + TX ACK |
| 0x02 | Bulk | OUT | 64 B | CAN frame TX |
| 0x82 | Bulk | IN | 64 B | CAN frame RX |

Note: A newer hardware revision (VID `0x1FC9`, PID `0x0100`) adds EP `0x83` for RX and uses a completely different protocol (`0x11` prefix, 51-byte fixed commands). This driver does not support that device.

## Protocol reference

### Authentication (SM4)

The device requires SM4 (Chinese national standard block cipher) authentication before any CAN operations. The key is hardcoded in the firmware:

```
Key: b"itekon2012usbcan" (16 bytes, ASCII)
```

Sequence:
1. Generate 16 random bytes (challenge)
2. Send `[0x13, 0xB0, 0x11, 0x00] + challenge` (20 bytes) on EP 0x01
3. Compute `SM4_ECB_Encrypt(key, challenge)` locally
4. Read response from EP 0x81
5. Verify `response[4:20]` matches local ciphertext

### Command format

All commands use the interrupt endpoint pair (EP 0x01 OUT / EP 0x81 IN).

**Request:** `[prefix, sub_cmd, data_len, data_bytes...]`

| Prefix | Usage |
|--------|-------|
| `0x12` | Configuration and query commands |
| `0x13` | Authentication |

**Response:** `[prefix, sub_cmd, status_byte, data...]`

- `status_byte & 0x80 != 0` = success; lower 7 bits = data length
- `status_byte & 0x80 == 0` = NACK (command rejected)

### Command table

| Command | Bytes | Description | Status on FW v791 |
|---------|-------|-------------|-------------------|
| Auth | `13 B0 11 00 [challenge×16]` | SM4 authentication | Working |
| HW version | `12 01 01 00` | Hardware version (16-bit LE) | Working |
| FW version | `12 12 01 00` | Firmware version (16-bit LE) | Working |
| CAN count | `12 13 01 00` | Number of CAN channels | Working |
| Serial | `12 14 01 00` | Serial number string | Working |
| HW type | `12 15 01 00` | Hardware type string | Working |
| GET_CONFIG | `12 06 01 00` | Read channel config (10 bytes) | Working |
| GET_STATUS | `12 0D 01 00` | Read CAN bus status | Working |
| GET_CAPS | `12 80 01 00` | Read device capabilities | Working |
| Start CAN | `12 0E 02 00 [ch<<4]` | Start a CAN channel | Working |
| Stop CAN | `12 0F 02 00 [ch<<4]` | Stop/reset a CAN channel | Working |
| Set bitrate | `12 23 06 00 [mode_ch] [BTR×4]` | Configure bitrate | **NACK** |
| Set filter | `12 24 0B [idx] [flags] ...` | Configure acceptance filter | **NACK** |

### CAN frame wire format (19 bytes)

```
Offset  Size  Field
------  ----  -----
0-3     4     TimeStamp (big-endian, milliseconds)
4       1     TimeFlag (0=unused, 1=valid timestamp)
5       1     SendType (0=normal, 1=single-shot)
6       1     Flags:
                bit 7 = ExternFlag (1=extended 29-bit ID)
                bit 6 = RemoteFlag (1=RTR frame)
                bit 4 = CANIndex (0=ch0, 1=ch1)
                bits 0-3 = DLC (0-8)
7-10    4     CAN ID (little-endian)
11-18   8     Data bytes (zero-padded)
```

**TX:** Up to 3 frames concatenated per bulk write (57 bytes max) on EP 0x02. After each write, the device sends a TX ACK on interrupt EP 0x81.

**RX:** Background thread polls EP 0x82 with 10ms timeout. Received data is split into 19-byte frames, routed to per-channel queues by the CANIndex bit.

### Bitrate register values

These 32-bit values are sent big-endian in the `SET_BITRATE` command (on firmware versions that support it):

| Rate | Value | Rate | Value |
|------|-------|------|-------|
| 5K | `0x00450257` | 250K | `0x00120017` |
| 10K | `0x00120257` | 400K | `0x00160008` |
| 20K | `0x0012012B` | 500K | `0x0012000B` |
| 40K | `0x00780031` | 666K | `0x00240005` |
| 50K | `0x0067002C` | 800K | `0x00240004` |
| 80K | `0x004B0018` | 1000K | `0x00120005` |
| 100K | `0x0012003B` | | |
| 125K | `0x0012002F` | | |
| 200K | `0x0027000E` | | |

### Initialization sequence

```
1. Find device by VID/PID
2. Claim USB interface 0
3. SM4 authentication (0x13 0xB0)
4. Read board info (HW/FW version, serial, etc.)
5. Attempt SET_BITRATE (0x12 0x23) — may NACK on newer firmware
6. Attempt SET_FILTER x14 (0x12 0x24) — may NACK on newer firmware
7. Read back actual bitrate from GET_CONFIG (0x12 0x06)
8. Start CAN channel (0x12 0x0E)
9. Launch background RX thread polling EP 0x82
```

## Architecture

```
itek_can/
  __init__.py       Exports ITeKBus
  sm4.py            SM4 ECB cipher wrapper (gmssl)
  protocol.py       Command builders, frame pack/unpack, bitrate tables,
                    response parsers, bitrate readback from BTR registers
  driver.py         ITeKDevice class — USB I/O, auth, config, TX/RX,
                    background receive thread
  bus.py            ITeKBus(can.BusABC) — python-can plugin adapter

tests/
  test_driver.py          Integration test (full lifecycle against live device)
  test_bitrate.py         Exhaustive bitrate value probe
  test_new_protocol.py    New protocol (0x11) probe (all timeout on this HW)
  test_probe_commands.py  Full sub-command scan (0x00-0xFF)
  test_sequences.py       Creative command sequence tests
  test_just_run.py        Skip-config smoke test (auth + start + TX/RX)
  test_start_bitrate.py   Extended START command analysis
  test_read_bitrate.py    GET_CONFIG bitrate register analysis
  test_exact_old_sequence.py  Exact old C driver lifecycle replication
  test_dangerous_cmds.py  Probing commands that crash the device
  test_write_config.py    Attempts to write config via various commands
  capture_protocol.py     USB protocol capture/analysis tool
```

## How this was built

This driver was created through pure reverse engineering, without access to firmware source code or official protocol documentation.

### Sources used

1. **iTekon-usb** — A 2018 open-source C library by "grool" (GitHub: LetMax6831/iTekon-usb) targeting the same VID/PID. This provided the initial protocol understanding: SM4 authentication, command format, frame layout, and bitrate tables.

2. **iTekCANFD SDK** — The manufacturer's SDK package containing a newer C library (`iTekCANFD.c`) and a Linux kernel SocketCAN driver (`itekon_usbcan.c`). These target a *different* device (VID `0x1FC9`, PID `0x0100`) with a completely different protocol. Analyzing the kernel driver confirmed the two devices are incompatible and revealed the newer bitrate register format.

3. **Live device probing** — Extensive testing against the physical adapter to determine which commands the firmware (v791) actually supports. Key discoveries:
   - The new protocol (`0x11` prefix, 51-byte commands) is completely unsupported on this hardware — all commands timeout
   - The old `SET_BITRATE` (`0x12 0x23`) and `SET_FILTER` (`0x12 0x24`) commands are rejected with NACK by firmware v791, despite being documented in the 2018 C library
   - The `GET_CONFIG` response contains SJA1000-style BTR0/BTR1 registers that encode the current bitrate
   - The CAN peripheral clock is 36 MHz (deduced by matching BTR register values to standard bitrates — only 36 MHz produces exact matches for 500K)
   - Sending `0x12 0x05` with arbitrary data crashes the device firmware (USB disconnect + automatic reset)

### What was tested and ruled out

The following approaches to setting the bitrate were exhaustively tested and all failed on firmware v791:

- All 15 old BTR values and all 14 new BTR values with `0x12 0x23`
- Every `data_len` variant (0x01 through 0x0A) with `0x12 0x23`
- Sub-commands 0x20 through 0x30 with bitrate payloads
- Full 0x00-0xFF sub-command scan with 6-byte bitrate payloads
- Raw SJA1000 BTR0/BTR1 bytes in various positions
- 64-byte padded commands
- Bitrate embedded in the START command (accepted but silently ignored)
- Exact old C driver claim/release/RX-thread lifecycle replication
- Writing via GET_CONFIG (0x06) as a setter
- 0xA* and 0xEE commands with config payloads
- USB vendor-specific control transfers
- Commands on the bulk endpoint instead of interrupt

## Known limitations

- **Bitrate cannot be changed via USB on firmware v791.** The device uses flash-stored settings configured by ECANTools (Windows only).
- **Classic CAN only.** This hardware does not support CAN FD.
- **macOS and Linux only.** Requires libusb (no Windows support — use the vendor's driver there).
- **Not tested with actual CAN bus traffic yet.** Authentication, command/response, TX frame submission, and RX thread are all verified against the live device, but end-to-end CAN communication requires connecting to a CAN bus at the matching bitrate.

## License

This is an independent reverse-engineering effort. The protocol knowledge comes from the open-source iTekon-usb library (no license specified) and direct device probing. No proprietary code or firmware was used.
