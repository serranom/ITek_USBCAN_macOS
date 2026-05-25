#!/usr/bin/env python3
"""
Probe the device to determine its current bitrate configuration.

Strategy:
1. Read GET_CONFIG (0x06) and all other info commands — look for bitrate encoding
2. Try extended START with different BTR values, check if GET_CONFIG changes
3. Check if any 0xA* commands return config that includes bitrate
4. Try reading back with GET_REFERENCE-style commands
"""

import os
import struct
import sys

import usb.core
import usb.util
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

dev = usb.core.find(idVendor=0x0471, idProduct=0x1200)
if not dev:
    print("Device not found"); sys.exit(1)
try:
    if dev.is_kernel_driver_active(0):
        dev.detach_kernel_driver(0)
except (usb.core.USBError, NotImplementedError):
    pass
usb.util.claim_interface(dev, 0)
print(f"Device: {dev.manufacturer} {dev.product}")


def send_recv(data, timeout=2000):
    dev.write(0x01, data, timeout=timeout)
    return bytes(dev.read(0x81, 64, timeout=timeout))


def auth():
    challenge = os.urandom(16)
    sm4 = CryptSM4()
    sm4.set_key(b"itekon2012usbcan", SM4_ENCRYPT)
    expected = sm4.crypt_ecb(challenge)
    resp = send_recv(bytes([0x13, 0xB0, 0x11, 0x00]) + challenge)
    return resp[4:20] == expected[:16]


def stop_can():
    try: send_recv(bytes([0x12, 0x0F, 0x02, 0x00, 0x00]))
    except: pass


def hexdump(data, prefix="  "):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"{prefix}{i:3d}: {hex_str:48s}  {ascii_str}")


assert auth(), "Auth failed!"
print("Auth OK\n")

# ── 1: Read ALL info commands in detail ──────────────────────────────────

print("=" * 60)
print("1. All info/query commands — full hex dumps")
print("=" * 60)

commands = [
    (0x01, "HW_VERSION"),
    (0x04, "CMD_04"),
    (0x06, "GET_CONFIG"),
    (0x0C, "CMD_0C"),
    (0x0D, "GET_STATUS"),
    (0x12, "FW_VERSION"),
    (0x13, "CAN_COUNT"),
    (0x14, "SERIAL_NUM"),
    (0x15, "HW_TYPE"),
    (0x80, "GET_CAPS"),
    (0xA1, "CMD_A1"),
    (0xA2, "CMD_A2"),
    (0xA3, "CMD_A3"),
    (0xA7, "CMD_A7"),
    (0xA9, "CMD_A9"),
    (0xEE, "CMD_EE"),
]

for sub, name in commands:
    try:
        resp = send_recv(bytes([0x12, sub, 0x01, 0x00]))
        ok = (resp[2] & 0x80) != 0 if len(resp) >= 3 else False
        data_len = resp[2] & 0x7F if ok else 0
        print(f"\n  0x{sub:02X} ({name}) — {'OK' if ok else 'NACK'}, data_len={data_len}")
        print(f"  Raw ({len(resp)}B): {resp.hex()}")
        if len(resp) > 3:
            hexdump(resp[3:], prefix="    ")
    except usb.core.USBError as e:
        print(f"\n  0x{sub:02X} ({name}) — ERROR: {e}")

# ── 2: GET_CONFIG with channel parameter ─────────────────────────────────

print("\n" + "=" * 60)
print("2. GET_CONFIG with different payloads")
print("=" * 60)

auth()

for payload in [
    bytes([0x00]),
    bytes([0x00, 0x00]),
    bytes([0x10]),       # channel 1
    bytes([0x00, 0x01]),
    bytes([0x01]),
]:
    dl = len(payload)
    cmd = bytes([0x12, 0x06, dl, 0x00]) + payload
    try:
        resp = send_recv(cmd, timeout=500)
        print(f"  payload={payload.hex():10s} -> {resp.hex()}")
    except usb.core.USBTimeoutError:
        print(f"  payload={payload.hex():10s} -> TIMEOUT")

# ── 3: Try GET_CONFIG before/after START with different BTR ──────────────

print("\n" + "=" * 60)
print("3. Does GET_CONFIG change if we stop→start with extended START?")
print("=" * 60)

auth()

# Baseline
resp_before = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  Before start:    {resp_before.hex()}")

# Start with no bitrate (simple start)
stop_can()
auth()
send_recv(bytes([0x12, 0x0E, 0x02, 0x00, 0x00]))
resp_simple = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  After simple:    {resp_simple.hex()}")

# Stop, re-auth, start with 250K new BTR
stop_can()
auth()
cmd = bytes([0x12, 0x0E, 0x06, 0x00, 0x00, 0x00]) + struct.pack(">I", 0x00091302)
send_recv(cmd)
resp_250k = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  After ext 250K:  {resp_250k.hex()}")

# Stop, re-auth, start with 1M new BTR
stop_can()
auth()
cmd = bytes([0x12, 0x0E, 0x06, 0x00, 0x00, 0x00]) + struct.pack(">I", 0x00040702)
send_recv(cmd)
resp_1m = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  After ext 1M:    {resp_1m.hex()}")

# Stop, re-auth, start with 500K OLD BTR
stop_can()
auth()
cmd = bytes([0x12, 0x0E, 0x06, 0x00, 0x00, 0x00]) + struct.pack(">I", 0x0012000B)
send_recv(cmd)
resp_500k_old = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  After ext old500K:{resp_500k_old.hex()}")

all_same = (resp_before == resp_simple == resp_250k == resp_1m == resp_500k_old)
print(f"\n  All identical? {all_same}")
if not all_same:
    print("  >>> CONFIG CHANGES — extended START may be setting bitrate!")

stop_can()

# ── 4: Parse GET_CONFIG bytes for possible BTR values ────────────────────

print("\n" + "=" * 60)
print("4. Analyzing GET_CONFIG response bytes")
print("=" * 60)

auth()
resp = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  Raw: {resp.hex()}")

# Parse: [12 06 8a 00 01 00 00 00 00 95 03 00 00]
# Header: 12 06 8a (OK, data_len=10)
# Data starts at byte 3
if len(resp) >= 3 and (resp[2] & 0x80):
    data = resp[3:]
    print(f"  Data ({len(data)}B): {data.hex()}")

    # Try various interpretations of 4-byte windows
    print("\n  Possible 4-byte values (big-endian):")
    for i in range(len(data) - 3):
        val = struct.unpack_from(">I", data, i)[0]
        if val != 0:
            print(f"    offset {i}: 0x{val:08X} ({val})")

    print("\n  Possible 4-byte values (little-endian):")
    for i in range(len(data) - 3):
        val = struct.unpack_from("<I", data, i)[0]
        if val != 0:
            print(f"    offset {i}: 0x{val:08X} ({val})")

    print("\n  Possible 2-byte values:")
    for i in range(len(data) - 1):
        val_be = struct.unpack_from(">H", data, i)[0]
        val_le = struct.unpack_from("<H", data, i)[0]
        if val_be != 0:
            print(f"    offset {i}: BE=0x{val_be:04X} ({val_be})  LE=0x{val_le:04X} ({val_le})")

    # Check against known BTR values
    print("\n  Checking against known bitrate tables:")

    OLD_BTRS = {
        "5K": 0x00450257, "10K": 0x00120257, "20K": 0x0012012B,
        "50K": 0x0067002C, "100K": 0x0012003B, "125K": 0x0012002F,
        "250K": 0x00120017, "500K": 0x0012000B, "1000K": 0x00120005,
    }
    NEW_BTRS = {
        "5K": 0x01F31302, "10K": 0x00F91302, "20K": 0x007C1302,
        "50K": 0x00311302, "100K": 0x00181302, "125K": 0x00131302,
        "250K": 0x00091302, "500K": 0x00070A02, "1000K": 0x00040702,
    }

    for i in range(len(data) - 3):
        val_be = struct.unpack_from(">I", data, i)[0]
        val_le = struct.unpack_from("<I", data, i)[0]
        for name, btr in OLD_BTRS.items():
            if val_be == btr:
                print(f"    MATCH at offset {i} (BE): OLD {name} = 0x{btr:08X}")
            if val_le == btr:
                print(f"    MATCH at offset {i} (LE): OLD {name} = 0x{btr:08X}")
        for name, btr in NEW_BTRS.items():
            if val_be == btr:
                print(f"    MATCH at offset {i} (BE): NEW {name} = 0x{btr:08X}")
            if val_le == btr:
                print(f"    MATCH at offset {i} (LE): NEW {name} = 0x{btr:08X}")

# ── 5: Try 0xA* commands with specific queries ──────────────────────────

print("\n" + "=" * 60)
print("5. Probing 0xA* commands for config/bitrate data")
print("=" * 60)

auth()

# These commands returned OK in earlier probing
for sub in [0xA1, 0xA2, 0xA3, 0xA7, 0xA9, 0xEE]:
    for dl in [0x01, 0x02, 0x04]:
        if dl == 1:
            payload = bytes([0x00])
        elif dl == 2:
            payload = bytes([0x00, 0x00])
        else:
            payload = bytes(dl)
        cmd = bytes([0x12, sub, dl, 0x00]) + payload
        try:
            resp = send_recv(cmd, timeout=500)
            ok = len(resp) >= 3 and (resp[2] & 0x80)
            if ok and len(resp) > 4:
                data_len = resp[2] & 0x7F
                print(f"  0x{sub:02X} dl={dl}: data_len={data_len} resp={resp.hex()}")
        except (usb.core.USBTimeoutError, usb.core.USBError):
            pass

# ── 6: SJA1000 BTR analysis of the 0x95 0x03 bytes ─────────────────────

print("\n" + "=" * 60)
print("6. SJA1000 bit timing analysis of config bytes")
print("=" * 60)

# From GET_CONFIG, the potentially interesting bytes are 0x95 and 0x03
# at data offsets 6 and 7
byte0, byte1 = 0x95, 0x03

# SJA1000 BTR0 format: [SJW1 SJW0 BRP5 BRP4 BRP3 BRP2 BRP1 BRP0]
# SJA1000 BTR1 format: [SAM TSEG2.2 TSEG2.1 TSEG2.0 TSEG1.3 TSEG1.2 TSEG1.1 TSEG1.0]

# Try as BTR0=0x95, BTR1=0x03
sjw = ((byte0 >> 6) & 0x03) + 1
brp = (byte0 & 0x3F) + 1
sam = (byte1 >> 7) & 0x01
tseg2 = ((byte1 >> 4) & 0x07) + 1
tseg1 = (byte1 & 0x0F) + 1
bit_time = 1 + tseg1 + tseg2
print(f"  If BTR0=0x{byte0:02X} BTR1=0x{byte1:02X} (SJA1000):")
print(f"    SJW={sjw}, BRP={brp}, SAM={sam}, TSEG1={tseg1}, TSEG2={tseg2}")
print(f"    Bit time = {bit_time} TQ")
for fosc in [8_000_000, 12_000_000, 16_000_000, 20_000_000, 24_000_000,
             36_000_000, 40_000_000, 48_000_000, 72_000_000, 80_000_000]:
    tq = 2 * brp / fosc
    bitrate = 1.0 / (bit_time * tq)
    if 4000 < bitrate < 1_100_000:
        print(f"    f_osc={fosc/1e6:.0f}MHz -> TQ={tq*1e9:.1f}ns -> bitrate={bitrate:.0f} bps")

# Try swapped: BTR0=0x03, BTR1=0x95
print(f"\n  If BTR0=0x{byte1:02X} BTR1=0x{byte0:02X} (swapped):")
sjw = ((byte1 >> 6) & 0x03) + 1
brp = (byte1 & 0x3F) + 1
sam = (byte0 >> 7) & 0x01
tseg2 = ((byte0 >> 4) & 0x07) + 1
tseg1 = (byte0 & 0x0F) + 1
bit_time = 1 + tseg1 + tseg2
print(f"    SJW={sjw}, BRP={brp}, SAM={sam}, TSEG1={tseg1}, TSEG2={tseg2}")
print(f"    Bit time = {bit_time} TQ")
for fosc in [8_000_000, 12_000_000, 16_000_000, 20_000_000, 24_000_000,
             36_000_000, 40_000_000, 48_000_000, 72_000_000, 80_000_000]:
    tq = 2 * brp / fosc
    bitrate = 1.0 / (bit_time * tq)
    if 4000 < bitrate < 1_100_000:
        print(f"    f_osc={fosc/1e6:.0f}MHz -> TQ={tq*1e9:.1f}ns -> bitrate={bitrate:.0f} bps")

# ── 7: Try to get full GET_CAPS and see if bitrate is listed ─────────────

print("\n" + "=" * 60)
print("7. GET_CAPS (0x80) full dump")
print("=" * 60)

auth()

resp = send_recv(bytes([0x12, 0x80, 0x01, 0x00]))
print(f"  Raw ({len(resp)}B): {resp.hex()}")
if len(resp) > 3:
    hexdump(resp)

# ── 8: Read GET_CONFIG with larger read buffer ───────────────────────────

print("\n" + "=" * 60)
print("8. Try reading more data from GET_CONFIG")
print("=" * 60)

auth()

# Maybe the response has more data than we're reading
cmd = bytes([0x12, 0x06, 0x01, 0x00])
dev.write(0x01, cmd, timeout=2000)
# Try reading with a larger buffer
resp = bytes(dev.read(0x81, 64, timeout=2000))
print(f"  Full 64B read ({len(resp)}B): {resp.hex()}")
hexdump(resp)

stop_can()
usb.util.release_interface(dev, 0)
print("\nDone.")
