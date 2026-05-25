#!/usr/bin/env python3
"""
Careful probing of commands that caused device crash.
0x12 0x05 with bitrate payload crashed the device.
0x12 0x03 with bitrate payload returned OK before the crash.

Let's check if config changed, then carefully probe 0x03 and 0x05.
"""

import os
import struct
import sys
import time

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


assert auth(), "Auth failed!"
print("Auth OK\n")

# ── Check if config changed from the crash ───────────────────────────────

print("=" * 60)
print("1. Config after device reset")
print("=" * 60)

resp = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  GET_CONFIG: {resp.hex()}")
# Expected: 12068a00010000000094030000 or 12068a00010000000095030000

# Parse BTR
if len(resp) >= 11:
    btr1 = resp[9]
    btr0 = resp[10]
    brp = (btr0 & 0x3F) + 1
    tseg1 = (btr1 & 0x0F) + 1
    tseg2 = ((btr1 >> 4) & 0x07) + 1
    bit_time = 1 + tseg1 + tseg2
    bitrate = 36_000_000 / (2 * brp * bit_time)
    print(f"  BTR0=0x{btr0:02X} BTR1=0x{btr1:02X} -> {bitrate:.0f} bps")

# ── Probe 0x03 carefully ────────────────────────────────────────────────

print("\n" + "=" * 60)
print("2. Careful probe of 0x03 (returned OK with bitrate payload)")
print("=" * 60)

auth()

# First, what does 0x03 return with minimal payload?
resp = send_recv(bytes([0x12, 0x03, 0x01, 0x00]))
print(f"  0x03 dl=1: {resp.hex()}")

# Now send 0x03 with a specific BTR value for 125K
# BTR0=0x0F (BRP=16), BTR1=0x95 (SAM=1, TSEG2=2, TSEG1=6)
# 36MHz / (2*16*9) = 125,000 bps
btr_125k = bytes([0x0F, 0x95])

# Read config before
resp_before = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"\n  Config BEFORE: {resp_before.hex()}")

# Try 0x03 with SJA1000 BTR format
for desc, cmd in [
    ("0x03 dl=2 BTR0+BTR1",  bytes([0x12, 0x03, 0x02, 0x00, 0x0F, 0x95])),
    ("0x03 dl=3 ch+BTR",     bytes([0x12, 0x03, 0x03, 0x00, 0x00, 0x0F, 0x95])),
]:
    try:
        resp = send_recv(cmd, timeout=1000)
        ok = len(resp) >= 3 and (resp[2] & 0x80)
        print(f"  {desc}: {'OK' if ok else 'NACK'} resp={resp.hex()}")
    except usb.core.USBTimeoutError:
        print(f"  {desc}: TIMEOUT")
    except usb.core.USBError as e:
        print(f"  {desc}: ERROR {e}")
        break

# Read config after
try:
    resp_after = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
    print(f"\n  Config AFTER:  {resp_after.hex()}")
    if resp_before != resp_after:
        print("  >>> CONFIG CHANGED!")
        if len(resp_after) >= 11:
            btr1 = resp_after[9]
            btr0 = resp_after[10]
            brp = (btr0 & 0x3F) + 1
            tseg1 = (btr1 & 0x0F) + 1
            tseg2 = ((btr1 >> 4) & 0x07) + 1
            bit_time = 1 + tseg1 + tseg2
            bitrate = 36_000_000 / (2 * brp * bit_time)
            print(f"  NEW BTR0=0x{btr0:02X} BTR1=0x{btr1:02X} -> {bitrate:.0f} bps")
except usb.core.USBError as e:
    print(f"  Config read failed: {e}")

# ── Try 0x03 with old-style BTR values ──────────────────────────────────

print("\n" + "=" * 60)
print("3. 0x03 with old 32-bit BTR values")
print("=" * 60)

auth()

resp_before = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  Config BEFORE: {resp_before.hex()}")

# Send 0x12 0x03 with same format as 0x12 0x23 (old SET_BITRATE)
# [0x12, 0x03, 0x06, 0x00, mode_chan, BTR[4]]
btr_250k = 0x00120017
cmd = bytes([0x12, 0x03, 0x06, 0x00, 0x00]) + struct.pack(">I", btr_250k)
print(f"  Sending: {cmd.hex()}")
try:
    resp = send_recv(cmd, timeout=1000)
    ok = len(resp) >= 3 and (resp[2] & 0x80)
    print(f"  Response: {'OK' if ok else 'NACK'} resp={resp.hex()}")
except usb.core.USBError as e:
    print(f"  ERROR: {e}")

resp_after = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  Config AFTER:  {resp_after.hex()}")
if resp_before != resp_after:
    print("  >>> CONFIG CHANGED!")
    if len(resp_after) >= 11:
        btr1 = resp_after[9]
        btr0 = resp_after[10]
        brp = (btr0 & 0x3F) + 1
        tseg1 = (btr1 & 0x0F) + 1
        tseg2 = ((btr1 >> 4) & 0x07) + 1
        bit_time = 1 + tseg1 + tseg2
        bitrate = 36_000_000 / (2 * brp * bit_time)
        print(f"  NEW BTR0=0x{btr0:02X} BTR1=0x{btr1:02X} -> {bitrate:.0f} bps")

usb.util.release_interface(dev, 0)
print("\nDone.")
