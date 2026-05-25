#!/usr/bin/env python3
"""
Last attempts to set the bitrate:
1. Write BTR values via GET_CONFIG (0x06) used as a setter
2. Try 0xA5 (found working but untested for config)
3. Try writing the raw BTR bytes (0x03 0x95 format) back via various commands
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

# Read current config for reference
resp = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"Current GET_CONFIG: {resp.hex()}")
# Data: 00 01 00 00 00 00 95 03 00 00
# BTR1=0x95 (at data[6]) BTR0=0x03 (at data[7])

# ── 1: Write config via 0x06 with full payload ──────────────────────────

print("\n" + "=" * 60)
print("1. Try 0x06 as config writer with BTR for 250K")
print("=" * 60)

# For 250K at 36MHz: BRP=8, TSEG1=6, TSEG2=2, SJW=1
# BTR0 = (SJW-1)<<6 | (BRP-1) = 0<<6 | 7 = 0x07
# BTR1 = SAM<<7 | (TSEG2-1)<<4 | (TSEG1-1) = 1<<7 | 1<<4 | 5 = 0x95
# Actually that gives same TSEG as 500K. Let me use different.
# 250K = 36MHz / (2 * BRP * bit_time). With BRP=8: bit_time = 36M/(2*8*250K) = 9 TQ
# Same bit_time, double BRP. BTR0 = 0x07, BTR1 = 0x95

# Actually for a DIFFERENT bitrate, let me try 125K:
# 125K = 36MHz / (2 * BRP * bit_time). With BRP=16: bit_time=9 → 36M/(2*16*9)=125K
# BTR0 = 0x0F, BTR1 = 0x95
btr0_125k = 0x0F
btr1_125k = 0x95

# Try writing the full config data with modified BTR bytes
# Original data: 00 01 00 00 00 00 95 03 00 00
# Modified:      00 01 00 00 00 00 95 0F 00 00  (BTR0 changed)
for config_payload in [
    # Send as data_len=0x0A (10), same format as response
    bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, btr1_125k, btr0_125k, 0x00, 0x00]),
    # Shorter - just BTR bytes
    bytes([0x00, btr1_125k, btr0_125k]),
    # Just the two bytes
    bytes([btr1_125k, btr0_125k]),
]:
    dl = len(config_payload)
    cmd = bytes([0x12, 0x06, dl, 0x00]) + config_payload
    try:
        resp = send_recv(cmd, timeout=500)
        ok = len(resp) >= 3 and (resp[2] & 0x80)
        data_changed = resp.hex() != "12068a00010000000095030000"
        print(f"  dl={dl:2d} cmd={cmd.hex()[:30]:30s} -> {'OK' if ok else 'NACK'} resp={resp.hex()}")
        if data_changed and ok:
            print(f"    >>> RESPONSE CHANGED!")
    except usb.core.USBTimeoutError:
        print(f"  dl={dl:2d} -> TIMEOUT")

# ── 2: Try 0xA5 ─────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("2. Probe 0xA5 command")
print("=" * 60)

auth()

for dl in [0x01, 0x02, 0x04, 0x06, 0x08, 0x0A]:
    if dl == 6:
        payload = bytes([0x00]) + struct.pack(">I", 0x0012000B)
    elif dl == 0x0A:
        payload = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x95, 0x03, 0x00, 0x00])
    else:
        payload = bytes(dl)
    cmd = bytes([0x12, 0xA5, dl, 0x00]) + payload
    try:
        resp = send_recv(cmd, timeout=500)
        ok = len(resp) >= 3 and (resp[2] & 0x80)
        print(f"  0xA5 dl={dl}: {'OK' if ok else 'NACK'} resp={resp.hex()}")
    except usb.core.USBTimeoutError:
        print(f"  0xA5 dl={dl}: TIMEOUT")

# ── 3: Try writing BTR0/BTR1 raw via 0x23 with SJA1000 format ───────────

print("\n" + "=" * 60)
print("3. SET_BITRATE with raw SJA1000 BTR0/BTR1 format")
print("=" * 60)

auth()

# Maybe the command expects SJA1000 BTR0/BTR1 directly, not the old
# driver's custom 32-bit value
# Current 500K: BTR0=0x03, BTR1=0x95
# Try sending these raw bytes in various positions
for desc, payload in [
    ("BTR0+BTR1 as 2 bytes",       bytes([0x12, 0x23, 0x02, 0x00, 0x03, 0x95])),
    ("chan+BTR0+BTR1",              bytes([0x12, 0x23, 0x03, 0x00, 0x00, 0x03, 0x95])),
    ("00+BTR0+BTR1",               bytes([0x12, 0x23, 0x03, 0x00, 0x00, 0x03, 0x95])),
    ("chan+BTR1+BTR0",              bytes([0x12, 0x23, 0x03, 0x00, 0x00, 0x95, 0x03])),
    ("full config data as bitrate", bytes([0x12, 0x23, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x95, 0x03, 0x00, 0x00])),
]:
    try:
        resp = send_recv(payload, timeout=500)
        ok = len(resp) >= 3 and (resp[2] & 0x80)
        print(f"  {desc:35s} -> {'OK' if ok else 'NACK'} resp={resp.hex()}")
    except usb.core.USBTimeoutError:
        print(f"  {desc:35s} -> TIMEOUT")

# ── 4: Try 0x07 (used by new protocol as reset) ─────────────────────────

print("\n" + "=" * 60)
print("4. Other untested sub-commands with config-like payloads")
print("=" * 60)

auth()

# Sub-commands we haven't tested with config payloads
for sub in [0x02, 0x03, 0x05, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x16, 0x17]:
    payload = bytes([0x00]) + struct.pack(">I", 0x0012000B)
    cmd = bytes([0x12, sub, 0x06, 0x00]) + payload
    try:
        resp = send_recv(cmd, timeout=300)
        ok = len(resp) >= 3 and (resp[2] & 0x80)
        if ok:
            print(f"  0x{sub:02X}: OK! resp={resp.hex()}")
    except usb.core.USBTimeoutError:
        pass
    except usb.core.USBError:
        auth()

# ── 5: Try VCI_SetReference-style commands ───────────────────────────────

print("\n" + "=" * 60)
print("5. Hypothetical SetReference: 0x12 0x0A/0x0B with RefType+data")
print("=" * 60)

auth()

# Maybe there's a generic config write command using RefType
for sub in [0x0A, 0x0B, 0x06]:
    for ref_type in range(8):
        # Format: [0x12, sub, data_len, ref_type, channel, BTR0, BTR1]
        cmd = bytes([0x12, sub, 0x04, ref_type, 0x00, 0x03, 0x95, 0x00])
        try:
            resp = send_recv(cmd, timeout=300)
            ok = len(resp) >= 3 and (resp[2] & 0x80)
            if ok and resp.hex() != "12068a00010000000095030000":  # filter out normal GET_CONFIG
                print(f"  0x{sub:02X} ref={ref_type}: OK resp={resp.hex()}")
        except (usb.core.USBTimeoutError, usb.core.USBError):
            pass

# ── 6: Check if config changes after any of our attempts ────────────────

print("\n" + "=" * 60)
print("6. Final config check")
print("=" * 60)

auth()
resp = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  GET_CONFIG now: {resp.hex()}")

usb.util.release_interface(dev, 0)
print("\nDone.")
