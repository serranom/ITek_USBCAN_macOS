#!/usr/bin/env python3
"""
Probe which bitrate values the device accepts with the old 0x12 0x23 command.
Tests both the old driver's BTR values and the new SDK's abit_timing values.
"""

import os
import struct
import sys

import usb.core
import usb.util
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

# ── Find device ────────────────────────────────────────────────────────────

dev = usb.core.find(idVendor=0x0471, idProduct=0x1200)
if dev is None:
    print("Device not found")
    sys.exit(1)

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


# ── Authenticate (legacy) ──────────────────────────────────────────────────

challenge = os.urandom(16)
sm4 = CryptSM4()
sm4.set_key(b"itekon2012usbcan", SM4_ENCRYPT)
expected = sm4.crypt_ecb(challenge)
auth_cmd = bytes([0x13, 0xB0, 0x11, 0x00]) + challenge
resp = send_recv(auth_cmd)
assert resp[4:20] == expected[:16], "Auth failed!"
print("Auth OK\n")

# ── Old driver BTR values (iTekon-usb, 2018) ──────────────────────────────

OLD_BTRS = {
    "5K":    0x00450257,
    "10K":   0x00120257,
    "20K":   0x0012012B,
    "40K":   0x00780031,
    "50K":   0x0067002C,
    "80K":   0x004B0018,
    "100K":  0x0012003B,
    "125K":  0x0012002F,
    "200K":  0x0027000E,
    "250K":  0x00120017,
    "400K":  0x00160008,
    "500K":  0x0012000B,
    "666K":  0x00240005,
    "800K":  0x00240004,
    "1000K": 0x00120005,
}

# ── New SDK abit_timing values (iTekCANFD, 2025) ──────────────────────────

NEW_BTRS = {
    "5K":    0x01F31302,
    "10K":   0x00F91302,
    "20K":   0x007C1302,
    "40K":   0x00630A02,
    "50K":   0x00311302,
    "80K":   0x001D1204,
    "100K":  0x00181302,
    "125K":  0x00131302,
    "200K":  0x00130A02,
    "250K":  0x00091302,
    "400K":  0x00090A02,
    "500K":  0x00070A02,
    "800K":  0x00021006,
    "1000K": 0x00040702,
}


def try_bitrate(name, btr_value, channel=0, mode=0):
    """Send old-format SET_BITRATE and check response."""
    mode_chan = (mode << 7) | (channel << 4)
    cmd = bytes([0x12, 0x23, 0x06, 0x00, mode_chan]) + struct.pack(">I", btr_value)
    try:
        resp = send_recv(cmd)
        ok = len(resp) >= 3 and (resp[2] & 0x80) != 0
        return ok, resp
    except usb.core.USBError as e:
        return False, str(e)


# ── Test old BTR values ───────────────────────────────────────────────────

print("=" * 60)
print("Testing OLD driver BTR values with 0x12 0x23 command")
print("=" * 60)
for name, btr in OLD_BTRS.items():
    ok, resp = try_bitrate(name, btr)
    resp_hex = resp.hex() if isinstance(resp, bytes) else resp
    status = "OK" if ok else "NACK"
    print(f"  {name:6s}  BTR=0x{btr:08X}  -> {status}  resp={resp_hex}")

print()

# ── Test new SDK BTR values ───────────────────────────────────────────────

# Re-authenticate in case the failed commands confused the device
challenge = os.urandom(16)
expected = sm4.crypt_ecb(challenge)
auth_cmd = bytes([0x13, 0xB0, 0x11, 0x00]) + challenge
resp = send_recv(auth_cmd)
assert resp[4:20] == expected[:16], "Re-auth failed!"

print("=" * 60)
print("Testing NEW SDK abit_timing values with 0x12 0x23 command")
print("=" * 60)
for name, btr in NEW_BTRS.items():
    ok, resp = try_bitrate(name, btr)
    resp_hex = resp.hex() if isinstance(resp, bytes) else resp
    status = "OK" if ok else "NACK"
    print(f"  {name:6s}  BTR=0x{btr:08X}  -> {status}  resp={resp_hex}")

print()

# ── Also try the 0x12 0x23 command with data_len variations ──────────────

# Re-auth
challenge = os.urandom(16)
expected = sm4.crypt_ecb(challenge)
resp = send_recv(bytes([0x13, 0xB0, 0x11, 0x00]) + challenge)
assert resp[4:20] == expected[:16]

print("=" * 60)
print("Testing different data_len values (byte[2]) with 500K old BTR")
print("=" * 60)
btr_500k = 0x0012000B
for data_len in [0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]:
    mode_chan = 0x00  # channel 0, normal mode
    if data_len <= 1:
        cmd = bytes([0x12, 0x23, data_len, 0x00])
    elif data_len <= 5:
        cmd = bytes([0x12, 0x23, data_len, 0x00, mode_chan]) + struct.pack(">I", btr_500k)[:data_len - 1]
    else:
        cmd = bytes([0x12, 0x23, data_len, 0x00, mode_chan]) + struct.pack(">I", btr_500k) + bytes(data_len - 5)

    try:
        resp = send_recv(cmd)
        ok = len(resp) >= 3 and (resp[2] & 0x80) != 0
        status = "OK" if ok else "NACK"
        print(f"  data_len=0x{data_len:02X} cmd={cmd.hex()} -> {status} resp={resp.hex()}")
    except usb.core.USBError as e:
        print(f"  data_len=0x{data_len:02X} -> ERROR: {e}")

print()

# ── Try other sub-commands near 0x23 ─────────────────────────────────────

# Re-auth
challenge = os.urandom(16)
expected = sm4.crypt_ecb(challenge)
resp = send_recv(bytes([0x13, 0xB0, 0x11, 0x00]) + challenge)
assert resp[4:20] == expected[:16]

print("=" * 60)
print("Scanning sub-commands 0x20-0x30 with 500K new BTR payload")
print("=" * 60)
btr_500k_new = 0x00070A02
for sub in range(0x20, 0x31):
    mode_chan = 0x00
    cmd = bytes([0x12, sub, 0x06, 0x00, mode_chan]) + struct.pack(">I", btr_500k_new)
    try:
        resp = send_recv(cmd, timeout=500)
        ok = len(resp) >= 3 and (resp[2] & 0x80) != 0
        status = "OK" if ok else "NACK"
        print(f"  0x{sub:02X} -> {status}  resp={resp[:8].hex()}")
    except usb.core.USBTimeoutError:
        print(f"  0x{sub:02X} -> TIMEOUT")
    except usb.core.USBError as e:
        print(f"  0x{sub:02X} -> ERROR: {e}")

# Cleanup
usb.util.release_interface(dev, 0)
print("\nDone.")
