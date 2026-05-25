#!/usr/bin/env python3
"""
Try various command sequences and formats to find how to set bitrate.
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

# ── Test 1: Release/claim, auth, IMMEDIATELY try bitrate ──────────────────
print("=" * 60)
print("Test 1: Clean claim → auth → bitrate (immediate)")
print("=" * 60)
usb.util.claim_interface(dev, 0)
assert auth(), "Auth failed"
cmd = bytes([0x12, 0x23, 0x06, 0x00, 0x00]) + struct.pack(">I", 0x0012000B)
resp = send_recv(cmd)
ok = len(resp) >= 3 and (resp[2] & 0x80)
print(f"  Bitrate resp: {resp.hex()} -> {'OK' if ok else 'NACK'}")
usb.util.release_interface(dev, 0)

# ── Test 2: Start CAN THEN bitrate ───────────────────────────────────────
print("\n" + "=" * 60)
print("Test 2: auth → start → bitrate")
print("=" * 60)
usb.util.claim_interface(dev, 0)
assert auth()
resp = send_recv(bytes([0x12, 0x0E, 0x02, 0x00, 0x00]))
print(f"  Start: {resp.hex()}")
cmd = bytes([0x12, 0x23, 0x06, 0x00, 0x00]) + struct.pack(">I", 0x0012000B)
resp = send_recv(cmd)
ok = len(resp) >= 3 and (resp[2] & 0x80)
print(f"  Bitrate: {resp.hex()} -> {'OK' if ok else 'NACK'}")
# Stop
send_recv(bytes([0x12, 0x0F, 0x02, 0x00, 0x00]))
usb.util.release_interface(dev, 0)

# ── Test 3: Bitrate embedded in START command ────────────────────────────
print("\n" + "=" * 60)
print("Test 3: Bitrate embedded in START command (extended 0x0E)")
print("=" * 60)
usb.util.claim_interface(dev, 0)
assert auth()

for data_len, payload in [
    (0x06, bytes([0x00]) + struct.pack(">I", 0x0012000B)),
    (0x06, bytes([0x00]) + struct.pack(">I", 0x00070A02)),
    (0x07, bytes([0x00, 0x00]) + struct.pack(">I", 0x0012000B)),
]:
    cmd = bytes([0x12, 0x0E, data_len, 0x00]) + payload
    try:
        resp = send_recv(cmd, timeout=500)
        ok = len(resp) >= 3 and (resp[2] & 0x80)
        print(f"  0x0E dl={data_len} payload={payload.hex()}: {resp.hex()} -> {'OK' if ok else 'NACK'}")
    except usb.core.USBTimeoutError:
        print(f"  0x0E dl={data_len}: TIMEOUT")

# Stop
try: send_recv(bytes([0x12, 0x0F, 0x02, 0x00, 0x00]))
except: pass
usb.util.release_interface(dev, 0)

# ── Test 4: USB control transfers ────────────────────────────────────────
print("\n" + "=" * 60)
print("Test 4: USB control transfers (vendor/class requests)")
print("=" * 60)
usb.util.claim_interface(dev, 0)

# Try vendor-specific control requests
for bRequest in range(0, 16):
    try:
        resp = dev.ctrl_transfer(0xC0, bRequest, 0, 0, 64, timeout=200)
        print(f"  Vendor IN  bReq=0x{bRequest:02X}: {bytes(resp).hex()}")
    except usb.core.USBError:
        pass

    try:
        resp = dev.ctrl_transfer(0xC1, bRequest, 0, 0, 64, timeout=200)
        print(f"  VendorIF IN bReq=0x{bRequest:02X}: {bytes(resp).hex()}")
    except usb.core.USBError:
        pass

usb.util.release_interface(dev, 0)

# ── Test 5: Try 0x11 commands padded to 64 bytes (full USB packet) ───────
print("\n" + "=" * 60)
print("Test 5: 0x11 commands padded to 64 bytes")
print("=" * 60)
usb.util.claim_interface(dev, 0)
assert auth()

# Try InitCAN with 64-byte padding
init_cmd = bytearray(64)
init_cmd[0] = 0x11
init_cmd[1] = 0x04
init_cmd[2] = 0x30
init_cmd[3] = 0x00
init_cmd[4] = 0       # channel 0
init_cmd[5] = 0       # CAN classic
init_cmd[8] = 0       # normal mode
struct.pack_into(">I", init_cmd, 9, 0x00070A02)  # 500K abit
struct.pack_into(">I", init_cmd, 13, 0x00070A02) # 500K dbit

try:
    resp = send_recv(bytes(init_cmd), timeout=1000)
    print(f"  InitCAN 64B: {resp.hex()}")
except usb.core.USBTimeoutError:
    print("  InitCAN 64B: TIMEOUT")

# Try GetDeviceInfo with 64 bytes
info_cmd = bytearray(64)
info_cmd[0] = 0x11
info_cmd[1] = 0x03
info_cmd[2] = 0x30
try:
    resp = send_recv(bytes(info_cmd), timeout=1000)
    print(f"  DeviceInfo 64B: {resp.hex()}")
except usb.core.USBTimeoutError:
    print("  DeviceInfo 64B: TIMEOUT")

# Try auth with new format but 64 bytes
challenge = os.urandom(16)
sm4 = CryptSM4()
sm4.set_key(b"itekon2012usbcan", SM4_ENCRYPT)
expected = sm4.crypt_ecb(challenge)

auth_cmd = bytearray(64)
auth_cmd[0] = 0x11
auth_cmd[1] = 0xE0
auth_cmd[2] = 0x30
auth_cmd[7:23] = challenge
try:
    resp = send_recv(bytes(auth_cmd), timeout=1000)
    print(f"  Auth 64B: {resp.hex()}")
    if len(resp) >= 23:
        match = resp[7:23] == expected[:16]
        print(f"  Auth match: {match}")
except usb.core.USBTimeoutError:
    print("  Auth 64B: TIMEOUT (device doesn't understand 0x11)")

usb.util.release_interface(dev, 0)

# ── Test 6: Try sending commands on BULK endpoint instead of INT ──────────
print("\n" + "=" * 60)
print("Test 6: Commands on BULK EP 0x02 instead of INT EP 0x01")
print("=" * 60)
usb.util.claim_interface(dev, 0)
auth()

# Send bitrate command on EP 0x02 instead of EP 0x01
btr_cmd = bytes([0x12, 0x23, 0x06, 0x00, 0x00]) + struct.pack(">I", 0x0012000B)
try:
    dev.write(0x02, btr_cmd, timeout=2000)
    try:
        resp = bytes(dev.read(0x82, 64, timeout=500))
        print(f"  Bulk bitrate resp (0x82): {resp.hex()}")
    except usb.core.USBTimeoutError:
        print("  No bulk resp")
    try:
        resp = bytes(dev.read(0x81, 64, timeout=500))
        print(f"  Int resp (0x81): {resp.hex()}")
    except usb.core.USBTimeoutError:
        print("  No int resp either")
except usb.core.USBError as e:
    print(f"  Error: {e}")

usb.util.release_interface(dev, 0)

# ── Test 7: Try 0x13 prefix commands (like auth but different sub) ────────
print("\n" + "=" * 60)
print("Test 7: 0x13 prefix with different sub-commands")
print("=" * 60)
usb.util.claim_interface(dev, 0)
auth()

for sub in range(0xA0, 0xC0):
    cmd = bytes([0x13, sub, 0x06, 0x00, 0x00]) + struct.pack(">I", 0x0012000B)
    try:
        resp = send_recv(cmd, timeout=300)
        print(f"  0x13 0x{sub:02X}: {resp.hex()}")
    except usb.core.USBTimeoutError:
        pass
    except usb.core.USBError as e:
        # Re-auth
        try: auth()
        except: pass

usb.util.release_interface(dev, 0)
print("\nDone.")
