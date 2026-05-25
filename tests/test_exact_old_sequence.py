#!/usr/bin/env python3
"""
Replicate the EXACT old C driver lifecycle to test SET_BITRATE.

The old C driver does:
  1. VCI_OpenDevice: libusb_open, start RX thread (no claim)
  2. VCI_InitCan: claim → auth → SET_BITRATE → SET_FILTER×14 → release
  3. VCI_StartCAN: start command (NO claim!)

We've always kept the interface claimed. Maybe the firmware requires
this specific claim/release pattern, or needs the RX thread running
concurrently.
"""

import os
import struct
import sys
import threading
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

print(f"Device: {dev.manufacturer} {dev.product}")

# ── 1. Start RX thread BEFORE claiming (like VCI_OpenDevice) ────────────

rx_running = True
rx_count = 0

def rx_thread():
    global rx_count
    while rx_running:
        try:
            data = bytes(dev.read(0x82, 57, timeout=10))
            rx_count += len(data) // 19
        except usb.core.USBTimeoutError:
            pass
        except usb.core.USBError:
            break

# Start RX thread first (old driver does this in VCI_OpenDevice)
t = threading.Thread(target=rx_thread, daemon=True)
t.start()
time.sleep(0.1)  # let it start
print("RX thread started")

# ── 2. VCI_InitCan: claim → auth → bitrate → filters → release ─────────

print("\n--- VCI_InitCan sequence ---")
usb.util.claim_interface(dev, 0)
print("  Interface claimed")

# Auth
challenge = os.urandom(16)
sm4 = CryptSM4()
sm4.set_key(b"itekon2012usbcan", SM4_ENCRYPT)
expected = sm4.crypt_ecb(challenge)
auth_cmd = bytes([0x13, 0xB0, 0x11, 0x00]) + challenge
dev.write(0x01, auth_cmd, timeout=2000)
resp = bytes(dev.read(0x81, 64, timeout=2000))
assert resp[4:20] == expected[:16], "Auth failed!"
print("  Auth OK")

# SET_BITRATE (500K old BTR)
btr_cmd = bytes([0x12, 0x23, 0x06, 0x00, 0x00]) + struct.pack(">I", 0x0012000B)
print(f"  Sending SET_BITRATE: {btr_cmd.hex()}")
dev.write(0x01, btr_cmd, timeout=2000)
resp = bytes(dev.read(0x81, 64, timeout=2000))
ok = len(resp) >= 3 and resp[2] == 0x81
print(f"  Response: {resp.hex()} -> {'OK (0x81)' if ok else f'NACK (0x{resp[2]:02X})'}")

if not ok:
    print("\n  --- Trying with 64-byte padded command ---")
    padded = bytearray(64)
    padded[:len(btr_cmd)] = btr_cmd
    dev.write(0x01, bytes(padded), timeout=2000)
    resp = bytes(dev.read(0x81, 64, timeout=2000))
    ok = len(resp) >= 3 and resp[2] == 0x81
    print(f"  Response: {resp.hex()} -> {'OK (0x81)' if ok else f'NACK (0x{resp[2]:02X})'}")

if not ok:
    print("\n  --- Trying with data_len=0x05 (exclude byte[3] from count) ---")
    btr_cmd2 = bytes([0x12, 0x23, 0x05, 0x00]) + struct.pack(">I", 0x0012000B)
    dev.write(0x01, btr_cmd2, timeout=2000)
    resp = bytes(dev.read(0x81, 64, timeout=2000))
    ok = len(resp) >= 3 and resp[2] == 0x81
    print(f"  Response: {resp.hex()} -> {'OK (0x81)' if ok else f'NACK (0x{resp[2]:02X})'}")

if not ok:
    print("\n  --- Trying with trailing 0x57 byte ---")
    # Maybe the '57' in the default init array {0x12,0x23,0x06,0x00,0x00,0x00,0x45,0x02,0x57}
    # is a magic byte that the HTONL(BotRate) doesn't fully overwrite?
    # No: sizeof(UINT)=4, so bytes 5-8 get overwritten. But let's try with an extra byte.
    btr_cmd3 = bytes([0x12, 0x23, 0x07, 0x00, 0x00]) + struct.pack(">I", 0x0012000B) + bytes([0x57])
    dev.write(0x01, btr_cmd3, timeout=2000)
    resp = bytes(dev.read(0x81, 64, timeout=2000))
    ok = len(resp) >= 3 and resp[2] == 0x81
    print(f"  Response: {resp.hex()} -> {'OK (0x81)' if ok else f'NACK (0x{resp[2]:02X})'}")

if not ok:
    print("\n  --- Trying with mode=1 (listen only) ---")
    btr_cmd4 = bytes([0x12, 0x23, 0x06, 0x00, 0x80]) + struct.pack(">I", 0x0012000B)
    dev.write(0x01, btr_cmd4, timeout=2000)
    resp = bytes(dev.read(0x81, 64, timeout=2000))
    ok = len(resp) >= 3 and resp[2] == 0x81
    print(f"  Response: {resp.hex()} -> {'OK (0x81)' if ok else f'NACK (0x{resp[2]:02X})'}")

# Release interface (like old driver does after InitCan)
usb.util.release_interface(dev, 0)
print("\n  Interface released")

# ── 3. VCI_StartCAN: start WITHOUT claiming ─────────────────────────────

print("\n--- VCI_StartCAN (no claim) ---")
start_cmd = bytes([0x12, 0x0E, 0x02, 0x00, 0x00])
try:
    dev.write(0x01, start_cmd, timeout=2000)
    resp = bytes(dev.read(0x81, 64, timeout=2000))
    ok = len(resp) >= 3 and (resp[2] & 0x80)
    print(f"  Start: {resp.hex()} -> {'OK' if ok else 'NACK'}")
except usb.core.USBError as e:
    print(f"  Start without claim: {e}")
    # If that fails, try with claim
    print("  Retrying with claim...")
    usb.util.claim_interface(dev, 0)
    dev.write(0x01, start_cmd, timeout=2000)
    resp = bytes(dev.read(0x81, 64, timeout=2000))
    ok = len(resp) >= 3 and (resp[2] & 0x80)
    print(f"  Start: {resp.hex()} -> {'OK' if ok else 'NACK'}")

# ── 4. Stop and cleanup ─────────────────────────────────────────────────

rx_running = False
t.join(timeout=1)

try:
    usb.util.claim_interface(dev, 0)
except:
    pass

try:
    stop_cmd = bytes([0x12, 0x0F, 0x02, 0x00, 0x00])
    dev.write(0x01, stop_cmd, timeout=2000)
    dev.read(0x81, 64, timeout=2000)
except:
    pass

try:
    usb.util.release_interface(dev, 0)
except:
    pass

print("\nDone.")
