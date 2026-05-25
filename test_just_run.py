#!/usr/bin/env python3
"""
Pragmatic test: skip bitrate config entirely, just auth → start → try TX/RX.
The device may already be configured at a bitrate from its last Windows session
or factory default.

Also tries: sending 0x12 0x23 with a 2-byte "index" payload format.
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

# ── Auth ──────────────────────────────────────────────────────────────────
print("\n--- Auth ---")
assert auth(), "Auth failed!"
print("Auth OK")

# ── Try a bitrate index approach ──────────────────────────────────────────
# Maybe the firmware uses an index byte instead of raw BTR values
print("\n--- Trying bitrate index format [0x12, 0x23, 0x02, 0x00, mode_chan, index] ---")
for idx in range(16):
    cmd = bytes([0x12, 0x23, 0x02, 0x00, 0x00, idx])
    try:
        resp = send_recv(cmd, timeout=500)
        ok = len(resp) >= 3 and (resp[2] & 0x80) != 0
        if ok:
            print(f"  Index {idx:2d} -> OK!  resp={resp.hex()}")
            break
    except usb.core.USBTimeoutError:
        pass
else:
    print("  All indices NACK'd")

# Re-auth
auth()

# ── Try 0x12 0x23 with mode_chan in byte[3] instead of byte[4] ────────────
# Maybe the format is [0x12, 0x23, data_len, mode_chan, BTR[4]]
print("\n--- Trying alternative format [0x12, 0x23, 0x05, mode_chan, BTR[4]] ---")
for btr in [0x0012000B, 0x00070A02]:
    cmd = bytes([0x12, 0x23, 0x05, 0x00]) + struct.pack(">I", btr)
    try:
        resp = send_recv(cmd, timeout=500)
        ok = len(resp) >= 3 and (resp[2] & 0x80) != 0
        print(f"  BTR=0x{btr:08X} -> {'OK' if ok else 'NACK'}  resp={resp.hex()}")
    except usb.core.USBTimeoutError:
        print(f"  BTR=0x{btr:08X} -> TIMEOUT")

auth()

# ── Check GET_CONFIG before and after START ───────────────────────────────
print("\n--- GET_CONFIG before start ---")
resp = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  Config: {resp.hex()}")

# ── Start CAN channel 0 (old format, 5 bytes) ────────────────────────────
print("\n--- START CAN (0x12 0x0E) ---")
resp = send_recv(bytes([0x12, 0x0E, 0x02, 0x00, 0x00]))
ok = len(resp) >= 3 and (resp[2] & 0x80) != 0
print(f"  Start resp: {resp.hex()} -> {'OK' if ok else 'NACK'}")

if ok:
    print("\n--- GET_CONFIG after start ---")
    resp = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
    print(f"  Config: {resp.hex()}")

    print("\n--- GET_STATUS after start ---")
    resp = send_recv(bytes([0x12, 0x0D, 0x01, 0x00]))
    print(f"  Status: {resp.hex()}")

    # ── Try TX on bulk endpoint ───────────────────────────────────────────
    print("\n--- TX test: send CAN frame ID=0x7DF data=[02 01 00] ---")
    # OLD protocol: 19-byte frames on EP 0x02
    frame = bytearray(19)
    frame[4] = 1       # TimeFlag
    frame[5] = 0       # SendType = normal
    frame[6] = 3       # DLC=3, channel=0, STD, no RTR
    struct.pack_into("<I", frame, 7, 0x7DF)  # CAN ID little-endian (old format)
    frame[11] = 0x02
    frame[12] = 0x01
    frame[13] = 0x00

    print(f"  Old-format frame (19B): {bytes(frame).hex()}")
    try:
        dev.write(0x02, bytes(frame), timeout=2000)
        print("  Bulk write OK")
        # Try reading ACK from EP 0x81
        try:
            ack = bytes(dev.read(0x81, 64, timeout=500))
            print(f"  INT ACK: {ack.hex()}")
        except usb.core.USBTimeoutError:
            print("  No INT ACK (timeout)")
    except usb.core.USBError as e:
        print(f"  Write error: {e}")

    # Also try NEW TX format
    print("\n--- TX test (new format): header + 24-byte frame ---")
    tx_header = bytes([0x21, 0x00, 0x01])
    tx_frame = bytearray(24)
    tx_frame[9] = 0       # channel 0
    tx_frame[10] = 0      # cantype = CAN
    tx_frame[11] = 3      # DLC
    struct.pack_into(">I", tx_frame, 12, 0x7DF)  # CAN ID big-endian (new format)
    tx_frame[16] = 0x02
    tx_frame[17] = 0x01
    tx_frame[18] = 0x00

    tx_data = tx_header + bytes(tx_frame)
    print(f"  New-format TX ({len(tx_data)}B): {tx_data.hex()}")
    try:
        dev.write(0x02, tx_data, timeout=2000)
        print("  Bulk write OK")
        try:
            ack = bytes(dev.read(0x82, 64, timeout=500))
            print(f"  BULK ACK (0x82): {ack.hex()}")
        except usb.core.USBTimeoutError:
            print("  No BULK ACK (timeout)")
        try:
            ack = bytes(dev.read(0x81, 64, timeout=500))
            print(f"  INT ACK (0x81): {ack.hex()}")
        except usb.core.USBTimeoutError:
            print("  No INT ACK (timeout)")
    except usb.core.USBError as e:
        print(f"  Write error: {e}")

    # ── Try RX (poll EP 0x82) ─────────────────────────────────────────────
    print("\n--- RX test: polling EP 0x82 for 3 seconds ---")
    t0 = time.time()
    count = 0
    while time.time() - t0 < 3.0:
        try:
            data = bytes(dev.read(0x82, 512, timeout=100))
            print(f"  RX ({len(data)}B): {data.hex()}")
            count += 1
        except usb.core.USBTimeoutError:
            pass
    print(f"  Received {count} packets")

    # ── Stop ──────────────────────────────────────────────────────────────
    print("\n--- STOP CAN ---")
    resp = send_recv(bytes([0x12, 0x0F, 0x02, 0x00, 0x00]))
    print(f"  Stop resp: {resp.hex()}")
else:
    print("Start CAN failed, skipping TX/RX tests")

usb.util.release_interface(dev, 0)
print("\nDone.")
