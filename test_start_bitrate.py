#!/usr/bin/env python3
"""
Deep dive into the extended START command (0x12 0x0E) with embedded bitrate.

Test 3 from test_sequences.py showed that:
  0x0E dl=6 payload=000012000b -> OK  (old 500K BTR)
  0x0E dl=6 payload=0000070a02 -> OK  (new 500K BTR)
  0x0E dl=7 payload=00000012000b -> OK

We need to figure out:
1. The exact payload format (which bytes are channel, mode, BTR?)
2. Whether different bitrate values actually change behavior
3. Whether we can TX/RX after this
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


def stop_can():
    try:
        send_recv(bytes([0x12, 0x0F, 0x02, 0x00, 0x00]))
    except:
        pass


# ── Auth ──────────────────────────────────────────────────────────────────
assert auth(), "Auth failed!"
print("Auth OK\n")


# ── Test: Parse the extended START response more carefully ────────────────

print("=" * 60)
print("Test A: Extended START with various payload structures")
print("=" * 60)

# The old START is: [0x12, 0x0E, 0x02, 0x00, chan_byte]
# where chan_byte = CANIndex << 4
# Old response for simple start: 120e8100

# Extended format seems to be:
# [0x12, 0x0E, data_len, 0x00, chan_byte, BTR[4]]
# Let's try systematic variations

test_cases = [
    # (description, data_len, payload_bytes)
    ("simple start ch0",        0x02, bytes([0x00])),
    ("simple start ch0 v2",     0x02, bytes([0x00, 0x00])),

    # Extended with old BTR 500K
    ("ext dl=5 ch0 old500K",    0x05, bytes([0x00]) + struct.pack(">I", 0x0012000B)),
    ("ext dl=6 ch0 old500K",    0x06, bytes([0x00, 0x00]) + struct.pack(">I", 0x0012000B)),
    ("ext dl=6 ch0+mode old500K", 0x06, bytes([0x00]) + struct.pack(">I", 0x0012000B) + bytes([0x00])),

    # Extended with new BTR 500K
    ("ext dl=5 ch0 new500K",    0x05, bytes([0x00]) + struct.pack(">I", 0x00070A02)),
    ("ext dl=6 ch0 new500K",    0x06, bytes([0x00, 0x00]) + struct.pack(">I", 0x00070A02)),

    # Extended with new BTR 250K
    ("ext dl=5 ch0 new250K",    0x05, bytes([0x00]) + struct.pack(">I", 0x00091302)),
    ("ext dl=6 ch0 new250K",    0x06, bytes([0x00, 0x00]) + struct.pack(">I", 0x00091302)),

    # Extended with new BTR 1000K
    ("ext dl=5 ch0 new1M",      0x05, bytes([0x00]) + struct.pack(">I", 0x00040702)),
    ("ext dl=6 ch0 new1M",      0x06, bytes([0x00, 0x00]) + struct.pack(">I", 0x00040702)),

    # Extended with old BTR 250K
    ("ext dl=5 ch0 old250K",    0x05, bytes([0x00]) + struct.pack(">I", 0x00120017)),
    ("ext dl=6 ch0 old250K",    0x06, bytes([0x00, 0x00]) + struct.pack(">I", 0x00120017)),

    # Different format: BTR first, then channel
    ("ext dl=6 btr-first old500K", 0x06, struct.pack(">I", 0x0012000B) + bytes([0x00, 0x00])),
]

for desc, data_len, payload in test_cases:
    stop_can()
    auth()
    cmd = bytes([0x12, 0x0E, data_len, 0x00]) + payload
    try:
        resp = send_recv(cmd, timeout=1000)
        ok = len(resp) >= 3 and (resp[2] & 0x80) != 0
        print(f"  {desc:35s}  cmd={cmd.hex():30s}  -> {'OK' if ok else 'NACK'}  resp={resp.hex()}")
    except usb.core.USBTimeoutError:
        print(f"  {desc:35s}  cmd={cmd.hex():30s}  -> TIMEOUT")
    except usb.core.USBError as e:
        print(f"  {desc:35s}  -> ERROR: {e}")

stop_can()

print()

# ── Test B: After extended START, read config/status ─────────────────────

print("=" * 60)
print("Test B: Config/Status before and after extended START")
print("=" * 60)

auth()

# Read config before
print("\n  --- Before START ---")
resp = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  GET_CONFIG: {resp.hex()}")
resp = send_recv(bytes([0x12, 0x0D, 0x01, 0x00]))
print(f"  GET_STATUS: {resp.hex()}")

# Extended START with new 500K BTR
cmd = bytes([0x12, 0x0E, 0x06, 0x00, 0x00, 0x00]) + struct.pack(">I", 0x00070A02)
resp = send_recv(cmd)
print(f"\n  START resp: {resp.hex()}")

# Read config after
print("\n  --- After START ---")
resp = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  GET_CONFIG: {resp.hex()}")
resp = send_recv(bytes([0x12, 0x0D, 0x01, 0x00]))
print(f"  GET_STATUS: {resp.hex()}")

# Now stop and restart with different bitrate
stop_can()
auth()

# Extended START with 250K
cmd = bytes([0x12, 0x0E, 0x06, 0x00, 0x00, 0x00]) + struct.pack(">I", 0x00091302)
resp = send_recv(cmd)
print(f"\n  START (250K) resp: {resp.hex()}")

print("\n  --- After START 250K ---")
resp = send_recv(bytes([0x12, 0x06, 0x01, 0x00]))
print(f"  GET_CONFIG: {resp.hex()}")
resp = send_recv(bytes([0x12, 0x0D, 0x01, 0x00]))
print(f"  GET_STATUS: {resp.hex()}")

stop_can()

print()

# ── Test C: Extended START then TX/RX ────────────────────────────────────

print("=" * 60)
print("Test C: Extended START → TX frame → Check for errors")
print("=" * 60)

auth()

# Extended START with 500K
cmd = bytes([0x12, 0x0E, 0x06, 0x00, 0x00, 0x00]) + struct.pack(">I", 0x00070A02)
resp = send_recv(cmd)
ok = len(resp) >= 3 and (resp[2] & 0x80)
print(f"  START: {resp.hex()} -> {'OK' if ok else 'NACK'}")

if ok:
    # Set filters (accept all) — using old format
    print("\n  Setting filters...")
    for i in range(14):
        filt = bytes([0x12, 0x24, 0x0B, 0x00,
                      0x00,           # flags: STD, range, channel 0
                      i,              # index
                      0x00, 0x00, 0x00, 0x00,  # ID1 = 0
                      0xFF, 0x07, 0x00, 0x00]) # ID2 = 0x7FF
        try:
            resp = send_recv(filt, timeout=500)
            filt_ok = len(resp) >= 3 and (resp[2] & 0x80)
            if i == 0:
                print(f"    Filter 0: {resp.hex()} -> {'OK' if filt_ok else 'NACK'}")
        except usb.core.USBTimeoutError:
            if i == 0:
                print(f"    Filter 0: TIMEOUT")
            break
    print(f"    (sent {i+1} filters)")

    # TX: old 19-byte frame format
    print("\n  Sending CAN frame (old 19B format)...")
    frame = bytearray(19)
    frame[4] = 1       # TimeFlag
    frame[5] = 0       # SendType = normal
    frame[6] = 3       # DLC=3, channel=0, STD, no RTR
    struct.pack_into("<I", frame, 7, 0x7DF)  # CAN ID LE
    frame[11] = 0x02
    frame[12] = 0x01
    frame[13] = 0x00
    print(f"    Frame: {bytes(frame).hex()}")

    try:
        dev.write(0x02, bytes(frame), timeout=2000)
        print("    Bulk write OK")
    except usb.core.USBError as e:
        print(f"    Write error: {e}")

    # Check for TX ACK on EP 0x81
    try:
        ack = bytes(dev.read(0x81, 64, timeout=1000))
        print(f"    INT ACK: {ack.hex()}")
    except usb.core.USBTimeoutError:
        print("    No INT ACK")

    # Check status after TX
    print("\n  Status after TX attempt:")
    try:
        resp = send_recv(bytes([0x12, 0x0D, 0x01, 0x00]))
        print(f"    GET_STATUS: {resp.hex()}")
    except:
        pass

    # Poll RX briefly
    print("\n  Polling EP 0x82 for 2 seconds...")
    t0 = time.time()
    count = 0
    while time.time() - t0 < 2.0:
        try:
            data = bytes(dev.read(0x82, 512, timeout=100))
            print(f"    RX ({len(data)}B): {data.hex()}")
            count += 1
        except usb.core.USBTimeoutError:
            pass
    print(f"    Received {count} packets")

stop_can()

print()

# ── Test D: Does the simple START also work? Check if extended is needed ─

print("=" * 60)
print("Test D: Simple START vs Extended START comparison")
print("=" * 60)

auth()

# Simple start (no bitrate)
cmd_simple = bytes([0x12, 0x0E, 0x02, 0x00, 0x00])
resp = send_recv(cmd_simple)
ok_simple = len(resp) >= 3 and (resp[2] & 0x80)
print(f"  Simple START:   cmd={cmd_simple.hex()} -> {'OK' if ok_simple else 'NACK'} resp={resp.hex()}")

resp = send_recv(bytes([0x12, 0x0D, 0x01, 0x00]))
print(f"  Status (simple): {resp.hex()}")

stop_can()
auth()

# Extended start with 500K
cmd_ext = bytes([0x12, 0x0E, 0x06, 0x00, 0x00, 0x00]) + struct.pack(">I", 0x00070A02)
resp = send_recv(cmd_ext)
ok_ext = len(resp) >= 3 and (resp[2] & 0x80)
print(f"  Extended START: cmd={cmd_ext.hex()} -> {'OK' if ok_ext else 'NACK'} resp={resp.hex()}")

resp = send_recv(bytes([0x12, 0x0D, 0x01, 0x00]))
print(f"  Status (extended): {resp.hex()}")

stop_can()

usb.util.release_interface(dev, 0)
print("\nDone.")
