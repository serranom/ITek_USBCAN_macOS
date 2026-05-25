#!/usr/bin/env python3
"""
Quick probe script to test the new iTekCANFD protocol against the live device.

Run:  python test_new_protocol.py

Tests each step independently so we can see exactly where things work or fail.
"""

import logging
import os
import struct
import sys
import traceback

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")

import usb.core
import usb.util

# ── Step 0: Find and claim the device ──────────────────────────────────────

print("=" * 60)
print("Step 0: Find USB device")
print("=" * 60)

dev = usb.core.find(idVendor=0x0471, idProduct=0x1200)
if dev is None:
    dev = usb.core.find(idVendor=0x1FC9, idProduct=0x0100)
if dev is None:
    print("ERROR: No iTek device found")
    sys.exit(1)

print(f"Found: VID=0x{dev.idVendor:04X} PID=0x{dev.idProduct:04X}")
print(f"  Manufacturer: {dev.manufacturer}")
print(f"  Product: {dev.product}")

try:
    if dev.is_kernel_driver_active(0):
        dev.detach_kernel_driver(0)
except (usb.core.USBError, NotImplementedError):
    pass

usb.util.claim_interface(dev, 0)

# Enumerate endpoints
cfg = dev.get_active_configuration()
intf = cfg[(0, 0)]
ep_addrs = sorted(ep.bEndpointAddress for ep in intf)
print(f"  Endpoints: {[f'0x{a:02X}' for a in ep_addrs]}")
has_ep83 = 0x83 in ep_addrs
print(f"  Has EP 0x83 (new-style RX): {has_ep83}")
print()


def send_recv(data: bytes, timeout: int = 2000) -> bytes:
    """Send on EP 0x01, receive on EP 0x81."""
    dev.write(0x01, data, timeout=timeout)
    return bytes(dev.read(0x81, 64, timeout=timeout))


# ── Step 1: SM4 Authentication ─────────────────────────────────────────────

print("=" * 60)
print("Step 1: SM4 Authentication")
print("=" * 60)

from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

challenge = os.urandom(16)
sm4 = CryptSM4()
sm4.set_key(b"itekon2012usbcan", SM4_ENCRYPT)
expected = sm4.crypt_ecb(challenge)

# Try new-format auth (0x11 0xE0)
print("\n--- New auth format (0x11 0xE0) ---")
auth_new = bytearray(51)
auth_new[0] = 0x11
auth_new[1] = 0xE0
auth_new[2] = 0x30
auth_new[7:23] = challenge

try:
    resp = send_recv(bytes(auth_new))
    print(f"  Response ({len(resp)}B): {resp.hex()}")
    print(f"  resp[2] = 0x{resp[2]:02X} ({'ERROR' if resp[2] == 0xB0 else 'OK'})")
    if len(resp) >= 23:
        device_answer = resp[7:23]
        match = device_answer == expected[:16]
        print(f"  Challenge match: {match}")
        if match:
            print("  >>> NEW AUTH WORKS!")
        else:
            print(f"  Expected: {expected[:16].hex()}")
            print(f"  Got:      {device_answer.hex()}")
except usb.core.USBError as e:
    print(f"  USB Error: {e}")

# Try legacy auth (0x13 0xB0) — re-generate challenge
print("\n--- Legacy auth format (0x13 0xB0) ---")
challenge2 = os.urandom(16)
expected2 = sm4.crypt_ecb(challenge2)
auth_old = bytes([0x13, 0xB0, 0x11, 0x00]) + challenge2

try:
    resp = send_recv(auth_old)
    print(f"  Response ({len(resp)}B): {resp.hex()}")
    if len(resp) >= 20:
        device_answer = resp[4:20]
        match = device_answer == expected2[:16]
        print(f"  Challenge match: {match}")
        if match:
            print("  >>> LEGACY AUTH WORKS!")
except usb.core.USBError as e:
    print(f"  USB Error: {e}")

print()

# ── Step 2: GetDeviceInfo (new format) ─────────────────────────────────────

print("=" * 60)
print("Step 2: GetDeviceInfo (0x11 0x03)")
print("=" * 60)

cmd = bytearray(51)
cmd[0] = 0x11
cmd[1] = 0x03
cmd[2] = 0x30

try:
    resp = send_recv(bytes(cmd))
    print(f"  Response ({len(resp)}B): {resp.hex()}")
    print(f"  resp[2] = 0x{resp[2]:02X} ({'ERROR' if resp[2] == 0xB0 else 'OK'})")
    if resp[2] != 0xB0:
        can_num = resp[3]
        hw_ver = f"V{resp[4]}.{resp[5]}.{resp[6]}"
        fw_ver = f"V{resp[7]}.{resp[8]}.{resp[9]}"
        hw_type = bytes(resp[10:30]).split(b"\x00")[0].decode("ascii", errors="replace")
        serial = bytes(resp[30:46]).split(b"\x00")[0].decode("ascii", errors="replace")
        print(f"  CAN channels: {can_num}")
        print(f"  HW version:   {hw_ver}")
        print(f"  FW version:   {fw_ver}")
        print(f"  HW type:      {hw_type}")
        print(f"  Serial:       {serial}")
        print("  >>> GET_DEVICE_INFO WORKS!")
    else:
        print("  Device returned error")
except usb.core.USBError as e:
    print(f"  USB Error: {e}")

print()

# ── Step 3: InitCAN (new format) ───────────────────────────────────────────

print("=" * 60)
print("Step 3: InitCAN (0x11 0x04) — 500K bitrate, classic CAN")
print("=" * 60)

ABIT_500K = 0x00070A02

init_cmd = bytearray(51)
init_cmd[0] = 0x11
init_cmd[1] = 0x04
init_cmd[2] = 0x30
init_cmd[3] = 0x00
init_cmd[4] = 0       # channel 0
init_cmd[5] = 0       # can_type = CAN (not CANFD)
init_cmd[6] = 0       # CANFDStandard = ISO
init_cmd[7] = 0       # CANFDSpeedup = no
init_cmd[8] = 0       # workMode = normal
struct.pack_into(">I", init_cmd, 9, ABIT_500K)    # abit_timing
struct.pack_into(">I", init_cmd, 13, ABIT_500K)   # dbit_timing (same for CAN)

try:
    resp = send_recv(bytes(init_cmd))
    print(f"  Response ({len(resp)}B): {resp.hex()}")
    print(f"  resp[2] = 0x{resp[2]:02X} ({'ERROR' if resp[2] == 0xB0 else 'OK'})")
    if resp[2] != 0xB0:
        print("  >>> INIT_CAN WORKS!")
    else:
        print(f"  Error code: 0x{resp[3]:02X}")
except usb.core.USBError as e:
    print(f"  USB Error: {e}")

print()

# ── Step 4: SetFilter (new format) ─────────────────────────────────────────

print("=" * 60)
print("Step 4: SetFilter (0x11 0x05)")
print("=" * 60)

# Standard filter: accept all
filt_cmd = bytearray(51)
filt_cmd[0] = 0x11
filt_cmd[1] = 0x05
filt_cmd[2] = 0x30
filt_cmd[3] = 0x00
filt_cmd[4] = 0       # channel
filt_cmd[5] = 0       # index
filt_cmd[6] = 0       # frameType = standard
filt_cmd[7] = 0       # filterType = range
struct.pack_into(">I", filt_cmd, 8, 0x000)    # ID1
struct.pack_into(">I", filt_cmd, 12, 0x7FF)   # ID2

try:
    resp = send_recv(bytes(filt_cmd))
    print(f"  Std filter resp ({len(resp)}B): {resp.hex()}")
    print(f"  resp[2] = 0x{resp[2]:02X} ({'ERROR' if resp[2] == 0xB0 else 'OK'})")
except usb.core.USBError as e:
    print(f"  USB Error: {e}")

# Extended filter: accept all
filt_cmd[6] = 1       # frameType = extended
struct.pack_into(">I", filt_cmd, 8, 0x000)
struct.pack_into(">I", filt_cmd, 12, 0x1FFFFFFF)

try:
    resp = send_recv(bytes(filt_cmd))
    print(f"  Ext filter resp ({len(resp)}B): {resp.hex()}")
    print(f"  resp[2] = 0x{resp[2]:02X} ({'ERROR' if resp[2] == 0xB0 else 'OK'})")
    if resp[2] != 0xB0:
        print("  >>> SET_FILTER WORKS!")
except usb.core.USBError as e:
    print(f"  USB Error: {e}")

print()

# ── Step 5: StartCAN (new format) ──────────────────────────────────────────

print("=" * 60)
print("Step 5: StartCAN (0x11 0x06)")
print("=" * 60)

start_cmd = bytearray(51)
start_cmd[0] = 0x11
start_cmd[1] = 0x06
start_cmd[2] = 0x30
start_cmd[3] = 0     # channel 0

try:
    resp = send_recv(bytes(start_cmd))
    print(f"  Response ({len(resp)}B): {resp.hex()}")
    print(f"  resp[2] = 0x{resp[2]:02X} ({'ERROR' if resp[2] == 0xB0 else 'OK'})")
    if resp[2] != 0xB0:
        print("  >>> START_CAN WORKS!")
except usb.core.USBError as e:
    print(f"  USB Error: {e}")

print()

# ── Step 6: Test TX (send one CAN frame) ───────────────────────────────────

print("=" * 60)
print("Step 6: TX test — send CAN frame ID=0x123 data=[01 02 03 04]")
print("=" * 60)

# TX format: [0x21, can_type, num_frames] + frame(s)
# Frame (24 bytes): [0:8]=ts, [9]=ch, [10]=cantype, [11]=len, [12:16]=id_BE, [16:24]=data
tx_header = bytes([0x21, 0x00, 0x01])  # CAN classic, 1 frame
tx_frame = bytearray(24)
tx_frame[9] = 0       # channel 0, send_type 0
tx_frame[10] = 0      # cantype = CAN
tx_frame[11] = 4      # DLC
struct.pack_into(">I", tx_frame, 12, 0x123)  # CAN ID
tx_frame[16:20] = bytes([0x01, 0x02, 0x03, 0x04])

tx_data = tx_header + bytes(tx_frame)
print(f"  TX payload ({len(tx_data)}B): {tx_data.hex()}")

try:
    dev.write(0x02, tx_data, timeout=2000)
    print("  Bulk write OK")

    # Read TX ACK
    rx_ep = 0x82 if has_ep83 else 0x81
    try:
        ack = bytes(dev.read(rx_ep, 64, timeout=500))
        print(f"  TX ACK from EP 0x{rx_ep:02X} ({len(ack)}B): {ack.hex()}")
        if len(ack) > 3:
            print(f"  Frames sent successfully: {ack[3]}")
    except usb.core.USBTimeoutError:
        print(f"  No TX ACK from EP 0x{rx_ep:02X} (timeout)")
except usb.core.USBError as e:
    print(f"  USB Error: {e}")

print()

# ── Step 7: ResetCAN (stop) ────────────────────────────────────────────────

print("=" * 60)
print("Step 7: ResetCAN (0x11 0x07) — stop channel 0")
print("=" * 60)

stop_cmd = bytearray(51)
stop_cmd[0] = 0x11
stop_cmd[1] = 0x07
stop_cmd[2] = 0x30
stop_cmd[3] = 0     # channel 0

try:
    resp = send_recv(bytes(stop_cmd))
    print(f"  Response ({len(resp)}B): {resp.hex()}")
    print(f"  resp[2] = 0x{resp[2]:02X} ({'ERROR' if resp[2] == 0xB0 else 'OK'})")
    if resp[2] != 0xB0:
        print("  >>> RESET_CAN WORKS!")
except usb.core.USBError as e:
    print(f"  USB Error: {e}")

print()

# ── Step 8: isConnected ────────────────────────────────────────────────────

print("=" * 60)
print("Step 8: isConnected (0x11 0x08)")
print("=" * 60)

conn_cmd = bytearray(51)
conn_cmd[0] = 0x11
conn_cmd[1] = 0x08
conn_cmd[2] = 0x30
conn_cmd[3] = 0xAA

try:
    resp = send_recv(bytes(conn_cmd))
    print(f"  Response ({len(resp)}B): {resp.hex()}")
    print(f"  resp[2] = 0x{resp[2]:02X} ({'ERROR' if resp[2] == 0xB0 else 'OK'})")
    if resp[2] != 0xB0:
        print("  >>> IS_CONNECTED WORKS!")
except usb.core.USBError as e:
    print(f"  USB Error: {e}")

print()

# ── Cleanup ────────────────────────────────────────────────────────────────

usb.util.release_interface(dev, 0)
print("Done — device released.")
print()

# ── Summary ────────────────────────────────────────────────────────────────

print("=" * 60)
print("SUMMARY")
print("=" * 60)
print("Run this script with the adapter plugged in.")
print("Check which steps show '>>> ... WORKS!' above.")
print("If all pass, the new protocol driver should work.")
