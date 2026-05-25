#!/usr/bin/env python3
"""
Deep probe of all working 0x12 sub-commands to find the bitrate-setting mechanism.
"""

import os
import struct
import sys

import usb.core
import usb.util
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

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
print(f"Device: {dev.manufacturer} {dev.product}\n")


def send_recv(data, timeout=2000):
    dev.write(0x01, data, timeout=timeout)
    return bytes(dev.read(0x81, 64, timeout=timeout))


def auth():
    challenge = os.urandom(16)
    sm4 = CryptSM4()
    sm4.set_key(b"itekon2012usbcan", SM4_ENCRYPT)
    expected = sm4.crypt_ecb(challenge)
    resp = send_recv(bytes([0x13, 0xB0, 0x11, 0x00]) + challenge)
    ok = resp[4:20] == expected[:16]
    if not ok:
        print("AUTH FAILED!")
        sys.exit(1)
    return ok


auth()
print("Auth OK\n")

# ── First, read all the known query commands to understand response format ──

print("=" * 60)
print("Reading all known query commands")
print("=" * 60)

queries = {
    0x01: "HW_VERSION",
    0x04: "CMD_04",
    0x06: "GET_CONFIG",
    0x0C: "CMD_0C",
    0x0D: "GET_STATUS",
    0x0E: "START_CAN",
    0x0F: "STOP_CAN",
    0x12: "FW_VERSION",
    0x13: "CAN_COUNT",
    0x14: "SERIAL_NUM",
    0x15: "HW_TYPE",
    0x80: "GET_CAPS",
    0xA1: "CMD_A1",
    0xA2: "CMD_A2",
    0xA3: "CMD_A3",
    0xA7: "CMD_A7",
    0xA9: "CMD_A9",
    0xEE: "CMD_EE",
}

for sub, name in queries.items():
    cmd = bytes([0x12, sub, 0x01, 0x00])
    try:
        resp = send_recv(cmd)
        ok = len(resp) >= 3 and (resp[2] & 0x80) != 0
        status = "OK" if ok else "NACK"
        print(f"  0x{sub:02X} ({name:12s}) -> {status}  resp={resp.hex()}")
    except usb.core.USBError as e:
        print(f"  0x{sub:02X} ({name:12s}) -> ERROR: {e}")

print()

# ── Probe 0xA1-0xA9 with longer payloads ────────────────────────────────

auth()

print("=" * 60)
print("Probing 0xA* commands with bitrate-like payloads")
print("=" * 60)

# Try sending each A* command with the structure of an InitCAN
# [0x12, sub, data_len, 0x00, channel, ...bitrate data...]
ABIT_500K = 0x00070A02

for sub in [0xA1, 0xA2, 0xA3, 0xA7, 0xA9, 0xEE]:
    print(f"\n  --- 0x{sub:02X} ---")
    for payload_len in [1, 2, 4, 6, 8, 10, 14, 20]:
        # Build a command with this payload length
        if payload_len == 1:
            payload = bytes([0x00])
        elif payload_len == 6:
            # Same format as old SET_BITRATE: [mode_chan, BTR[4]]
            payload = bytes([0x00]) + struct.pack(">I", ABIT_500K)
        elif payload_len == 10:
            # Maybe: [channel, can_type, mode, BTR[4], ...]
            payload = bytes([0x00, 0x00, 0x00]) + struct.pack(">I", ABIT_500K) + bytes(3)
        elif payload_len == 14:
            # Extended format
            payload = bytes([0x00, 0x00, 0x00]) + struct.pack(">I", ABIT_500K) + struct.pack(">I", ABIT_500K) + bytes(3)
        else:
            payload = bytes(payload_len)

        cmd = bytes([0x12, sub, payload_len, 0x00]) + payload
        try:
            resp = send_recv(cmd, timeout=500)
            ok = len(resp) >= 3 and (resp[2] & 0x80) != 0
            status = "OK" if ok else "NACK"
            print(f"    len={payload_len:2d} cmd={cmd[:12].hex()} -> {status} resp={resp.hex()}")
        except usb.core.USBTimeoutError:
            print(f"    len={payload_len:2d} -> TIMEOUT")
        except usb.core.USBError as e:
            print(f"    len={payload_len:2d} -> ERROR: {e}")

print()

# ── Probe 0x04, 0x06, 0x0C with longer payloads ────────────────────────

auth()

print("=" * 60)
print("Probing 0x04, 0x06, 0x0C, 0x0D with longer payloads")
print("=" * 60)

for sub in [0x04, 0x06, 0x0C, 0x0D]:
    print(f"\n  --- 0x{sub:02X} ---")
    for payload_len in [1, 2, 4, 6, 8, 10, 14]:
        if payload_len == 6:
            payload = bytes([0x00]) + struct.pack(">I", ABIT_500K)
        else:
            payload = bytes(payload_len)

        cmd = bytes([0x12, sub, payload_len, 0x00]) + payload
        try:
            resp = send_recv(cmd, timeout=500)
            ok = len(resp) >= 3 and (resp[2] & 0x80) != 0
            status = "OK" if ok else "NACK"
            # Show more of the response for OK responses
            resp_show = resp.hex() if len(resp) <= 20 else resp[:20].hex() + "..."
            print(f"    len={payload_len:2d} -> {status} resp={resp_show}")
        except usb.core.USBTimeoutError:
            print(f"    len={payload_len:2d} -> TIMEOUT")
        except usb.core.USBError as e:
            print(f"    len={payload_len:2d} -> ERROR: {e}")

print()

# ── Check 0x80 (GET_CAPS) response in detail ───────────────────────────

auth()

print("=" * 60)
print("GET_CAPS (0x80) detailed response")
print("=" * 60)

try:
    resp = send_recv(bytes([0x12, 0x80, 0x01, 0x00]))
    print(f"  Full response ({len(resp)}B): {resp.hex()}")
    if len(resp) >= 3 and (resp[2] & 0x80):
        data_len = resp[2] & 0x7F
        print(f"  Data length: {data_len}")
        payload = resp[3:]
        for i in range(0, len(payload), 16):
            hex_str = ' '.join(f'{b:02x}' for b in payload[i:i+16])
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload[i:i+16])
            print(f"    {i:3d}: {hex_str:48s}  {ascii_str}")
except usb.core.USBError as e:
    print(f"  ERROR: {e}")

print()

# ── Try the FULL old driver sequence exactly (claim, auth, bitrate, filters) ─

auth()

print("=" * 60)
print("Exact old-driver sequence: auth → bitrate → filter × 14")
print("=" * 60)

# Bitrate: 500K using OLD values
cmd_br = bytes([0x12, 0x23, 0x06, 0x00, 0x00]) + struct.pack(">I", 0x0012000B)
print(f"  Bitrate cmd: {cmd_br.hex()}")
try:
    resp = send_recv(cmd_br)
    ok_br = len(resp) >= 3 and (resp[2] & 0x80) != 0
    print(f"  Bitrate resp: {resp.hex()} -> {'OK' if ok_br else 'NACK'}")
except usb.core.USBError as e:
    print(f"  Bitrate: ERROR {e}")
    ok_br = False

if not ok_br:
    # Try without auth being done (re-auth and try immediately)
    print("  Retrying bitrate RIGHT after fresh auth...")
    usb.util.release_interface(dev, 0)
    usb.util.claim_interface(dev, 0)
    auth()
    try:
        resp = send_recv(cmd_br)
        ok_br = len(resp) >= 3 and (resp[2] & 0x80) != 0
        print(f"  Bitrate resp: {resp.hex()} -> {'OK' if ok_br else 'NACK'}")
    except usb.core.USBError as e:
        print(f"  Bitrate: ERROR {e}")

# ── Full sub-command scan looking for ANY command that accepts 6+ byte payload ─

auth()

print()
print("=" * 60)
print("Full scan: which commands accept 6-byte payload with bitrate?")
print("=" * 60)

# A bitrate-setting command likely accepts a 6+ byte payload
# We look for commands that return OK with this data
btr_payload = bytes([0x00]) + struct.pack(">I", 0x0012000B)

for sub in range(0x00, 0x100):
    if sub == 0x11:
        continue  # known to cause issues
    cmd = bytes([0x12, sub, 0x06, 0x00]) + btr_payload
    try:
        resp = send_recv(cmd, timeout=300)
        ok = len(resp) >= 3 and (resp[2] & 0x80) != 0
        if ok:
            print(f"  0x{sub:02X} -> OK  resp={resp.hex()}")
    except usb.core.USBTimeoutError:
        pass
    except usb.core.USBError as e:
        # Re-auth and continue
        try:
            usb.util.release_interface(dev, 0)
            usb.util.claim_interface(dev, 0)
            auth()
        except:
            pass

usb.util.release_interface(dev, 0)
print("\nDone.")
