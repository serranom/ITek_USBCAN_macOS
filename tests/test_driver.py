#!/usr/bin/env python3
"""
Integration test for the iTek USBCAN driver.

Tests the full lifecycle: open → auth → board info → configure → start → TX → stop → close.
"""

import logging
import sys
import time

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")

import can
from itek_can.driver import ITeKDevice
from itek_can.protocol import FRAME_SIZE, pack_frame, unpack_frame

# ── Step 1: Direct driver test ───────────────────────────────────────────

print("=" * 60)
print("Step 1: ITeKDevice — direct driver API")
print("=" * 60)

dev = ITeKDevice(device_index=0)

print("\n--- Authenticate ---")
dev.authenticate()
print("Auth OK")

print("\n--- Board Info ---")
info = dev.get_board_info()
for k, v in info.items():
    print(f"  {k}: {v}")

print("\n--- Configure (500K) ---")
dev.configure(channel=0, bitrate=500_000)

print("\n--- Start ---")
dev.start(channel=0)

print("\n--- Status ---")
status = dev.get_status(0)
print(f"  Raw: {status.hex()}")

print("\n--- TX test: send CAN frame ---")
msg = can.Message(
    arbitration_id=0x7DF,
    data=[0x02, 0x01, 0x00],
    is_extended_id=False,
)

# Show what we're packing
packed = pack_frame(msg, channel=0)
print(f"  Packed frame ({len(packed)}B): {packed.hex()}")

# Verify round-trip
ch, unpacked = unpack_frame(packed)
print(f"  Unpack: ch={ch} id=0x{unpacked.arbitration_id:X} "
      f"dlc={unpacked.dlc} data={unpacked.data.hex()} "
      f"ext={unpacked.is_extended_id} rtr={unpacked.is_remote_frame}")

# Send it
dev.send_message(msg, channel=0)
print("  TX sent (no error)")

print("\n--- Status after TX ---")
status = dev.get_status(0)
print(f"  Raw: {status.hex()}")

print("\n--- RX poll (2 seconds) ---")
t0 = time.time()
count = 0
while time.time() - t0 < 2.0:
    rx = dev.recv(0, timeout=0.1)
    if rx is not None:
        print(f"  RX: id=0x{rx.arbitration_id:X} data={rx.data.hex()}")
        count += 1
print(f"  Received {count} frames")

print("\n--- Stop ---")
dev.stop(0)

print("\n--- Close ---")
dev.close()
print("Device closed OK")

# ── Step 2: python-can Bus interface ─────────────────────────────────────

print("\n" + "=" * 60)
print("Step 2: ITeKBus — python-can BusABC interface")
print("=" * 60)

from itek_can.bus import ITeKBus

bus = ITeKBus(channel=0, bitrate=500_000)
print(f"\n  channel_info: {bus.channel_info}")

print("\n--- Send via Bus ---")
msg = can.Message(arbitration_id=0x123, data=[0x01, 0x02, 0x03, 0x04])
bus.send(msg)
print("  Sent OK")

print("\n--- Recv via Bus (1 second) ---")
rx = bus.recv(timeout=1.0)
if rx:
    print(f"  RX: id=0x{rx.arbitration_id:X} data={rx.data.hex()}")
else:
    print("  No data (expected if no CAN bus connected)")

print("\n--- Shutdown ---")
bus.shutdown()
print("  Bus shutdown OK")

# ── Step 3: Extended ID + RTR frame test ─────────────────────────────────

print("\n" + "=" * 60)
print("Step 3: Frame packing — extended ID and RTR")
print("=" * 60)

# Extended ID
ext_msg = can.Message(
    arbitration_id=0x18DAF100,
    data=[0x02, 0x3E, 0x00],
    is_extended_id=True,
)
packed = pack_frame(ext_msg, channel=0)
ch, unpacked = unpack_frame(packed)
print(f"  Extended: id=0x{unpacked.arbitration_id:08X} ext={unpacked.is_extended_id} "
      f"data={unpacked.data.hex()}")
assert unpacked.is_extended_id
assert unpacked.arbitration_id == 0x18DAF100

# RTR frame
rtr_msg = can.Message(
    arbitration_id=0x7DF,
    is_remote_frame=True,
    dlc=0,
    is_extended_id=False,
)
packed = pack_frame(rtr_msg, channel=0)
ch, unpacked = unpack_frame(packed)
print(f"  RTR:      id=0x{unpacked.arbitration_id:03X} rtr={unpacked.is_remote_frame} "
      f"dlc={unpacked.dlc}")
assert unpacked.is_remote_frame
assert unpacked.arbitration_id == 0x7DF

# Channel 1
ch1_msg = can.Message(arbitration_id=0x100, data=[0xFF])
packed = pack_frame(ch1_msg, channel=1)
ch, unpacked = unpack_frame(packed)
print(f"  Channel1: id=0x{unpacked.arbitration_id:03X} ch={ch}")
assert ch == 1

print("\nAll frame pack/unpack tests passed!")
print("\nDone.")
