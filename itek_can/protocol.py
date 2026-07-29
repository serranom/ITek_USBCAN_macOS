"""
iTek USBCAN protocol — command builders, frame pack/unpack, bitrate tables.

Implements the legacy protocol (0x12/0x13 prefix, variable-length commands)
used by VID 0x0471 / PID 0x1200 adapters.

References:
  - iTekon-usb C library (2018, "grool") — original basis.
  - Disassembly of the vendor's ``usbcan.dll`` (CANalyst 1.1.9.17) — corrects
    the bitrate mechanism. See ``docs/PROTOCOL.md`` for the full command table.

Key correction from the DLL RE: the CAN bitrate is set via the InitCAN command
``0x12 0x03`` (SJA1000 BTR0/BTR1), NOT via ``0x12 0x23`` (which the firmware
NACKs). See ``cmd_init_can`` below.
"""

import struct
from typing import Optional

import can

# ── USB identifiers ────────────────────────────────────────────────────────

VENDOR_ID = 0x0471
PRODUCT_ID = 0x1200

# ── USB Endpoints ──────────────────────────────────────────────────────────

EP_INT_OUT = 0x01   # Interrupt OUT — command channel
EP_INT_IN = 0x81    # Interrupt IN  — command responses + TX ACK
EP_BULK_OUT = 0x02  # Bulk OUT      — CAN data TX
EP_BULK_IN = 0x82   # Bulk IN       — CAN data RX

# ── CAN frame wire format (old protocol) ───────────────────────────────────
# 19 bytes fixed per frame:
#   [0:4]   TimeStamp  (big-endian)
#   [4]     TimeFlag   (0=unused, 1=valid)
#   [5]     SendType   (0=normal, 1=single-shot)
#   [6]     Flags:  bit7 = ExternFlag (extended ID)
#                   bit6 = RemoteFlag (RTR)
#                   bit4 = CANIndex
#                   bits0-3 = DLC
#   [7:11]  CAN ID     (little-endian, native x86 byte order)
#   [11:19] Data bytes

FRAME_SIZE = 19
MAX_FRAMES_PER_TX = 3   # Device accepts max 3 frames per bulk write (57 bytes)

# ── Modes ──────────────────────────────────────────────────────────────────

MODE_NORMAL = 0
MODE_LISTEN_ONLY = 1

# ── Bitrate tables ─────────────────────────────────────────────────────────
# 32-bit values sent big-endian (network byte order) to the device.
# These are CAN controller bit-timing register configs.

BITRATES = {
    5_000:     0x00450257,
    10_000:    0x00120257,
    20_000:    0x0012012B,
    40_000:    0x00780031,
    50_000:    0x0067002C,
    80_000:    0x004B0018,
    100_000:   0x0012003B,
    125_000:   0x0012002F,
    200_000:   0x0027000E,
    250_000:   0x00120017,
    400_000:   0x00160008,
    500_000:   0x0012000B,
    666_000:   0x00240005,
    800_000:   0x00240004,
    1_000_000: 0x00120005,
}

# SJA1000-style bit-timing registers (Timing0/Timing1), as consumed by the
# vendor DLL's InitCAN command (0x12 0x03).  Standard 16 MHz table.
# Source: usbcan.dll VCI_InitCAN disassembly (reads pInitConfig->Timing0/Timing1).
BTR_SJA1000 = {
    1_000_000: (0x00, 0x14),
    500_000:   (0x00, 0x1C),
    250_000:   (0x01, 0x1C),
    125_000:   (0x03, 0x1C),
    100_000:   (0x04, 0x1C),
    50_000:    (0x09, 0x1C),
    20_000:    (0x18, 0x1C),
    10_000:    (0x31, 0x1C),
}


# ── Command builders ────────────────────────────────────────────────────────

def cmd_auth_legacy(challenge: bytes) -> bytes:
    """0x13 0xB0 — SM4 authentication.

    Send: [0x13, 0xB0, 0x11, 0x00, challenge[16]]  (20 bytes)
    Resp: [0x13, 0xB0, 0x11, 0x00, encrypted[16]]   (20 bytes)
    Verify: resp[4:20] == SM4_ECB("itekon2012usbcan", challenge)
    """
    assert len(challenge) == 16
    return bytes([0x13, 0xB0, 0x11, 0x00]) + challenge


def cmd_init_can(channel: int, bitrate: int, mode: int = MODE_NORMAL) -> bytes:
    """0x12 0x03 — InitCAN: set bit-timing (bitrate) + mode for a channel.

    This is the REAL bitrate mechanism, recovered from usbcan.dll's VCI_InitCAN
    (CANalyst 1.1.9.17).  The vendor tool sets the rate every session with this
    command — there is no separate "flash write" and no Windows/ECANTools
    dependency.  Replaces the bogus 0x12 0x23 path (see cmd_set_bitrate).

    Send: [0x12, 0x03, 0x04, 0x00, cm, BTR0, BTR1]  (7 bytes)
      cm   = (0x80 if listen-only) | (0x10 if channel == 1)
      BTR0 = SJA1000 Timing0,  BTR1 = SJA1000 Timing1  (from BTR_SJA1000)
    Success: resp[2] == 0x81.
    """
    if bitrate not in BTR_SJA1000:
        raise ValueError(
            f"Unsupported bitrate {bitrate}. "
            f"Supported (InitCAN/SJA1000): {sorted(BTR_SJA1000.keys())}"
        )
    btr0, btr1 = BTR_SJA1000[bitrate]
    cm = (0x80 if mode == MODE_LISTEN_ONLY else 0x00) | (0x10 if channel == 1 else 0x00)
    return bytes([0x12, 0x03, 0x04, 0x00, cm, btr0, btr1])


def cmd_set_acc_filter(
    channel: int,
    acc_code: int = 0x00000000,
    acc_mask: int = 0xFFFFFFFF,
    mode: int = MODE_NORMAL,
) -> bytes:
    """0x12 0x04 — set acceptance filter (AccCode/AccMask) for a channel.

    Recovered from usbcan.dll's VCI_InitCAN (issued right after 0x12 0x03).
    Defaults accept every frame.  Replaces the bogus 0x12 0x24 path.

    Send: [0x12, 0x04, 0x0A, 0x00, cm2, AccCode[BE4], AccMask[BE4]]  (13 bytes)
      cm2 = (0x40 if listen-only) | (0x10 if channel == 1)
    """
    cm2 = (0x40 if mode == MODE_LISTEN_ONLY else 0x00) | (0x10 if channel == 1 else 0x00)
    return (
        bytes([0x12, 0x04, 0x0A, 0x00, cm2])
        + struct.pack(">I", acc_code & 0xFFFFFFFF)
        + struct.pack(">I", acc_mask & 0xFFFFFFFF)
    )


def cmd_set_bitrate(channel: int, bitrate: int, mode: int = MODE_NORMAL) -> bytes:
    """0x12 0x23 — set bitrate and mode for a channel.

    DEPRECATED / SUPERSEDED.  This opcode does not exist on FW v791 (it NACKs)
    and is absent from the vendor DLL — it came from the 2018 "grool" C
    reference.  Use ``cmd_init_can`` (0x12 0x03) instead.  Kept only as a
    fallback for hypothetical older firmware.

    Send: [0x12, 0x23, 0x06, 0x00, mode_chan, BTR[4]]  (9 bytes)
      mode_chan = (mode << 7) | (channel << 4)
      BTR = bitrate value, big-endian
    """
    if bitrate not in BITRATES:
        raise ValueError(
            f"Unsupported bitrate {bitrate}. "
            f"Supported: {sorted(BITRATES.keys())}"
        )
    mode_chan = (mode << 7) | ((channel & 0x0F) << 4)
    return bytes([0x12, 0x23, 0x06, 0x00, mode_chan]) + struct.pack(">I", BITRATES[bitrate])


def cmd_set_filter(channel: int, index: int) -> bytes:
    """0x12 0x24 — set filter for a channel.

    DEPRECATED / SUPERSEDED by ``cmd_set_acc_filter`` (0x12 0x04). This opcode
    NACKs on FW v791 and is absent from the vendor DLL. Kept as a fallback.

    Send: [0x12, 0x24, 0x0B, index, flags, 0x00×9]  (14 bytes)
      byte[3] = filter index (0-13)
      byte[4] = flags: bit7=1 (enable?) | CANIndex
    """
    flags = (1 << 7) | (channel & 0x01)
    cmd = bytearray(14)
    cmd[0] = 0x12
    cmd[1] = 0x24
    cmd[2] = 0x0B
    cmd[3] = index & 0xFF
    cmd[4] = flags
    return bytes(cmd)


def cmd_start(channel: int) -> bytes:
    """0x12 0x0E — start CAN channel.

    Send: [0x12, 0x0E, 0x02, 0x00, chan_byte]  (5 bytes)
      chan_byte = channel << 4
    Resp: [0x12, 0x0E, status, ...]
      status & 0x80 != 0 means OK
    """
    return bytes([0x12, 0x0E, 0x02, 0x00, (channel & 0x0F) << 4])


def cmd_stop(channel: int) -> bytes:
    """0x12 0x0F — stop (reset) CAN channel.

    Send: [0x12, 0x0F, 0x02, 0x00, chan_byte]  (5 bytes)
    """
    return bytes([0x12, 0x0F, 0x02, 0x00, (channel & 0x0F) << 4])


def cmd_hw_version() -> bytes:
    """0x12 0x01 — read hardware version."""
    return bytes([0x12, 0x01, 0x01, 0x00])


def cmd_fw_version() -> bytes:
    """0x12 0x12 — read firmware version."""
    return bytes([0x12, 0x12, 0x01, 0x00])


def cmd_can_count() -> bytes:
    """0x12 0x13 — read number of CAN channels."""
    return bytes([0x12, 0x13, 0x01, 0x00])


def cmd_serial() -> bytes:
    """0x12 0x14 — read serial number."""
    return bytes([0x12, 0x14, 0x01, 0x00])


def cmd_hw_type() -> bytes:
    """0x12 0x15 — read hardware type string."""
    return bytes([0x12, 0x15, 0x01, 0x00])


def cmd_get_config() -> bytes:
    """0x12 0x06 — read channel configuration.

    Response data (10 bytes):
        [0]    channel?
        [1]    status / mode (0x01 = normal?)
        [2:6]  reserved / filter config
        [6]    BTR1 (SJA1000 style — TSEG1/TSEG2/SAM)
        [7]    BTR0 (SJA1000 style — BRP/SJW)
        [8:10] reserved
    """
    return bytes([0x12, 0x06, 0x01, 0x00])


def cmd_get_status(channel: int = 0) -> bytes:
    """0x12 0x0D — read CAN status."""
    return bytes([0x12, 0x0D, 0x01, 0x00])


# ── CAN controller clock (Hz) ─────────────────────────────────────────────
# The iTek USBCAN uses an STM32-class MCU with a 36 MHz APB1 clock driving
# the bxCAN peripheral.  This is needed to convert BTR register values back
# to a bitrate in bps.
CAN_CLOCK_HZ = 36_000_000


# ── Response parsing ────────────────────────────────────────────────────────

def check_response_ok(resp: bytes) -> bool:
    """Check if a command response indicates success.

    In the old protocol, byte[2] with bit 7 set (& 0x80 != 0) means OK.
    Response format: [0x12, sub_cmd, status, ...]
    """
    return len(resp) >= 3 and (resp[2] & 0x80) != 0


def parse_string_response(resp: bytes) -> str:
    """Extract a null-terminated ASCII string from response data.

    Data payload starts at byte 4, length = (byte[2] & 0x0F) - 1.
    """
    if not check_response_ok(resp):
        return ""
    data_len = (resp[2] & 0x0F)
    if data_len > 1 and len(resp) > 4:
        raw = resp[4 : 4 + data_len - 1]
        return raw.split(b"\x00")[0].decode("ascii", errors="replace")
    return ""


def parse_version_response(resp: bytes) -> int:
    """Extract a 16-bit version number from response data.

    Version is at resp[4:6], little-endian: (resp[5] << 8) | resp[4].
    """
    if not check_response_ok(resp) or len(resp) < 6:
        return 0
    return (resp[5] << 8) | resp[4]


def parse_config_bitrate(resp: bytes, clock_hz: int = CAN_CLOCK_HZ) -> int:
    """Extract the configured bitrate from a GET_CONFIG response.

    The response data bytes at offsets 6-7 (relative to data start, which is
    byte 3 of the full response) contain SJA1000-style bit timing registers:

        data[7] = BTR0:  [SJW1 SJW0 | BRP5..BRP0]
        data[6] = BTR1:  [SAM | TSEG2_2..TSEG2_0 | TSEG1_3..TSEG1_0]

    With a 36 MHz CAN peripheral clock:
        TQ       = 2 × BRP / f_clk
        bit_time = (1 + TSEG1 + TSEG2) × TQ
        bitrate  = 1 / bit_time

    Returns 0 if the response can't be parsed.
    """
    if not check_response_ok(resp):
        return 0
    # data starts at resp[3]; we need offsets 6 and 7 → resp[9] and resp[10]
    if len(resp) < 11:
        return 0

    btr1 = resp[9]   # data[6] — TSEG1, TSEG2, SAM
    btr0 = resp[10]  # data[7] — BRP, SJW

    brp   = (btr0 & 0x3F) + 1
    tseg1 = (btr1 & 0x0F) + 1
    tseg2 = ((btr1 >> 4) & 0x07) + 1
    bit_time_tq = 1 + tseg1 + tseg2

    tq = 2.0 * brp / clock_hz
    bitrate = round(1.0 / (bit_time_tq * tq))

    # Snap to nearest standard rate if within 1%
    for standard in sorted(BITRATES.keys()):
        if abs(bitrate - standard) / standard < 0.01:
            return standard

    return bitrate


# ── CAN frame packing (TX) ─────────────────────────────────────────────────

def pack_frame(msg: can.Message, channel: int = 0) -> bytes:
    """Pack a python-can Message into the 19-byte legacy wire format.

    Wire layout:
        [0:4]   TimeStamp  (big-endian, usually 0 for TX)
        [4]     TimeFlag   (0)
        [5]     SendType   (0 = normal)
        [6]     Flags:  bit7 = ExternFlag, bit6 = RemoteFlag,
                        bit4 = CANIndex, bits0-3 = DLC
        [7:11]  CAN ID     (little-endian)
        [11:19] Data       (padded with 0x00)
    """
    frame = bytearray(FRAME_SIZE)

    # TimeStamp — 0 for TX
    # TimeFlag = 0, SendType = 0

    # Flags byte
    flags = min(len(msg.data), 8) & 0x0F     # DLC in low nibble
    flags |= (channel & 0x01) << 4           # CANIndex in bit 4
    if msg.is_remote_frame:
        flags |= (1 << 6)                    # RemoteFlag
    if msg.is_extended_id:
        flags |= (1 << 7)                    # ExternFlag
    frame[6] = flags

    # CAN ID — little-endian (native byte order, same as x86)
    struct.pack_into("<I", frame, 7, msg.arbitration_id)

    # Data
    dlen = min(len(msg.data), 8)
    frame[11 : 11 + dlen] = msg.data[:dlen]

    return bytes(frame)


def pack_frames_batch(msgs: list[can.Message], channel: int = 0) -> bytes:
    """Pack multiple frames for a single bulk write (max 3 frames, 57 bytes)."""
    if len(msgs) > MAX_FRAMES_PER_TX:
        raise ValueError(f"Too many frames ({len(msgs)} > {MAX_FRAMES_PER_TX})")
    return b"".join(pack_frame(m, channel) for m in msgs)


# ── CAN frame unpacking (RX) ───────────────────────────────────────────────

def unpack_frame(data: bytes, offset: int = 0) -> tuple[int, can.Message]:
    """Unpack one 19-byte frame from bulk RX data.

    Returns: (channel_index, can.Message)
    """
    if len(data) - offset < FRAME_SIZE:
        raise ValueError(f"Not enough data for frame (have {len(data) - offset}, need {FRAME_SIZE})")

    timestamp_raw = struct.unpack_from(">I", data, offset)[0]
    time_flag = data[offset + 4]
    send_type = data[offset + 5]
    flags = data[offset + 6]

    dlc = flags & 0x0F
    channel = (flags >> 4) & 0x01
    is_remote = bool(flags & (1 << 6))
    is_extended = bool(flags & (1 << 7))

    # CAN ID — little-endian
    arb_id = struct.unpack_from("<I", data, offset + 7)[0]

    # Data
    payload = bytes(data[offset + 11 : offset + 11 + min(dlc, 8)])

    msg = can.Message(
        timestamp=timestamp_raw / 1000.0 if time_flag else 0.0,
        arbitration_id=arb_id,
        is_extended_id=is_extended,
        is_remote_frame=is_remote,
        dlc=dlc,
        data=payload,
        channel=channel,
    )
    return channel, msg


def parse_rx_bulk(data: bytes) -> list[tuple[int, can.Message]]:
    """Parse bulk RX data into frames.

    The old protocol sends raw 19-byte frames concatenated.
    The bulk read may return up to 3 frames (57 bytes).
    """
    results = []
    num_frames = len(data) // FRAME_SIZE

    for i in range(num_frames):
        offset = i * FRAME_SIZE
        try:
            results.append(unpack_frame(data, offset))
        except (ValueError, struct.error):
            break

    return results
