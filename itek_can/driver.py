"""
iTek USBCAN device driver — handles USB communication, authentication,
configuration, and CAN frame TX/RX via pyusb.

Implements the legacy protocol (0x12/0x13 prefix) for the old hardware
(VID 0x0471, PID 0x1200).

Reference: iTekon-usb C library (2018, "grool")
"""

import logging
import os
import struct
import threading
import time
from collections import deque
from typing import Optional

import usb.core
import usb.util
import can

from .protocol import (
    VENDOR_ID,
    PRODUCT_ID,
    EP_INT_OUT,
    EP_INT_IN,
    EP_BULK_OUT,
    EP_BULK_IN,
    FRAME_SIZE,
    MAX_FRAMES_PER_TX,
    MODE_NORMAL,
    cmd_auth_legacy,
    cmd_set_bitrate,
    cmd_set_filter,
    cmd_start,
    cmd_stop,
    cmd_hw_version,
    cmd_fw_version,
    cmd_can_count,
    cmd_serial,
    cmd_hw_type,
    cmd_get_config,
    cmd_get_status,
    check_response_ok,
    parse_string_response,
    parse_version_response,
    parse_config_bitrate,
    pack_frame,
    unpack_frame,
)
from .sm4 import sm4_encrypt_ecb

logger = logging.getLogger(__name__)

USB_TIMEOUT_MS = 2000
RX_POLL_TIMEOUT_MS = 10


class ITeKDevice:
    """Low-level driver for an iTek USBCAN adapter (VID 0x0471, PID 0x1200).

    Lifecycle:
        dev = ITeKDevice()
        dev.authenticate()
        info = dev.get_board_info()
        dev.configure(channel=0, bitrate=500000)
        dev.start(channel=0)
        # ... TX/RX ...
        dev.close()
    """

    def __init__(self, device_index: int = 0):
        dev = self._find_device(device_index)
        self._dev = dev
        self._lock = threading.Lock()  # protects EP 0x01 / 0x81 command channel
        self._rx_queues: dict[int, deque[can.Message]] = {
            0: deque(maxlen=10_000),
            1: deque(maxlen=10_000),
        }
        self._rx_thread: Optional[threading.Thread] = None
        self._running = False
        self._active_channels: set[int] = set()
        self._can_channels: int = 1

        # Detach kernel driver if active (Linux)
        try:
            if self._dev.is_kernel_driver_active(0):
                self._dev.detach_kernel_driver(0)
        except (usb.core.USBError, NotImplementedError):
            pass

        usb.util.claim_interface(self._dev, 0)
        logger.info(
            "iTek device opened (index %d, VID:PID %04X:%04X)",
            device_index, dev.idVendor, dev.idProduct,
        )

    @staticmethod
    def _find_device(device_index: int):
        """Find the device by VID/PID."""
        devices = list(
            usb.core.find(
                idVendor=VENDOR_ID, idProduct=PRODUCT_ID, find_all=True
            )
        )
        if not devices:
            raise can.CanInitializationError(
                f"No iTek USBCAN device found "
                f"(VID:PID 0x{VENDOR_ID:04X}:0x{PRODUCT_ID:04X})"
            )
        if device_index >= len(devices):
            raise can.CanInitializationError(
                f"Device index {device_index} out of range (found {len(devices)})"
            )
        return devices[device_index]

    # ── Command channel ─────────────────────────────────────────────────────

    def send_command(self, cmd: bytes, timeout: int = USB_TIMEOUT_MS) -> bytes:
        """Send a command on the interrupt endpoint and return the response."""
        with self._lock:
            self._dev.write(EP_INT_OUT, cmd, timeout=timeout)
            resp = self._dev.read(EP_INT_IN, 64, timeout=timeout)
            return bytes(resp)

    # ── Authentication ──────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Perform SM4 challenge-response authentication.

        Uses the legacy 0x13 0xB0 format (only format supported by this hardware).
        The SM4 key is hardcoded: b"itekon2012usbcan".
        """
        challenge = os.urandom(16)
        expected = sm4_encrypt_ecb(challenge)
        resp = self.send_command(cmd_auth_legacy(challenge))

        if len(resp) >= 20 and resp[4:20] == expected[:16]:
            logger.info("SM4 authentication OK")
            return

        raise can.CanInitializationError(
            "SM4 authentication failed — wrong key or unsupported firmware"
        )

    # ── Board info ─────────────────────────────────────────────────────────

    def get_board_info(self) -> dict:
        """Read board information using individual query commands.

        Returns dict with keys: hw_version, fw_version, can_channels,
        serial, hw_type.
        """
        info = {}

        try:
            resp = self.send_command(cmd_hw_version())
            info["hw_version"] = parse_version_response(resp)
        except usb.core.USBError:
            info["hw_version"] = 0

        try:
            resp = self.send_command(cmd_fw_version())
            info["fw_version"] = parse_version_response(resp)
        except usb.core.USBError:
            info["fw_version"] = 0

        try:
            resp = self.send_command(cmd_can_count())
            if check_response_ok(resp) and len(resp) > 3:
                info["can_channels"] = resp[len(resp) - 1]
                self._can_channels = info["can_channels"]
            else:
                info["can_channels"] = 1
        except usb.core.USBError:
            info["can_channels"] = 1

        try:
            resp = self.send_command(cmd_serial())
            info["serial"] = parse_string_response(resp)
        except usb.core.USBError:
            info["serial"] = ""

        try:
            resp = self.send_command(cmd_hw_type())
            info["hw_type"] = parse_string_response(resp)
        except usb.core.USBError:
            info["hw_type"] = ""

        return info

    # ── Bitrate readback ───────────────────────────────────────────────────

    def get_bitrate(self) -> int:
        """Read the device's current bitrate from the GET_CONFIG registers.

        Parses the SJA1000-style BTR0/BTR1 bytes in the GET_CONFIG response
        using a 36 MHz CAN peripheral clock (typical for STM32-based adapters).

        Returns the bitrate in bps, or 0 if it can't be determined.
        """
        try:
            resp = self.send_command(cmd_get_config())
            return parse_config_bitrate(resp)
        except usb.core.USBError as e:
            logger.warning("GET_CONFIG failed: %s", e)
            return 0

    # ── Configuration ───────────────────────────────────────────────────────

    def configure(
        self,
        channel: int,
        bitrate: int,
        mode: int = MODE_NORMAL,
    ) -> None:
        """Configure a CAN channel (bitrate + filters).

        On firmware v791, the SET_BITRATE (0x12 0x23) and SET_FILTER (0x12 0x24)
        commands are not supported and will be skipped. The device uses whatever
        bitrate is stored in its flash memory (configured via ECANTools on Windows).

        On older firmware, these commands work normally.
        """
        # Try SET_BITRATE — may fail on newer firmware
        try:
            resp = self.send_command(cmd_set_bitrate(channel, bitrate, mode))
            if check_response_ok(resp):
                logger.info("Bitrate set to %d bps on channel %d", bitrate, channel)
            else:
                # Read back the actual bitrate from the device
                actual = self.get_bitrate()
                if actual and actual != bitrate:
                    logger.warning(
                        "SET_BITRATE rejected by firmware. "
                        "Device is configured at %d bps (requested %d). "
                        "Use ECANTools on Windows to change the stored bitrate.",
                        actual, bitrate,
                    )
                elif actual:
                    logger.info(
                        "SET_BITRATE not supported, but device is already at %d bps",
                        actual,
                    )
                else:
                    logger.warning(
                        "SET_BITRATE rejected and could not read back bitrate. "
                        "Use ECANTools on Windows to configure."
                    )
        except Exception as e:
            logger.warning("SET_BITRATE failed: %s — using device default", e)

        # Try SET_FILTER × 14 — may fail on newer firmware
        filters_ok = True
        for i in range(14):
            try:
                resp = self.send_command(cmd_set_filter(channel, i))
                if not check_response_ok(resp):
                    if i == 0:
                        logger.debug(
                            "SET_FILTER not supported by firmware — using device defaults."
                        )
                    filters_ok = False
                    break
            except usb.core.USBError:
                filters_ok = False
                break

        if filters_ok:
            logger.info("Filters configured on channel %d", channel)

    # ── Start / Stop ────────────────────────────────────────────────────────

    def start(self, channel: int) -> None:
        """Start CAN on a channel and launch the RX thread if needed."""
        resp = self.send_command(cmd_start(channel))
        if not check_response_ok(resp):
            raise can.CanInitializationError(
                f"StartCAN failed on channel {channel}: {resp.hex()}"
            )

        self._active_channels.add(channel)

        if not self._running:
            self._running = True
            self._rx_thread = threading.Thread(
                target=self._rx_worker, daemon=True, name="itek-rx"
            )
            self._rx_thread.start()

        logger.info("Channel %d started", channel)

    def stop(self, channel: int) -> None:
        """Stop (reset) a CAN channel."""
        self._active_channels.discard(channel)
        try:
            resp = self.send_command(cmd_stop(channel))
            if check_response_ok(resp):
                logger.info("Channel %d stopped", channel)
            else:
                logger.warning("Stop channel %d: NACK", channel)
        except usb.core.USBError as e:
            logger.warning("Stop channel %d: %s", channel, e)

    # ── TX ──────────────────────────────────────────────────────────────────

    def send_message(self, msg: can.Message, channel: int) -> None:
        """Send a single CAN message."""
        self.send_messages([msg], channel)

    def send_messages(self, msgs: list[can.Message], channel: int) -> None:
        """Send a batch of CAN messages.

        The old protocol batches up to 3 frames per bulk write (57 bytes).
        After each write, a TX ACK is read from interrupt EP 0x81.
        """
        # Split into batches of MAX_FRAMES_PER_TX (3)
        for batch_start in range(0, len(msgs), MAX_FRAMES_PER_TX):
            batch = msgs[batch_start : batch_start + MAX_FRAMES_PER_TX]
            payload = b"".join(pack_frame(m, channel) for m in batch)

            self._dev.write(EP_BULK_OUT, payload, timeout=USB_TIMEOUT_MS)

            # Read TX ACK from interrupt endpoint
            # The old C driver does this after every bulk TX write
            with self._lock:
                try:
                    self._dev.read(EP_INT_IN, 10, timeout=1000)
                except usb.core.USBTimeoutError:
                    logger.debug("TX ACK timeout (batch of %d frames)", len(batch))
                except usb.core.USBError as e:
                    logger.debug("TX ACK read error: %s", e)

    # ── RX ──────────────────────────────────────────────────────────────────

    def recv(
        self, channel: int, timeout: Optional[float] = None
    ) -> Optional[can.Message]:
        """Pop the next received message for *channel*, blocking up to *timeout*."""
        q = self._rx_queues.get(channel)
        if q is None:
            return None

        deadline = None if timeout is None else time.monotonic() + timeout

        while True:
            try:
                return q.popleft()
            except IndexError:
                pass

            if deadline is not None and time.monotonic() >= deadline:
                return None
            if deadline is None:
                return None
            time.sleep(0.001)

    def _rx_worker(self) -> None:
        """Background thread: polls EP 0x82, parses 19-byte frames into queues.

        Mirrors the handle_recv() function in the old C driver.
        """
        while self._running:
            try:
                data = bytes(
                    self._dev.read(EP_BULK_IN, FRAME_SIZE * 3, timeout=RX_POLL_TIMEOUT_MS)
                )
            except usb.core.USBTimeoutError:
                continue
            except usb.core.USBError as e:
                if self._running:
                    logger.warning("RX USB error: %s", e)
                break

            # Parse 19-byte frames
            num_frames = len(data) // FRAME_SIZE
            for i in range(num_frames):
                offset = i * FRAME_SIZE
                try:
                    channel, msg = unpack_frame(data, offset)
                    q = self._rx_queues.get(channel)
                    if q is not None:
                        q.append(msg)
                except Exception as e:
                    logger.debug("RX frame parse error at offset %d: %s", offset, e)

    # ── Status ─────────────────────────────────────────────────────────────

    def get_status(self, channel: int = 0) -> bytes:
        """Read CAN channel status. Returns raw response bytes."""
        return self.send_command(cmd_get_status(channel))

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def close(self) -> None:
        """Stop all channels, shut down the RX thread, release USB."""
        self._running = False

        for ch in list(self._active_channels):
            self.stop(ch)

        if self._rx_thread and self._rx_thread.is_alive():
            self._rx_thread.join(timeout=2.0)

        try:
            usb.util.release_interface(self._dev, 0)
        except usb.core.USBError:
            pass

        self._dev = None
        logger.info("iTek device closed")
