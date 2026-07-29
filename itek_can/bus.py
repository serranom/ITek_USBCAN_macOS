"""
python-can BusABC implementation for iTek USBCAN adapters.

Usage:
    import can
    bus = can.Bus(interface='itek', channel=0, bitrate=500000)
    bus.send(can.Message(arbitration_id=0x123, data=[1, 2, 3]))
    msg = bus.recv(timeout=1.0)
"""

import logging
from typing import Optional

import can

from .driver import ITeKDevice
from .protocol import MODE_LISTEN_ONLY, MODE_NORMAL

logger = logging.getLogger(__name__)


class ITeKBus(can.BusABC):
    """python-can interface for iTek USBCAN adapters.

    Parameters
    ----------
    channel : int
        CAN channel index (usually 0).
    bitrate : int
        Arbitration bitrate in bps (e.g. 250_000, 500_000).
        Set per-session via InitCAN (0x12 0x03); supported rates are the
        keys of ``protocol.BTR_SJA1000``. No Windows/ECANTools step needed.
    device : int
        USB device index when multiple adapters are connected.
    mode : str
        ``"normal"`` or ``"listen"`` (listen-only / monitor mode).
    """

    def __init__(
        self,
        channel: int = 0,
        bitrate: int = 500_000,
        device: int = 0,
        mode: str = "normal",
        can_filters=None,
        **kwargs,
    ):
        super().__init__(channel=channel, can_filters=can_filters, **kwargs)

        if isinstance(channel, str):
            channel = int(channel)
        self._channel = channel

        work_mode = MODE_LISTEN_ONLY if mode == "listen" else MODE_NORMAL

        self._device = ITeKDevice(device_index=device)
        self._device.authenticate()

        info = self._device.get_board_info()
        hw_ver = info.get("hw_version", 0)
        fw_ver = info.get("fw_version", 0)
        serial = info.get("serial", "")
        hw_type = info.get("hw_type", "USBCAN")

        self._device.configure(
            channel=channel,
            bitrate=bitrate,
            mode=work_mode,
        )

        actual_bitrate = self._device.get_bitrate()
        bitrate_str = f"{actual_bitrate // 1000}K" if actual_bitrate else "unknown"
        self.channel_info = (
            f"iTek {hw_type} ch{channel} @ {bitrate_str} "
            f"(SN:{serial}, HW:v{hw_ver}, FW:v{fw_ver})"
        )
        logger.info("Board: %s", self.channel_info)

        self._device.start(channel)

    # ── BusABC interface ────────────────────────────────────────────────────

    def send(self, msg: can.Message, timeout: Optional[float] = None) -> None:
        self._device.send_message(msg, self._channel)

    def _recv_internal(
        self, timeout: Optional[float]
    ) -> tuple[Optional[can.Message], bool]:
        msg = self._device.recv(self._channel, timeout=timeout)
        return msg, False

    def shutdown(self) -> None:
        super().shutdown()
        if self._device:
            self._device.close()
            self._device = None
