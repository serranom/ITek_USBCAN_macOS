"""
iTek USBCAN Protocol Capture — Two Options

OPTION A: Wireshark + USBPcap (RECOMMENDED — no driver changes needed)
=========================================================================
1. Install Wireshark (https://www.wireshark.org/) — check "Install USBPcap" during setup
2. Reboot after install
3. Open Wireshark, start capture on the USBPcap interface where the iTek is connected
4. Open ECANTools and do the following sequence:
   a. Open device
   b. Set bitrate to 500K on channel 0
   c. Start CAN
   d. Send a test frame (any ID, any data)
   e. Stop CAN
   f. Change bitrate to 250K
   g. Start CAN again
   h. Stop and close device
5. Stop the Wireshark capture
6. File -> Export Specified Packets -> save as "itek_capture.pcapng"
7. Then run: python capture_protocol.py itek_capture.pcapng
   This will decode all the iTek USB commands from the capture.

OPTION B: pyusb sniffer (requires Zadig driver swap — ECANTools won't work simultaneously)
=========================================================================
Run:  python capture_protocol.py --live
This claims the USB device directly. You can't use ECANTools at the same time.
Instead, the script will exercise the device itself by sending known commands.

Usage:
    python capture_protocol.py <file.pcapng>     Parse a Wireshark capture
    python capture_protocol.py --live             Live USB monitor (requires WinUSB via Zadig)
"""

import sys
import struct
from datetime import datetime


def decode_command(data):
    """Decode an iTek command/response."""
    if len(data) < 2:
        return f"TOO_SHORT ({data.hex()})"

    if data[0] == 0x13 and len(data) >= 4:
        if data[1] == 0xB0:
            return f"SM4_AUTH challenge={data[4:20].hex()}" if len(data) >= 20 else "SM4_AUTH"

    if data[0] == 0x12:
        sub = data[1]
        known = {
            0x01: "HW_VERSION", 0x04: "CMD_04", 0x06: "GET_CONFIG",
            0x0C: "CMD_0C", 0x0D: "GET_STATUS", 0x0E: "START_CAN",
            0x0F: "STOP_CAN", 0x12: "FW_VERSION", 0x13: "CAN_COUNT",
            0x14: "SERIAL_NUM", 0x15: "HW_TYPE", 0x23: "SET_BITRATE_v1",
            0x24: "SET_FILTER_v1", 0x80: "GET_CAPS", 0xA1: "CMD_A1",
            0xA2: "CMD_A2", 0xA3: "CMD_A3", 0xA7: "CMD_A7",
            0xA9: "CMD_A9", 0xEE: "CMD_EE",
        }
        name = known.get(sub, f"CMD_{sub:02X}")

        if len(data) > 2:
            status_byte = data[2]
            is_response = bool(status_byte & 0x80)
            data_len = status_byte & 0x7F
            payload = data[3:] if len(data) > 3 else b""

            if is_response:
                return f"RESP {name} ok=True data_len={data_len} payload={payload.hex()}"
            else:
                return f"CMD  {name} len_field={status_byte} payload={payload.hex()}"

        return f"CMD  {name}"

    return f"UNKNOWN prefix=0x{data[0]:02X} data={data.hex()}"


def decode_can_frame(data, offset=0):
    """Decode a 19-byte CAN frame."""
    if len(data) - offset < 19:
        return None, ""

    frame = data[offset:offset + 19]
    timestamp = struct.unpack_from(">I", frame, 0)[0]
    time_flag = frame[4]
    send_type = frame[5]
    flags = frame[6]
    dlc = flags & 0x0F
    channel = (flags >> 4) & 1
    is_remote = bool(flags & 0x40)
    is_extended = bool(flags & 0x80)
    can_id = struct.unpack_from("<I", frame, 7)[0]
    payload = frame[11:11 + dlc]

    desc = (
        f"CAN ch{channel} ID=0x{can_id:X} DLC={dlc} "
        f"{'EXT' if is_extended else 'STD'} "
        f"{'RTR ' if is_remote else ''}"
        f"data=[{payload.hex()}] "
        f"ts={timestamp} send_type={send_type}"
    )
    return frame, desc


def parse_pcapng(filepath):
    """Parse a pcapng file and extract iTek USB transfers."""
    try:
        # Try using scapy for pcapng parsing
        from scapy.all import rdpcap, raw
        packets = rdpcap(filepath)
        print(f"Loaded {len(packets)} packets from {filepath}")
        print()
        print("NOTE: Full pcapng parsing requires USB layer dissection.")
        print("Showing raw packet summaries — look for bulk/interrupt transfers")
        print("to endpoints 0x01, 0x81, 0x02, 0x82")
        print()
        for i, pkt in enumerate(packets):
            data = raw(pkt)
            print(f"Packet {i:4d} ({len(data):4d}B): {data[:64].hex()}")
        return
    except ImportError:
        pass

    # Fallback: raw pcapng parsing for USB captures
    print(f"Parsing {filepath}...")
    print()

    with open(filepath, "rb") as f:
        raw_data = f.read()

    # Look for iTek USB data patterns in the raw capture
    # USB bulk/interrupt payloads containing our known command prefixes
    patterns = {
        b"\x13\xb0\x11\x00": "SM4_AUTH",
        b"\x12\x01": "HW_VERSION",
        b"\x12\x06": "GET_CONFIG",
        b"\x12\x0e": "START_CAN",
        b"\x12\x0f": "STOP_CAN",
        b"\x12\x12": "FW_VERSION",
        b"\x12\x13": "CAN_COUNT",
        b"\x12\x14": "SERIAL",
        b"\x12\x15": "HW_TYPE",
        b"\x12\x23": "SET_BITRATE_v1",
        b"\x12\x24": "SET_FILTER_v1",
    }

    print("Scanning for known iTek command patterns in raw capture data...")
    print("(For proper parsing, install scapy: pip install scapy)")
    print()

    found = []
    for offset in range(len(raw_data) - 2):
        for pattern, name in patterns.items():
            if raw_data[offset:offset + len(pattern)] == pattern:
                # Extract surrounding context (up to 64 bytes)
                context = raw_data[offset:min(offset + 64, len(raw_data))]
                # Trim at first occurrence of another pattern or null run
                decoded = decode_command(context[:20])
                found.append((offset, name, context[:32], decoded))

    print(f"Found {len(found)} potential command/response occurrences:")
    print()
    for offset, name, context, decoded in found:
        print(f"  offset=0x{offset:06X}: {decoded}")
        print(f"    raw: {context.hex()}")
        print()

    if not found:
        print("No known patterns found. The capture may be empty or in an unexpected format.")
        print("Try exporting from Wireshark as 'pcapng' with USBPcap dissector.")


def live_probe():
    """Live USB probe — requires WinUSB driver (Zadig)."""
    import usb.core
    import usb.util
    import os

    dev = usb.core.find(idVendor=0x0471, idProduct=0x1200)
    if dev is None:
        print("ERROR: iTek USBCAN not found")
        print("Make sure adapter is plugged in and driver is WinUSB (use Zadig)")
        sys.exit(1)

    print(f"Found: {dev.manufacturer} {dev.product}")

    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except (usb.core.USBError, NotImplementedError):
        pass

    usb.util.claim_interface(dev, 0)

    def send_recv(cmd):
        dev.write(0x01, cmd, timeout=2000)
        return bytes(dev.read(0x81, 64, timeout=2000))

    print()
    print("=== Full Command Scan ===")
    print()

    # Auth first
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
    challenge = os.urandom(16)
    auth_cmd = bytes([0x13, 0xB0, 0x11, 0x00]) + challenge
    resp = send_recv(auth_cmd)
    sm4 = CryptSM4()
    sm4.set_key(b"itekon2012usbcan", SM4_ENCRYPT)
    expected = sm4.crypt_ecb(challenge)
    auth_ok = resp[4:20] == expected[:16]
    print(f"AUTH: {'OK' if auth_ok else 'FAILED'}")
    if not auth_ok:
        usb.util.release_interface(dev, 0)
        return

    # Scan all commands with various payload sizes
    print()
    print("Scanning all sub-commands (0x00-0xFF) with 4-byte probe...")
    results = {}
    for sub in range(0x100):
        if sub == 0x11:  # skip known crasher
            continue
        cmd = bytes([0x12, sub, 0x01, 0x00])
        try:
            resp = send_recv(cmd)
            status = resp[2] if len(resp) > 2 else 0
            results[sub] = (resp, bool(status & 0x80))
            if status & 0x80:
                print(f"  0x{sub:02X} -> {resp.hex()} (OK)")
        except usb.core.USBError as e:
            print(f"  0x{sub:02X} -> USB ERROR: {e}")
            # Reconnect
            try:
                usb.util.release_interface(dev, 0)
            except:
                pass
            dev = usb.core.find(idVendor=0x0471, idProduct=0x1200)
            try:
                if dev.is_kernel_driver_active(0):
                    dev.detach_kernel_driver(0)
            except:
                pass
            usb.util.claim_interface(dev, 0)
            # Re-auth
            challenge = os.urandom(16)
            resp = send_recv(bytes([0x13, 0xB0, 0x11, 0x00]) + challenge)

    print()
    print(f"Total recognized commands: {sum(1 for _, ok in results.values() if ok)}")

    # For each recognized command, try with longer payloads
    print()
    print("=== Probing recognized commands with longer payloads ===")
    for sub, (resp, ok) in sorted(results.items()):
        if not ok:
            continue
        print(f"\n  0x{sub:02X}:")
        for plen in [1, 2, 4, 6, 8, 10, 14]:
            payload = bytes(plen)
            cmd = bytes([0x12, sub, plen, 0x00]) + payload
            try:
                resp = send_recv(cmd)
                print(f"    len={plen:2d}: {resp.hex()}")
            except:
                print(f"    len={plen:2d}: ERROR")
                break

    usb.util.release_interface(dev, 0)

    # Save results
    with open("probe_results.txt", "w") as f:
        f.write(f"iTek USBCAN Probe Results\n")
        f.write(f"Date: {datetime.now().isoformat()}\n\n")
        for sub, (resp, ok) in sorted(results.items()):
            f.write(f"0x{sub:02X}: {resp.hex()} {'OK' if ok else 'NACK'}\n")
    print("\nResults saved to probe_results.txt")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    if sys.argv[1] == "--live":
        live_probe()
    else:
        parse_pcapng(sys.argv[1])


if __name__ == "__main__":
    main()
