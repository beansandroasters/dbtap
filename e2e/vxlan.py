"""Wrap pcap packets in VXLAN (UDP 4789) to simulate Traffic Mirroring locally.

Usage:
    uv run --no-project e2e/vxlan.py wrap in.pcap out.pcap  # Test --pcap import
    uv run --no-project e2e/vxlan.py send in.pcap           # Send to 127.0.0.1:4789 for live --vxlan
"""
import socket
import struct
import sys
import time


def packets(path):
    with open(path, "rb") as f:
        head = f.read(24)
        assert struct.unpack("<I", head[:4])[0] == 0xA1B2C3D4, "Only microsecond-resolution pcap is supported"
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, usec, caplen, _ = struct.unpack("<IIII", h)
            yield sec, usec, f.read(caplen)


def wrap(frame, ident):
    vxlan = struct.pack(">II", 0x08000000, 42 << 8)
    udp_len = 8 + len(vxlan) + len(frame)
    udp = struct.pack(">HHHH", 50000 + ident % 1000, 4789, udp_len, 0)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, ident & 0xFFFF, 0, 64, 17, 0,
                     bytes([10, 9, 0, 1]), bytes([10, 9, 0, 2]))
    eth = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00"
    return eth + ip + udp + vxlan + frame


mode, src = sys.argv[1], sys.argv[2]
if mode == "wrap":
    skipped = 0
    with open(sys.argv[3], "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for n, (sec, usec, frame) in enumerate(packets(src)):
            # Outer IP length is 16-bit; oversized offloaded frames cannot be wrapped.
            if len(frame) + 36 > 65535:
                skipped += 1
                continue
            w = wrap(frame, n)
            out.write(struct.pack("<IIII", sec, usec, len(w), len(w)) + w)
    print(f"Frames too large to wrap: {skipped}")
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    n = 0
    for sec, usec, frame in packets(src):
        if len(frame) + 8 > 65000:
            continue
        s.sendto(struct.pack(">II", 0x08000000, 42 << 8) + frame, ("127.0.0.1", 4789))
        n += 1
        if n % 200 == 0:
            time.sleep(0.001)
    print(f"Frames sent: {n}")
