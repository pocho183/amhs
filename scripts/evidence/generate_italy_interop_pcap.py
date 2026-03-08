#!/usr/bin/env python3
import argparse
import socket
import struct
from pathlib import Path


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4_header(src: str, dst: str, payload_len: int, ident: int) -> bytes:
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    flags_frag = 0x4000
    ttl = 64
    proto = 6
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    csum = checksum(hdr)
    return hdr[:10] + struct.pack("!H", csum) + hdr[12:]


def tcp_header(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    offset_reserved = (5 << 4)
    window = 4096
    urg = 0
    header = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, offset_reserved, flags, window, 0, urg)
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src),
        socket.inet_aton(dst),
        0,
        6,
        len(header) + len(payload),
    )
    csum = checksum(pseudo + header + payload)
    return struct.pack("!HHLLBBHHH", sport, dport, seq, ack, offset_reserved, flags, window, csum, urg)


def write_pcap(path: Path, packets: list[bytes]) -> None:
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for idx, pkt in enumerate(packets):
            ts_sec = 1735689600 + idx
            ts_usec = 0
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)))
            f.write(pkt)


def build_frame(src_mac: bytes, dst_mac: bytes, src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes, ident: int) -> bytes:
    ip = ipv4_header(src_ip, dst_ip, 20 + len(payload), ident)
    tcp = tcp_header(src_ip, dst_ip, sport, dport, seq, ack, flags, payload)
    eth = dst_mac + src_mac + b"\x08\x00"
    return eth + ip + tcp + payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deterministic Italy interop campaign PCAP")
    parser.add_argument("output", help="Output pcap path")
    args = parser.parse_args()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    peer_a_mac = bytes.fromhex("021122334455")
    peer_b_mac = bytes.fromhex("0266778899aa")
    gw_mac = bytes.fromhex("02aabbccddee")

    packets: list[bytes] = []
    scenarios = [
        ("ENAV-OPS", "BIND submit status report release", "127.0.0.11", 31021, "127.0.0.20", 102),
        ("MIL-NET", "RTSE/ROSE bind submit release", "127.0.0.12", 31022, "127.0.0.20", 102),
        ("METEO-LEGACY", "BER bind submit status with legacy directoryName", "127.0.0.13", 31023, "127.0.0.20", 102),
    ]

    for i, (peer, message, src_ip, sport, dst_ip, dport) in enumerate(scenarios, start=1):
        payload_req = f"{peer}|REQ|{message}".encode()
        payload_rsp = f"{peer}|RSP|OK".encode()
        seq = 1000 * i
        ack = 2000 * i
        packets.append(build_frame(peer_a_mac if i == 1 else peer_b_mac, gw_mac, src_ip, dst_ip, sport, dport, seq, 0, 0x18, payload_req, i))
        packets.append(build_frame(gw_mac, peer_a_mac if i == 1 else peer_b_mac, dst_ip, src_ip, dport, sport, ack, seq + len(payload_req), 0x18, payload_rsp, i + 100))

    write_pcap(out, packets)


if __name__ == "__main__":
    main()
