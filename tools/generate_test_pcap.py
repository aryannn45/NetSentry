#!/usr/bin/env python3
"""Generate a small classic PCAP exercising DNS, HTTP and scan detection."""

import argparse
import struct
import time


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet_ipv4(protocol, source, destination, transport):
    source_ip = bytes(map(int, source.split(".")))
    destination_ip = bytes(map(int, destination.split(".")))
    total_length = 20 + len(transport)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        protocol,
        0,
        source_ip,
        destination_ip,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return b"\x00" * 12 + b"\x08\x00" + header + transport


def tcp_packet(source_port, destination_port, payload=b"", flags=0x02):
    header = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        0,
        0,
        (5 << 12) | flags,
        65535,
        0,
        0,
    )
    return header + payload


def udp_packet(source_port, destination_port, payload):
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def dns_query(name):
    labels = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split("."))
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\0" + b"\0\x01\0\x01"


def packets():
    yield ethernet_ipv4(
        17,
        "192.0.2.10",
        "198.51.100.53",
        udp_packet(53000, 53, dns_query("www.example.com")),
    )
    request = b"GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"
    yield ethernet_ipv4(
        6, "192.0.2.10", "198.51.100.20", tcp_packet(51000, 80, request, 0x18)
    )
    for destination_port in (22, 23, 445):
        yield ethernet_ipv4(
            6,
            "203.0.113.9",
            "198.51.100.20",
            tcp_packet(40000, destination_port),
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", help="output classic PCAP file")
    args = parser.parse_args()
    now = int(time.time())
    with open(args.output, "wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets()):
            output.write(struct.pack("<IIII", now + index, 0, len(packet), len(packet)))
            output.write(packet)
    print("Wrote {} Ethernet packets to {}".format(sum(1 for _ in packets()), args.output))


if __name__ == "__main__":
    main()
