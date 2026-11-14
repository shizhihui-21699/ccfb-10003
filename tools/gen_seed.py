#!/usr/bin/env python3
"""Emit a small, valid seed corpus for the TLVX fuzzer.

Seeds are generated independently of the C encoder on purpose: if the seed
builder and the library disagreed on the wire format, the fuzzer would spend
its time rediscovering the format instead of exploring it.
"""
import os
import struct
import sys

HDR = b"TLVX" + bytes([1])


def uleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if (v == 0 and not (b & 0x40)) or (v == -1 and (b & 0x40)):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def length(n: int) -> bytes:
    if n <= 0x7F:
        return bytes([n])
    if n <= 0x1FFF:
        return bytes([0x80 | (n >> 8), n & 0xFF])
    if n <= 0xFFFFF:
        return bytes([0xC0 | (n >> 16), (n >> 8) & 0xFF, n & 0xFF])
    return b"\xE0" + uleb(n)


KIND = {"int": 0, "uint": 1, "bytes": 2, "str": 3, "bool": 4, "cont": 5, "skip": 6}


def field(tag: int, kind: str, value: bytes, opt_slot=None) -> bytes:
    t = KIND[kind] << 4
    if kind == "cont":
        t |= 0x80
    if opt_slot is not None:
        t |= 0x08 | opt_slot
    return uleb(tag) + bytes([t]) + length(len(value)) + value


def message(fields: bytes, bitmap: int = 0, flags: int = 0) -> bytes:
    region = bytes([bitmap]) + fields
    return HDR + struct.pack(">HI", flags, len(region)) + region


def scope(fields: bytes, bitmap: int = 0) -> bytes:
    return bytes([bitmap]) + fields


def seeds():
    yield "empty", message(b"")
    yield "uint_small", message(field(1, "uint", uleb(5)))
    yield "uint_big", message(field(1, "uint", uleb((1 << 56) - 1)))
    yield "int_neg", message(field(1, "int", sleb(-1)))
    yield "int_pos", message(field(1, "int", sleb((1 << 30) - 1)))
    yield "bool", message(field(1, "bool", b"\x01"))
    yield "bytes", message(field(1, "bytes", b"\xde\xad\xbe\xef"))
    yield "string_utf8", message(field(1, "str", "你好".encode()))
    yield "skip", message(field(1, "skip", b"\x00\x01\x02"))
    yield "optional", message(field(5, "uint", uleb(9), opt_slot=2), bitmap=1 << 2)
    yield "multi", message(
        field(1, "uint", uleb(1))
        + field(2, "bytes", b"ab")
        + field(3, "bool", b"\x00")
        + field(4, "int", sleb(-300))
    )
    yield "nested", message(field(1, "cont", scope(field(2, "uint", uleb(7)))))
    yield "nested3", message(
        field(1, "cont", scope(field(2, "cont", scope(field(3, "cont", scope(field(4, "uint", uleb(1))), 0), 0), 0), 0))
    )
    yield "opt_container", message(
        field(3, "cont", scope(field(1, "uint", uleb(2))), opt_slot=1), bitmap=1 << 1
    )
    yield "wide", message(b"".join(field(i, "uint", uleb(i)) for i in range(1, 40)))
    yield "long_bytes", message(field(1, "bytes", bytes(range(256)) * 4))
    yield "strict_flag", message(field(1, "uint", uleb(1)), flags=1)


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else "corpus/seed"
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for name, data in seeds():
        assert len(data) < 8192
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)
        n += 1
    print(f"wrote {n} seeds to {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
