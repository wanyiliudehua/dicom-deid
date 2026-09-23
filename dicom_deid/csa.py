"""Siemens CSA 私有块内 UID 等长替换"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

from .uid_map import UidMap

UID_RE = re.compile(rb'\d\.\d[\d.]{8,}')

CSA_TAGS = [(0x0029, 0x1010), (0x0029, 0x1020)]

VENDOR_PREFIXES = ("1.3.12.2.1107", "1.2.276.0.7230010", "1.2.840.113619", "1.3.46.670589")


@dataclass
class CsaResult:
    replaced: int = 0
    unmapped: list[str] = field(default_factory=list)
    length_mismatch: list[str] = field(default_factory=list)
    length_preserved: bool = True


def process_blob(blob: bytes, uid_map: UidMap) -> tuple[bytes, CsaResult]:
    """对单个 CSA blob 做等长 UID 替换"""
    res = CsaResult(length_preserved=True)
    orig_len = len(blob)

    # 找出所有厂商 UID
    found = sorted(set(
        m.decode('ascii', errors='ignore')
        for m in UID_RE.findall(blob)
        if any(m.startswith(p.encode()) for p in VENDOR_PREFIXES)
    ), key=len, reverse=True)

    out = bytearray(blob)
    for old in found:
        r = uid_map.get_or_insert(old)
        if r is None:
            res.unmapped.append(old)
            continue
        new, _ = r
        if len(new) != len(old):
            res.length_mismatch.append(f"{old} -> {new}")
            continue
        # 等长字节替换
        ob = old.encode()
        nb = new.encode()
        i = 0
        while i + len(ob) <= len(out):
            if bytes(out[i:i+len(ob)]) == ob:
                out[i:i+len(ob)] = nb
                res.replaced += 1
                i += len(ob)
            else:
                i += 1

    if len(out) != orig_len:
        res.length_preserved = False
        return blob, res

    return bytes(out), res