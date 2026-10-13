"""UID 长度保持重映射"""
from __future__ import annotations
import hashlib
import os
import re
from dataclasses import dataclass, field

ROOT = "1.2.826.0.1.3680043.10.9999."
SHORT_ROOT = "2.25."

# UID 字节串正则与厂商 UID 前缀（全项目唯一来源，csa/audit 共用）
UID_RE = re.compile(rb'\d\.\d[\d.]{8,}')
VENDOR_PREFIXES = ("1.3.12.2.1107", "1.2.276.0.7230010", "1.2.840.113619", "1.3.46.670589")


def _remap_len_preserving(old: str, salt: bytes) -> str | None:
    L = len(old)
    if L == 0:
        return None
    if L > len(ROOT):
        root, digits = ROOT, L - len(ROOT)
    else:
        if L <= len(SHORT_ROOT):
            return None
        root, digits = SHORT_ROOT, L - len(SHORT_ROOT)
    # 随机盐让假 UID 不可按公开算法反推、跨运行不可关联；映射留档于 uid_map.json
    h = hashlib.sha256(salt + f"DEID|{old}".encode()).hexdigest()
    # 取模不取高位截断：十进制高位首位永不为 0，短 UID 小空间会留出永远不可达的死槽；
    # 但 UID 组件禁止前导零（"0" 本身合法）：d>=2 时限定首位 1-9
    if digits == 1:
        num = str(int(h[:32], 16) % 10)
    else:
        num = str(int(h[:32], 16) % (10 ** digits - 10 ** (digits - 1)) + 10 ** (digits - 1))
    out = root + num
    return out[:L] if len(out) > L else out


@dataclass
class UidMap:
    _map: dict[str, str] = field(default_factory=dict)
    _used: set[str] = field(default_factory=set)
    _salt: bytes = field(default_factory=lambda: os.urandom(16))

    def get_or_insert(self, old: str) -> tuple[str, bool] | None:
        if old in self._map:
            return self._map[old], False
        new = _remap_len_preserving(old, self._salt)
        # 短 UID 输出空间极小（长度 29 只有 10 个候选值），撞名加盐重试找空位
        n = 0
        while new is not None and new in self._used:
            n += 1
            if n > 999:
                raise ValueError(f"UID 重映射空间不足: {old}")
            new = _remap_len_preserving(old, self._salt + str(n).encode())
        if new is None:
            return None
        self._map[old] = new
        self._used.add(new)
        return new, True

    def get(self, old: str) -> str | None:
        return self._map.get(old)

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self._map)

    @property
    def size(self) -> int:
        return len(self._map)

    def validate(self) -> str | None:
        seen: set[str] = set()
        for o, n in self._map.items():
            if len(o) != len(n):
                return f"长度不一致: {o} ({len(o)}) -> {n} ({len(n)})"
            if n in seen:
                return f"重复的新 UID: {n}"
            seen.add(n)
        return None
