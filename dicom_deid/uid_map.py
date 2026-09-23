"""UID 长度保持重映射"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field


ROOT = "1.2.826.0.1.3680043.10.9999."
SHORT_ROOT = "2.25."


def _remap_len_preserving(old: str) -> str | None:
    L = len(old)
    if L == 0:
        return None
    if L > len(ROOT):
        root, digits = ROOT, L - len(ROOT)
    else:
        if L <= len(SHORT_ROOT):
            return None
        root, digits = SHORT_ROOT, L - len(SHORT_ROOT)
    h = hashlib.sha256(f"DEID|{old}".encode()).hexdigest()
    num = str(int(h[:32], 16)).zfill(digits)[:digits]
    out = root + num
    return out[:L] if len(out) > L else out


@dataclass
class UidMap:
    _map: dict[str, str] = field(default_factory=dict)

    def get_or_insert(self, old: str) -> tuple[str, bool] | None:
        if old in self._map:
            return self._map[old], False
        new = _remap_len_preserving(old)
        if new is None:
            return None
        if len(new) != len(old):
            return None
        self._map[old] = new
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

    def find_uids_in_bytes(self, data: bytes) -> list[str]:
        """从字节流中提取所有 UID 格式的字符串"""
        out: list[str] = []
        i = 0
        n = len(data)
        while i < n:
            if data[i:i+1].isdigit() and i + 2 < n and data[i+1:i+2] == b'.' and data[i+2:i+3].isdigit():
                start = i
                while i < n and (data[i:i+1].isdigit() or data[i:i+1] == b'.'):
                    i += 1
                try:
                    s = data[start:i].decode('ascii')
                    if s.count('.') >= 2 and len(s) >= 10:
                        if s not in out:
                            out.append(s)
                except UnicodeDecodeError:
                    pass
            else:
                i += 1
        return out

    @staticmethod
    def is_vendor_uid(uid: str) -> bool:
        return (uid.startswith("1.3.12.2.1107")
                or uid.startswith("1.2.276.0.7230010")
                or uid.startswith("1.2.840.113619")
                or uid.startswith("1.3.46.670589"))