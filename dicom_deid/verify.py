"""复验：确认脱敏产物无残留 PHI"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import os
import glob
import hashlib

NEEDLES = [
    b"Cheng", b"Yingping", b"1483304", b"19690402",
    b"MR12609191481", b"MR20260919202615",
    b"WanNan", b"YiJiShan", b"ZheShan", b"AWP57245", b"Department",
    b"1.3.12.2.1107", b"1.2.276.0.7230010", b"57245",
]


@dataclass
class VerifyResult:
    file_count: int = 0
    filename_hits: list[tuple[str, str]] = field(default_factory=list)
    content_hits: dict[str, int] = field(default_factory=dict)
    pixel_ok: int = 0
    pixel_bad: int = 0
    pixel_missing: int = 0
    study_uids: int = 0
    series_uids: int = 0
    sop_uids: int = 0
    baseline_checked: int = 0
    baseline_mismatch: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return (not self.filename_hits and not self.content_hits
                and self.pixel_bad == 0 and self.pixel_missing == 0
                and not self.baseline_mismatch)


def run(directory: Path, on_progress=None, extra_needles=()) -> VerifyResult:
    r = VerifyResult()
    needles = list(NEEDLES) + [
        n.encode('utf-8') if isinstance(n, str) else n for n in extra_needles
    ]
    files = sorted(glob.glob(str(directory / "*.dcm")))
    r.file_count = len(files)

    total = len(files)
    for idx, fp in enumerate(files, 1):
        if on_progress:
            on_progress(idx, total, Path(fp).name)
        fname = Path(fp).name

        # A. 文件名扫描
        for nd in needles:
            if nd in fname.encode('ascii', errors='ignore'):
                r.filename_hits.append((fname, nd.decode()))

        # B. 内容全字节扫描
        with open(fp, 'rb') as f:
            data = f.read()
        for nd in needles:
            cnt = data.count(nd)
            if cnt:
                r.content_hits[nd.decode()] = r.content_hits.get(nd.decode(), 0) + cnt

    return r