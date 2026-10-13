"""复验：确认脱敏产物无残留 PHI"""
from __future__ import annotations
import mmap
from dataclasses import dataclass, field
from pathlib import Path

from .audit import collect_dicom_files
from .uid_map import VENDOR_PREFIXES

# 通用特征串只留厂商 UID 前缀；具体患者/机构特征串由调用方经 extra_needles 传入
NEEDLES = [p.encode() for p in VENDOR_PREFIXES]


@dataclass
class VerifyResult:
    file_count: int = 0
    filename_hits: list[tuple[str, str]] = field(default_factory=list)
    content_hits: dict[str, int] = field(default_factory=dict)

    @property
    def all_passed(self) -> bool:
        return not self.filename_hits and not self.content_hits


def run(directory: Path, on_progress=None, extra_needles=()) -> VerifyResult:
    r = VerifyResult()
    needles = list(NEEDLES) + [
        n.encode('utf-8') if isinstance(n, str) else n for n in extra_needles
    ]
    # 与审计同一套 DICOM 识别（不依赖 .dcm 扩展名），避免漏检后"假通过"
    files = collect_dicom_files(directory)
    r.file_count = len(files)

    total = len(files)
    for idx, fp in enumerate(files, 1):
        if on_progress:
            on_progress(idx, total, fp.name)
        rel = fp.relative_to(directory).as_posix()

        # A. 路径扫描（文件名 + 目录名，目录名泄露同样致命）
        for nd in needles:
            if nd in rel.encode('ascii', errors='ignore'):
                r.filename_hits.append((rel, nd.decode()))

        # B. 内容全字节扫描（mmap 惰性分页，大文件不占内存）
        size = fp.stat().st_size
        if size:
            with open(fp, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                for nd in needles:
                    cnt, pos = 0, 0
                    while (i := mm.find(nd, pos)) != -1:
                        cnt += 1
                        pos = i + len(nd)
                    if cnt:
                        r.content_hits[nd.decode()] = r.content_hits.get(nd.decode(), 0) + cnt

    return r
