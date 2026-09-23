"""脱敏主流程"""
from __future__ import annotations
import os
import glob
import re
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import pydicom

from .policy import Policy, Profile
from .uid_map import UidMap
from .csa import process_blob

UID_RE = re.compile(rb'\d\.\d[\d.]{8,}')

# 厂商 UID 前缀
VENDOR_PREFIXES = ("1.3.12.2.1107", "1.2.276.0.7230010")

# CSA 私有块标签
CSA_TAGS = [(0x0029, 0x1010), (0x0029, 0x1020)]

# XML 脱敏标签
XML_CLEAR_TAGS = {
    '00080050', '00080080', '00080081', '00080090', '00081010', '00081030',
    '00081040', '00081050', '00100010', '00100020', '00100030', '00181000',
    '00200010', '00400253', '00400009', '00400280',
}


@dataclass
class Summary:
    src_files: int = 0
    out_files: int = 0
    tags_cleared: int = 0
    uids_remapped: int = 0
    csa_uids_replaced: int = 0
    renamed_files: int = 0
    uid_map_size: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)
    pixel_identical: int = 0


def _walk_clear(ds: pydicom.Dataset, clear_kws: set[str], log: list[dict]) -> int:
    """递归清空 PHI，返回清除数"""
    n = 0
    to_clear = []
    seqs = []

    for elem in ds:
        if elem.keyword == "PixelData":
            continue
        if elem.VR == "SQ":
            seqs.append(elem)
            continue
        kw = elem.keyword or ""
        if kw not in clear_kws:
            continue
        try:
            val = str(elem.value)
        except Exception:
            val = ""
        if val:
            to_clear.append(elem)

    for elem in to_clear:
        old = elem.value
        elem.value = ""
        n += 1
        log.append({
            'kw': elem.keyword,
            'tag': str(elem.tag),
            'vr': str(elem.VR),
            'old': str(old)[:80],
            'new': '',
        })

    for seq_elem in seqs:
        if seq_elem.value:
            for item in seq_elem.value:
                n += _walk_clear(item, clear_kws, log)

    return n


def _remap_uids(ds: pydicom.Dataset, uid_kws: set[str], uid_map: UidMap) -> int:
    """UID 长度保持重映射"""
    n = 0
    for elem in ds:
        kw = elem.keyword or ""
        if kw in uid_kws:
            old = str(elem.value)
            if old:
                r = uid_map.get_or_insert(old)
                if r:
                    new, _ = r
                    if len(new) == len(old):
                        elem.value = new
                        n += 1
    return n


def _fix_csa(ds: pydicom.Dataset, uid_map: UidMap) -> tuple[int, list[str]]:
    """CSA 私有块内厂商 UID 等长替换"""
    from .csa import process_blob as _process_blob
    from pydicom.tag import Tag
    total = 0
    errors = []
    for (g, e) in CSA_TAGS:
        tag = Tag(g, e)
        if tag not in ds:
            continue
        blob = bytes(ds[tag].value)
        new_blob, res = _process_blob(blob, uid_map)
        total += res.replaced
        if not res.length_preserved:
            errors.append(f"CSA ({g:04X},{e:04X}) 长度变化，已回滚")
            continue
        for u in res.unmapped:
            errors.append(f"CSA 内 UID 无法映射: {u}")
        ds[tag].value = new_blob
    return total, errors


def _set_str(ds: pydicom.Dataset, keyword: str, value: str):
    """设置字符串标签（仅在已存在时更新）"""
    try:
        ds[keyword].value = value
    except KeyError:
        pass


def run(src: Path, out: Path, policy: Policy,
        on_progress: Callable[[int, int, str], None] | None = None,
        dry_run: bool = False) -> Summary:
    """执行脱敏。dry_run=True 时走完全流程但不写任何文件。"""
    if not dry_run:
        os.makedirs(out, exist_ok=True)

    from .audit import collect_dicom_files
    files = collect_dicom_files(src)

    summary = Summary(src_files=len(files))
    uid_map = UidMap()

    total = len(files)
    for idx, fp in enumerate(files, 1):
        if on_progress:
            on_progress(idx, total, Path(fp).name)

        try:
            ds = pydicom.dcmread(fp, force=True)
            log = []

            # 清空 PHI
            clear_kws = policy.clear_keywords()
            n_clear = _walk_clear(ds, clear_kws, log)
            summary.tags_cleared += n_clear

            # UID 重映射
            uid_kws = Policy.uid_keywords()
            n_uid = _remap_uids(ds, uid_kws, uid_map)
            summary.uids_remapped += n_uid

            # CSA 私有块
            csa_n, csa_errs = _fix_csa(ds, uid_map)
            summary.csa_uids_replaced += csa_n
            summary.errors.extend([(Path(fp).name, e) for e in csa_errs])

            # 审计标记
            _set_str(ds, "PatientIdentityRemoved", "YES")
            _set_str(ds, "DeidentificationMethod", policy.profile.method_text)

            # 输出
            if policy.rename_files:
                out_name = f"{ds.SOPInstanceUID}.dcm"
            else:
                out_name = Path(fp).name
            out_path = out / out_name
            if not dry_run:
                ds.save_as(str(out_path), write_like_original=False)
            summary.out_files += 1

            if policy.rename_files and out_name != Path(fp).name:
                summary.renamed_files += 1

        except Exception as e:
            summary.errors.append((Path(fp).name, f"{type(e).__name__}: {e}"))

    # UID 映射表
    summary.uid_map_size = uid_map.size
    if dry_run:
        return summary
    uid_map_path = out / "uid_map.json"
    with open(uid_map_path, 'w', encoding='utf-8') as fh:
        json.dump(uid_map.mapping, fh, ensure_ascii=False, indent=2)

    # XML 处理
    xml_files = sorted(glob.glob(str(src / "*.xml")))
    if xml_files:
        with open(xml_files[0], 'r', encoding='utf-8-sig') as fh:
            raw = fh.read()
        for old, new in uid_map.mapping.items():
            if old in raw:
                raw = raw.replace(old, new)
        pat = re.compile(r'<Attribute Tag="([0-9A-Fa-f]{8})" VR="([A-Z]{2})">(.*?)</Attribute>', re.S)
        def repl(m):
            if m.group(1).upper() in XML_CLEAR_TAGS:
                return f'<Attribute Tag="{m.group(1)}" VR="{m.group(2)}"></Attribute>'
            return m.group(0)
        raw = pat.sub(repl, raw)
        study_new = uid_map.get("1.2.276.0.7230010.3.1.2.2843334150.21124.1789818734.943") or "study"
        xml_out = out / f"{study_new}.xml"
        with open(xml_out, 'w', encoding='utf-8') as fh:
            fh.write(raw)

    return summary