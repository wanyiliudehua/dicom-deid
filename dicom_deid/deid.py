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

# CSA 私有块标签
CSA_TAGS = [(0x0029, 0x1010), (0x0029, 0x1020)]


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
    """UID 长度保持重映射（含嵌套 Sequence）"""
    n = 0
    for elem in ds:
        if elem.VR == "SQ":
            for item in elem.value or []:
                n += _remap_uids(item, uid_kws, uid_map)
            continue
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
    from pydicom.tag import Tag
    total = 0
    errors = []
    for (g, e) in CSA_TAGS:
        tag = Tag(g, e)
        if tag not in ds:
            continue
        blob = bytes(ds[tag].value)
        new_blob, res = process_blob(blob, uid_map)
        if not res.length_preserved:
            errors.append(f"CSA ({g:04X},{e:04X}) 长度变化，已回滚")
            continue
        total += res.replaced
        for u in res.unmapped:
            errors.append(f"CSA 内 UID 无法映射: {u}")
        ds[tag].value = new_blob
    return total, errors


def run(src: Path, out: Path, policy: Policy,
        on_progress: Callable[[int, int, str], None] | None = None,
        dry_run: bool = False, force: bool = False) -> Summary:
    """执行脱敏。dry_run=True 时走完全流程但不写任何文件。"""
    if not dry_run:
        os.makedirs(out, exist_ok=True)
        existing = list(out.rglob("*.dcm"))
        if existing and not force:
            raise ValueError(f"输出目录已含 {len(existing)} 个 .dcm，可能与新产物混叠；请换空目录或允许覆盖(force)")

    from .audit import collect_dicom_files
    # 输出目录若嵌套在源目录内，排除其中文件，避免把自己的产物当输入（尤其 --force 重跑时）
    out_res = out.resolve()
    files = [f for f in collect_dicom_files(src)
             if not f.resolve().is_relative_to(out_res)]

    summary = Summary(src_files=len(files))
    uid_map = UidMap()
    clear_kws = policy.clear_keywords()  # 提出循环：全量 DICOM 词典扫描只做一次
    written: set[str] = set()

    total = len(files)
    for idx, fp in enumerate(files, 1):
        if on_progress:
            on_progress(idx, total, Path(fp).name)

        try:
            ds = pydicom.dcmread(fp, force=True)
            log = []

            # 清空 PHI
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

            # 审计标记（无条件写入，下游靠它识别已脱敏）
            ds.PatientIdentityRemoved = "YES"
            ds.DeidentificationMethod = policy.profile.method_text

            # 输出：镜像源目录结构；目录名若是已知旧 UID（按检查号/StudyUID 分目录的导出），
            # 同步换成新 UID，否则目录名会把原 UID 泄露出去
            rel = Path(fp).relative_to(src)
            rel_dir = Path(*(uid_map.get(p) or p for p in rel.parent.parts))
            if policy.rename_files:
                name = f"{ds.SOPInstanceUID}.dcm"
            else:
                name = rel.name  # --keep-filename：保持原名（⚠ 文件名可能泄露）
            out_rel = rel_dir / name
            key = out_rel.as_posix()
            if key in written:
                summary.errors.append((str(rel), f"输出名冲突: {key}（重复 SOPInstanceUID），已跳过"))
                continue
            written.add(key)
            out_path = out / out_rel
            if not dry_run:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                ds.save_as(str(out_path), write_like_original=False)
            summary.out_files += 1

            if policy.rename_files and name != rel.name:
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

    # XML 侧车：全部处理；UID 按词边界整体替换，防止短 UID 截坏长 UID
    # 只匹配叶子属性（内容不含 <Attribute），否则父级 SQ 的匹配会把第一个子属性整个吞掉
    pat = re.compile(r'<Attribute Tag="([0-9A-Fa-f]{8})" VR="([A-Z]{2})">((?:(?!<Attribute)[\s\S])*?)</Attribute>')
    from pydicom.datadict import dictionary_keyword
    def repl(m):
        # 与 DICOM 同一套清空规则（标签号→关键词），性别/年龄/体重/日期/姓名随策略清
        if dictionary_keyword(int(m.group(1), 16)) in clear_kws:
            return f'<Attribute Tag="{m.group(1)}" VR="{m.group(2)}"></Attribute>'
        return m.group(0)
    xml_files = [xf for xf in
                 sorted(glob.glob(str(src / "**" / "*.xml"), recursive=True))
                 if not Path(xf).resolve().is_relative_to(out_res)]
    for i, xf in enumerate(xml_files, 1):
        with open(xf, 'r', encoding='utf-8-sig') as fh:
            raw = fh.read()
        mapping = uid_map.mapping
        if mapping:
            uid_pat = re.compile(r'\b(?:' + '|'.join(sorted(map(re.escape, mapping), key=len, reverse=True)) + r')\b')
            raw = uid_pat.sub(lambda m: mapping[m.group(0)], raw)
        raw = pat.sub(repl, raw)
        # 侧车输出同样镜像目录结构（deid_N.xml 命名，原文件名可能是 UID）
        xrel = Path(xf).relative_to(src)
        xdir = Path(*(uid_map.get(p) or p for p in xrel.parent.parts))
        out_x = out / xdir / f"deid_{i}.xml"
        out_x.parent.mkdir(parents=True, exist_ok=True)
        with open(out_x, 'w', encoding='utf-8') as fh:
            fh.write(raw)

    return summary