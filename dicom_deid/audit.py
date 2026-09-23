"""只读 PHI 审计 —— 扫描 DICOM 目录，输出报告"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import os
import glob
import re

import pydicom

FALSE_POSITIVES = {
    "SmallestImagePixelValue", "LargestImagePixelValue",
    "SmallestPixelValueInSeries", "LargestPixelValueInSeries",
    "ImageType", "ImagePositionPatient", "ImageOrientationPatient",
    "NumberOfAverages", "ImagedNucleus", "SoftwareVersions", "ProtocolName",
}

PHI_KEYWORDS = [
    "patient", "physician", "operator", "institution", "address", "telephone",
    "personname", "birth", "accession", "studyid", "admission", "insurance",
    "ethnic", "military", "otherpatient", "referring", "performing", "requesting",
    "reading", "stationname", "deviceserial", "identif", "occupation", "comments",
]

# 文件名泄露检测特征串
FILENAME_NEEDLES = [
    "1.3.12.2.1107", "1.2.276.0.7230010", "57245",
]

# 非 DICOM 侧车/杂项扩展名（收集时跳过）
SIDECAR_EXTS = {
    ".xml", ".json", ".txt", ".csv", ".md", ".html", ".log",
    ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".pdf",
}

# UID 正则
UID_RE = re.compile(rb'\d\.\d[\d.]{8,}')
VENDOR_PREFIXES = (b"1.3.12.2.1107", b"1.2.276.0.7230010")


@dataclass
class TagInfo:
    tag: str = ""
    vr: str = ""
    count: int = 0
    samples: list[str] = field(default_factory=list)


@dataclass
class Consistency:
    patient_ids: list[str] = field(default_factory=list)
    patient_names: list[str] = field(default_factory=list)
    accession_numbers: list[str] = field(default_factory=list)
    study_uids: int = 0
    series_uids: int = 0
    sop_uids: int = 0


@dataclass
class AuditReport:
    dir: str = ""
    file_count: int = 0
    parse_errors: list[tuple[str, str]] = field(default_factory=list)
    phi_tags: dict[str, TagInfo] = field(default_factory=dict)
    person_names: dict[str, TagInfo] = field(default_factory=dict)
    private_tags: set[str] = field(default_factory=set)
    private_vendor_uids: dict[str, int] = field(default_factory=dict)
    filename_leaks: list[tuple[str, str]] = field(default_factory=list)
    consistency: Consistency = field(default_factory=Consistency)


def collect_dicom_files(directory: Path) -> list[Path]:
    """收集目录内 DICOM 文件 —— 不依赖扩展名。

    覆盖无损压缩导出的常见形态：.dcm/.dicom/.img/无扩展名、
    无 128 字节前导（魔数嗅探失败时试探解析兜底）。像素数据不依赖解码。
    """
    out = []
    for p in sorted(Path(directory).iterdir()):
        if not p.is_file() or p.suffix.lower() in SIDECAR_EXTS:
            continue
        if _looks_like_dicom(p):
            out.append(p)
    return out


def _looks_like_dicom(path: Path) -> bool:
    """DICOM 识别：前导魔数 (128 字节后 'DICM')，否则试探解析。"""
    try:
        with open(path, 'rb') as f:
            head = f.read(132)
    except OSError:
        return False
    if head[128:132] == b'DICM':
        return True
    # 无前导/无扩展名：试探解析（压缩传输语法只读元数据，不解像素）
    try:
        ds = pydicom.dcmread(str(path), stop_before_pixels=True, force=True)
    except Exception:
        return False
    return any(k in ds for k in
               ("SOPInstanceUID", "StudyInstanceUID", "Modality", "PatientName"))


def run(directory: Path, on_progress=None, extra_needles=()) -> AuditReport:
    files = collect_dicom_files(directory)
    fname_needles = list(FILENAME_NEEDLES) + [str(n) for n in extra_needles]
    rep = AuditReport(dir=str(directory), file_count=len(files))

    pids, pnames, accs = set(), set(), set()
    studies, series, sops = set(), set(), set()

    total = len(files)
    for idx, fp in enumerate(files, 1):
        if on_progress:
            on_progress(idx, total, fp.name)

        fname = fp.name

        for n in fname_needles:
            if n in fname:
                rep.filename_leaks.append((fname, n))

        try:
            ds = pydicom.dcmread(str(fp), force=True)
        except Exception as e:
            rep.parse_errors.append((fname, str(e)))
            continue

        for elem in ds:
            tag_str = f"({elem.tag.group:04X},{elem.tag.element:04X})"
            kw = getattr(elem, 'keyword', '') or ''
            vr = elem.VR

            is_priv = elem.tag.group % 2 == 1 and elem.tag.group > 0
            if is_priv:
                rep.private_tags.add(tag_str)

            # 私有块内 UID 子串扫描
            if is_priv:
                raw = elem.value
                if isinstance(raw, (bytes, bytearray)):
                    data = bytes(raw)
                elif hasattr(raw, 'value') and isinstance(raw.value, (bytes, bytearray)):
                    data = bytes(raw.value)
                else:
                    data = b''
                if data:
                    for uid in UID_RE.findall(data):
                        if uid.startswith(VENDOR_PREFIXES[0]) or uid.startswith(VENDOR_PREFIXES[1]):
                            rep.private_vendor_uids[uid.decode('ascii', errors='ignore')] = \
                                rep.private_vendor_uids.get(uid.decode('ascii', errors='ignore'), 0) + 1
                continue

            lkw = kw.lower()
            is_phi = any(k in lkw for k in PHI_KEYWORDS) and kw not in FALSE_POSITIVES

            try:
                val_str = str(elem.value)
            except Exception:
                val_str = "<unreadable>"
            short = val_str[:80]

            # PN 字段
            if vr == "PN" and val_str:
                info = rep.person_names.setdefault(kw, TagInfo(tag=tag_str, vr=str(vr)))
                info.count += 1
                if len(info.samples) < 5 and short not in info.samples:
                    info.samples.append(short)

            # PHI 标签（空值 = 已清空，不构成发现；脱敏输出重审计应洁净）
            if is_phi and val_str.strip():
                info = rep.phi_tags.setdefault(kw, TagInfo(tag=tag_str, vr=str(vr)))
                info.count += 1
                if len(info.samples) < 5 and short not in info.samples:
                    info.samples.append(short)

            # 一致性
            match kw:
                case "PatientID": pids.add(val_str)
                case "PatientName": pnames.add(val_str)
                case "AccessionNumber": accs.add(val_str)
                case "StudyInstanceUID": studies.add(val_str)
                case "SeriesInstanceUID": series.add(val_str)
                case "SOPInstanceUID": sops.add(val_str)

    rep.consistency = Consistency(
        patient_ids=sorted(pids), patient_names=sorted(pnames),
        accession_numbers=sorted(accs),
        study_uids=len(studies), series_uids=len(series), sop_uids=len(sops),
    )
    return rep