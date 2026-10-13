"""核心逻辑最小回归测试：py tests/test_core.py"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pydicom
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset

from dicom_deid.csa import process_blob
from dicom_deid.deid import _remap_uids, run as deid_run
from dicom_deid.policy import Policy, Profile
from dicom_deid.uid_map import UidMap
from dicom_deid.verify import run as verify_run

SOP_CLASS = "1.2.840.10008.5.1.4.1.1.2"
BASE_UID = "1.2.840.113619.2.55.3.604688.111.1111.20200101111111"


def make_dcm(path: Path, sop_uid: str, nested_uid: str | None = None) -> None:
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = SOP_CLASS
    meta.MediaStorageSOPInstanceUID = sop_uid
    meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"
    ds = FileDataset(str(path), {}, file_meta=meta, preamble=b"\0" * 128)
    ds.SOPClassUID = SOP_CLASS
    ds.SOPInstanceUID = sop_uid
    ds.StudyInstanceUID = BASE_UID + "99"
    ds.PatientName = "Cheng^Yingping"
    ds.PatientID = "1483304"
    if nested_uid:
        inner = Dataset()
        inner.ReferencedSOPInstanceUID = nested_uid
        ds.ReferencedImageSequence = pydicom.sequence.Sequence([inner])
    ds.save_as(str(path), write_like_original=False)


def test_nested_uid_remap():
    ds = Dataset()
    ds.SOPInstanceUID = BASE_UID
    inner = Dataset()
    inner.ReferencedSOPInstanceUID = BASE_UID + "77"
    ds.ReferencedImageSequence = pydicom.sequence.Sequence([inner])
    m = UidMap()
    n = _remap_uids(ds, Policy.uid_keywords(), m)
    assert n == 2, f"嵌套序列 UID 未全部重映射: n={n}"
    new_nested = ds.ReferencedImageSequence[0].ReferencedSOPInstanceUID
    assert new_nested != BASE_UID + "77" and len(new_nested) == len(BASE_UID + "77")
    assert m.validate() is None


def test_csa_equal_length():
    uid = b"1.3.12.2.1107.5.1.4.1.2.3.20200101.111.2222.333333333"
    blob = b"HDR\x00" + uid + b"\x00TRAILER" + uid
    m = UidMap()
    out, res = process_blob(blob, m)
    assert res.length_preserved and res.replaced == 2 and len(out) == len(blob)
    assert uid not in out


def test_deid_markers_verify_and_collision():
    with tempfile.TemporaryDirectory() as td:
        src, out = Path(td) / "src", Path(td) / "out"
        src.mkdir()
        make_dcm(src / "a.dcm", BASE_UID + "01", nested_uid=BASE_UID + "02")
        make_dcm(src / "b.dcm", BASE_UID + "01")  # 同 SOPInstanceUID → 输出名冲突
        s = deid_run(src, out, Policy(Profile.Conservative), dry_run=False)
        assert s.src_files == 2 and s.out_files == 1, (s.src_files, s.out_files)
        assert any("输出名冲突" in msg for _, msg in s.errors)
        (out_files := list(out.glob("*.dcm")))
        ds = pydicom.dcmread(str(out_files[0]))
        assert ds.PatientIdentityRemoved == "YES", "脱敏标记未写入"
        assert ds.PatientName == "" and ds.PatientID == ""
        nested = ds.ReferencedImageSequence[0].ReferencedSOPInstanceUID
        assert nested != BASE_UID + "02", "嵌套 UID 仍是原值"

        # 复验：产物应通过；无 .dcm 扩展名的 DICOM 不能再"假通过"
        r = verify_run(out)
        assert r.all_passed and r.file_count == 1
        make_dcm(src / "noext", BASE_UID + "03")  # 无扩展名 DICOM
        r2 = verify_run(src, extra_needles=["Cheng"])
        assert r2.file_count >= 2 and not r2.all_passed, "复验漏检非 .dcm 文件"


def test_force_guard():
    with tempfile.TemporaryDirectory() as td:
        src, out = Path(td) / "src", Path(td) / "out"
        src.mkdir()
        make_dcm(src / "a.dcm", BASE_UID + "11")
        deid_run(src, out, Policy(Profile.Aggressive))
        try:
            deid_run(src, out, Policy(Profile.Aggressive))
        except ValueError:
            pass
        else:
            raise AssertionError("二次写入未被 force 守卫拦截")
        deid_run(src, out, Policy(Profile.Aggressive), force=True)


def test_xml_word_boundary():
    with tempfile.TemporaryDirectory() as td:
        src, out = Path(td) / "src", Path(td) / "out"
        src.mkdir()
        make_dcm(src / "a.dcm", BASE_UID + "21")
        trap = BASE_UID + "2155"  # 是 SOP UID 的"前缀扩展"，但不在映射表里
        (src / "1.xml").write_text(
            f'<root><A>{BASE_UID + "21"}</A><B>{trap}</B></root>', encoding="utf-8")
        deid_run(src, out, Policy(Profile.Aggressive))
        xml = (out / "deid_1.xml").read_text(encoding="utf-8")
        assert trap in xml, "裸替换把长 UID 截坏了"
        assert f"<A>{BASE_UID + '21'}</A>" not in xml, "XML 内 UID 未替换"
        assert f"<B>{trap}</B>" in xml


def test_recursive_collect_nested_layout():
    """真实导出布局（按检查号分子目录 + 侧车 XML）：子目录内 DICOM/XML 都要被处理；
    输出目录嵌套在源目录内时不得被当成输入。"""
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "src"
        sub = src / "1.2.276.0.7230010.3.1.2.2210554489.24416.1767225843.35809"
        sub.mkdir(parents=True)
        make_dcm(src / "top.dcm", BASE_UID + "31")
        make_dcm(sub / "a.dcm", BASE_UID + "32")
        make_dcm(sub / "b.dcm", BASE_UID + "33")
        (sub / "side.xml").write_text(
            f'<root><A>{BASE_UID + "32"}</A></root>', encoding="utf-8")
        out = src / "_out"  # 输出目录嵌套在源目录内
        s = deid_run(src, out, Policy(Profile.Conservative))
        assert s.src_files == 3, f"子目录内 DICOM 未被收集: src_files={s.src_files}"
        assert s.out_files == 3
        assert len(list(out.rglob("*.dcm"))) == 3
        assert (out / sub.name).is_dir(), "输出未镜像源目录结构"
        assert len(list((out / sub.name).glob("*.dcm"))) == 2
        xs = list(out.rglob("deid_1.xml"))
        assert xs and xs[0].parent.name == sub.name, "XML 侧车未镜像目录结构"
        xml = xs[0].read_text(encoding="utf-8")
        assert BASE_UID + "32" not in xml, "XML 内 UID 未替换"
        # 二次 force 重跑：不得把 _out 里的产物当输入
        s2 = deid_run(src, out, Policy(Profile.Conservative), force=True)
        assert s2.src_files == 3, f"输出目录被当成输入: src_files={s2.src_files}"


def test_phi_rule_shared_and_empty_value():
    """审计认定的 PHI 必须被脱敏清除（同一规则一处维护）；空值不得误报。"""
    from dicom_deid.audit import run as audit_run
    with tempfile.TemporaryDirectory() as td:
        src, out = Path(td) / "src", Path(td) / "out"
        src.mkdir()
        make_dcm(src / "a.dcm", BASE_UID + "41")
        ds = pydicom.dcmread(str(src / "a.dcm"), force=True)
        ds.ImageComments = "post-op Zhang"   # 审计判 PHI 的自由文本
        ds.PatientWeight = ""                # 空值（DS 读回为 None）
        ds.save_as(str(src / "a.dcm"), write_like_original=False)
        rep = audit_run(src)
        assert "ImageComments" in rep.phi_tags
        assert "PatientWeight" not in rep.phi_tags, "空值被误报为发现"
        deid_run(src, out, Policy(Profile.Aggressive))
        o = pydicom.dcmread(str(next(out.glob("*.dcm"))), force=True)
        assert not str(o.get("ImageComments") or "").strip(), "审计认定的 PHI 未被清空"
        assert not audit_run(out).phi_tags, "B 产物审计仍有发现"


def test_xml_nested_sq_and_profile_clear():
    """XML 嵌套 SQ 的每个子属性都要清；性别等随策略在 XML 侧车同样清空。"""
    with tempfile.TemporaryDirectory() as td:
        src, out = Path(td) / "src", Path(td) / "out"
        src.mkdir()
        make_dcm(src / "a.dcm", BASE_UID + "42")
        (src / "1.xml").write_text(
            '<r><Attribute Tag="00400275" VR="SQ">'
            '<Attribute Tag="00400009" VR="SH">LEAK1</Attribute>'
            '<Attribute Tag="00400009" VR="SH">LEAK2</Attribute></Attribute>'
            '<Attribute Tag="00100040" VR="CS">M</Attribute></r>',
            encoding="utf-8")
        deid_run(src, out, Policy(Profile.Aggressive))
        xml = (out / "deid_1.xml").read_text(encoding="utf-8")
        assert "LEAK1" not in xml and "LEAK2" not in xml, "嵌套 SQ 子属性逃过清空"
        assert ">M<" not in xml, "B 策略 XML 侧车未清性别"


def test_short_uid_no_collision():
    """短 UID 输出空间极小（长度 29 只有 10 个候选值），映射必须互不撞名。"""
    m = UidMap()
    olds = [f"1.2.826.0.1.3680043.10.99990{i}" for i in range(10)]  # 各 29 位
    news = [m.get_or_insert(o)[0] for o in olds]
    assert len(set(news)) == 10, f"短 UID 撞名: {news}"
    assert m.validate() is None


def test_dirname_uid_remapped():
    """目录名就是旧 StudyUID 的导出布局：输出目录名必须换成新 UID，否则泄露原 UID。"""
    import json
    with tempfile.TemporaryDirectory() as td:
        src, out = Path(td) / "src", Path(td) / "out"
        sub = src / (BASE_UID + "99")   # make_dcm 的 StudyInstanceUID 即此值
        sub.mkdir(parents=True)
        make_dcm(sub / "a.dcm", BASE_UID + "51")
        deid_run(src, out, Policy(Profile.Conservative))
        um = json.loads((out / "uid_map.json").read_text(encoding="utf-8"))
        new_dir = um[BASE_UID + "99"]
        assert new_dir != BASE_UID + "99" and (out / new_dir).is_dir(), "旧 UID 目录名未重映射"
        assert not (out / (BASE_UID + "99")).exists()
        assert len(list((out / new_dir).glob("*.dcm"))) == 1


def test_dirname_leaks():
    """目录名含检查号/旧 UID 必须被审计报出；复验也要查目录名。"""
    from dicom_deid.audit import run as audit_run
    from dicom_deid.verify import run as verify_run
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "src"
        sub = src / "1.2.276.0.7230010.MR22601010006"  # 旧 UID 前缀 + 检查号
        sub.mkdir(parents=True)
        make_dcm(sub / "a.dcm", BASE_UID + "61")
        ds = pydicom.dcmread(str(sub / "a.dcm"), force=True)
        ds.AccessionNumber = "MR22601010006"
        ds.save_as(str(sub / "a.dcm"), write_like_original=False)
        rep = audit_run(src)
        assert any("1.2.276.0.7230010" in n for _, n in rep.dir_leaks), "目录名旧 UID 未报出"
        assert any(n == "身份值:MR22601010006" for _, n in rep.dir_leaks), "目录名检查号未报出"
        assert not rep.filename_leaks, "文件名不该命中"
        v = verify_run(src, extra_needles=["MR22601010006"])
        assert not v.all_passed and v.filename_hits, "复验未查目录名"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok: {fn.__name__}")
    print(f"{len(fns)} tests passed")
