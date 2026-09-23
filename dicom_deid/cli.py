"""DICOM 脱敏工具 —— 命令行入口

用法概览：
    dicom-deid audit  <DICOM目录>                  只读 PHI 审计
    dicom-deid deid   <源目录> <输出目录> -p a|b    脱敏（策略必选：a 保守 / b 激进）
    dicom-deid tui                                 交互式 TUI
    dicom-deid serve [--port N]                    REST API 服务
    dicom-deid                                     无参数 = 交互向导（选功能 → 选策略）

退出码：0 = 成功/洁净；1 = 完成但有发现（审计查到 PHI、存在未检查的非 DICOM 文件、脱敏有错误）；2 = 出错或中止
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from .policy import Policy, Profile

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _progress(quiet: bool):
    if quiet:
        return None

    def cb(i: int, total: int, name: str):
        print(f"\r  [{i}/{total}] {name[:60]:<60}", end="", flush=True)
        if i >= total:
            print()
    return cb


# ---------------------------------------------------------------- audit

def _audit_dict(rep) -> dict:
    return {
        "dir": rep.dir,
        "file_count": rep.file_count,
        "parse_errors": [{"file": f, "error": e} for f, e in rep.parse_errors],
        "phi_tags": {k: dataclasses.asdict(v) for k, v in rep.phi_tags.items()},
        "person_names": {k: dataclasses.asdict(v) for k, v in rep.person_names.items()},
        "private_tags": sorted(rep.private_tags),
        "private_vendor_uids": rep.private_vendor_uids,
        "filename_leaks": [{"file": f, "needle": n} for f, n in rep.filename_leaks],
        "consistency": dataclasses.asdict(rep.consistency),
    }


def _warn_skipped(src: Path, collected) -> None:
    """目录里有非 DICOM 文件被跳过时明确警告（如裸 .jp2 图像）——
    静默跳过会让用户以为'无法识别/没处理'，而这些文件的文件名可能就是泄露。"""
    from .audit import SIDECAR_EXTS
    got = {p.name for p in collected}
    skipped = [p.name for p in sorted(Path(src).iterdir())
               if p.is_file() and p.name not in got
               and p.suffix.lower() not in SIDECAR_EXTS]
    if skipped:
        print(f"⚠ 跳过 {len(skipped)} 个非 DICOM 文件 —— 本工具仅支持 DICOM 原图；"
              f"裸图像（.jp2/.png 等）无元数据可脱敏，本工具不改动它们。"
              f"文件名或像素内若含患者信息（如烧录文字的报告单），"
              f"需另行做文件名改名/像素级遮盖后再外发:")
        for n in skipped[:10]:
            print(f"      {n}")
        if len(skipped) > 10:
            print(f"      ... 共 {len(skipped)} 个")
    return skipped


def cmd_audit(args) -> int:
    from . import audit
    src = Path(args.directory)
    if not src.is_dir():
        print(f"错误：目录不存在 {src}", file=sys.stderr)
        return EXIT_ERROR

    print(f"[审计] 只读扫描 {src}")
    skipped = _warn_skipped(src, audit.collect_dicom_files(src))
    rep = audit.run(src, on_progress=_progress(args.quiet),
                    extra_needles=tuple(args.needle or ()))
    print(f"  文件数           : {rep.file_count}")
    print(f"  解析失败         : {len(rep.parse_errors)}")
    print(f"  PHI 标签种类     : {len(rep.phi_tags)}")
    for kw, info in sorted(rep.phi_tags.items()):
        print(f"      {info.tag} {info.vr:<3} {kw:<40} x{info.count}  样例: {info.samples[0] if info.samples else ''}")
    print(f"  PN 姓名字段      : {len(rep.person_names)}")
    for kw, info in sorted(rep.person_names.items()):
        print(f"      {info.tag} {info.vr:<3} {kw:<40} x{info.count}  样例: {info.samples[0] if info.samples else ''}")
    print(f"  私有标签         : {len(rep.private_tags)}  {' '.join(sorted(rep.private_tags)[:8])}{' ...' if len(rep.private_tags) > 8 else ''}")
    print(f"  私有块内厂商 UID : {len(rep.private_vendor_uids)} 个（共 {sum(rep.private_vendor_uids.values())} 处）")
    for uid, cnt in sorted(rep.private_vendor_uids.items())[:5]:
        print(f"      {uid}  x{cnt}")
    print(f"  文件名泄露       : {len(rep.filename_leaks)}")
    for f, n in rep.filename_leaks[:5]:
        print(f"      {f}  命中 '{n}'")
    c = rep.consistency
    print(f"  一致性           : PatientID={c.patient_ids} PatientName={c.patient_names}")
    print(f"                     Accession={c.accession_numbers} Study={c.study_uids} Series={c.series_uids} SOP={c.sop_uids}")

    if args.json:
        Path(args.json).write_text(
            json.dumps(_audit_dict(rep), ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"  报告已写入       : {args.json}")

    findings = bool(rep.phi_tags or rep.person_names or rep.filename_leaks
                    or rep.private_vendor_uids or rep.parse_errors)
    if findings:
        print("结论：发现 PHI/泄露风险，脱敏前请先确认策略。")
        return EXIT_FINDINGS
    if skipped:
        print(f"结论：已扫描的 DICOM 文件内未发现 PHI；"
              f"{len(skipped)} 个非 DICOM 文件不在检查范围"
              f"（仅支持 DICOM 原图，其文件名/像素可能仍含患者信息，见上方警告）。")
        return EXIT_FINDINGS
    print("结论：未发现 PHI。")
    return EXIT_OK


# ---------------------------------------------------------------- deid

def _print_plan(src: Path, out: Path, profile: Profile, rename: bool, dry_run: bool) -> None:
    kept = Policy.kept_clinical(profile)
    print(f"[脱敏] {'试运行(dry-run，不写文件)' if dry_run else '执行'}")
    print(f"  源目录   : {src}")
    print(f"  输出目录 : {out}")
    print(f"  策略     : {profile.label}  ({profile.method_text})")
    print(f"  清空     : 姓名/ID/生日/检查号/机构/设备序列号/人员姓名/流程标识"
          + ("" if profile == Profile.Conservative else "，以及 性别/年龄/身高体重/全部日期时间"))
    print(f"  保留     : {'、'.join(kept)}")
    print("  UID      : 长度保持重映射（含嵌套 SQ、CSA 私有块等长替换）")
    print(f"  文件名   : {'按新 SOPInstanceUID 重命名' if rename else '保持原名（⚠ 仍可能泄露设备序列号）'}")
    print("  标记     : PatientIdentityRemoved=YES + DeidentificationMethod")


def cmd_deid(args) -> int:
    from . import deid
    src, out = Path(args.src), Path(args.out)
    if not src.is_dir():
        print(f"错误：源目录不存在 {src}", file=sys.stderr)
        return EXIT_ERROR
    if src.resolve() == out.resolve():
        print("错误：输出目录不能与源目录相同（覆盖原数据是独立的高危流程，不在此命令内做）。",
              file=sys.stderr)
        return EXIT_ERROR
    try:
        profile = Profile.from_str(args.profile)
    except ValueError as e:
        print(f"错误：{e}", file=sys.stderr)
        return EXIT_ERROR

    existing = list(out.glob("*.dcm")) if out.is_dir() else []
    if existing and not args.force:
        print(f"错误：输出目录已含 {len(existing)} 个 .dcm，可能与新产物混叠。"
              f"请换空目录或加 --force。", file=sys.stderr)
        return EXIT_ERROR

    rename = not args.keep_filename
    _print_plan(src, out, profile, rename, args.dry_run)
    from .audit import collect_dicom_files
    _warn_skipped(src, collect_dicom_files(src))

    if not args.dry_run and not args.yes:
        if not sys.stdin.isatty():
            print("错误：非交互环境请显式加 --yes 确认（脱敏写出文件不可逆）。", file=sys.stderr)
            return EXIT_ERROR
        try:
            ans = input("确认执行？[y/N] ").strip().lower()
        except EOFError:
            print("错误：输入流已关闭，无法确认。请加 --yes。", file=sys.stderr)
            return EXIT_ERROR
        if ans not in ("y", "yes"):
            print("已中止，未写任何文件。")
            return EXIT_ERROR

    policy = Policy(profile=profile, rename_files=rename)
    s = deid.run(src, out, policy, on_progress=_progress(args.quiet),
                 dry_run=args.dry_run)
    print(f"  源文件/出文件    : {s.src_files} / {s.out_files}")
    print(f"  清空标签         : {s.tags_cleared}")
    print(f"  UID 重映射       : {s.uids_remapped}（映射表 {s.uid_map_size} 条）")
    print(f"  CSA 内替换       : {s.csa_uids_replaced}")
    print(f"  重命名文件       : {s.renamed_files}")
    print(f"  错误             : {len(s.errors)}")
    for f, e in s.errors[:10]:
        print(f"      {f}: {e}")
    if not args.dry_run:
        print(f"  产物目录         : {out}（含 uid_map.json）")

    if args.json:
        Path(args.json).write_text(
            json.dumps(dataclasses.asdict(s), ensure_ascii=False, indent=2),
            encoding="utf-8")

    if profile == Profile.Conservative:
        print("⚠ 合规提示：A 保守策略保留了 性别+年龄+检查日期，小范围内仍可能被反推身份；"
              "公开发布数据集请改用 B 激进策略。脱敏 ≠ 可随意外发。")
    if s.errors:
        return EXIT_FINDINGS
    return EXIT_OK


# ---------------------------------------------------------------- tui / serve

def cmd_tui(_args) -> int:
    from .tui import DicomDeidApp
    DicomDeidApp().run()
    return EXIT_OK


def cmd_serve(args) -> int:
    try:
        import uvicorn
        from .api import app
    except ImportError as e:
        print(f"❌ serve 缺少 API 依赖（{e}）。安装可选组后重试：",
              file=sys.stderr)
        print("   pip install \"dicom-deid[api]\"   # 即 fastapi/uvicorn/python-multipart",
              file=sys.stderr)
        return EXIT_ERROR
    print(f"DICOM-DeID API: http://0.0.0.0:{args.port}")
    uvicorn.run(app, host="0.0.0.0", port=args.port)
    return EXIT_OK


# ---------------------------------------------------------------- 向导

def _ask(prompt: str, valid: dict[str, str] | None = None, hint: str | None = None) -> str:
    """交互询问；valid = 输入值 -> 归一值；hint = 方括号内显示文案"""
    if valid:
        hint = hint or " / ".join(valid.keys())
        while True:
            ans = input(f"{prompt} [{hint}]: ").strip()
            for k, v in valid.items():
                if ans.lower() in (k.lower(), v.lower()):
                    return v
            print(f"  请输入: {hint}")
    return input(f"{prompt}: ").strip()


def wizard() -> int:
    print("=" * 60)
    print("  DICOM 脱敏工具 —— 交互向导")
    print("=" * 60)
    func = _ask("① 选择功能",
                {"1": "audit", "审计": "audit", "2": "deid", "脱敏": "deid"},
                hint="1 审计/ 2 脱敏")
    if func == "audit":
        d = _ask("② DICOM 目录")
        return cmd_audit(argparse.Namespace(directory=d, json=None, needle=None, quiet=False))
    prof = _ask("② 选择策略（A 保守=保留性别/年龄/日期，B 激进=全部清除）",
                {"A": "a", "B": "b"})
    src = _ask("③ 源目录")
    out = _ask("④ 输出目录")
    return cmd_deid(argparse.Namespace(
        src=src, out=out, profile=prof, keep_filename=False,
        dry_run=False, yes=False, force=False, quiet=False, json=None))


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dicom-deid",
        description="DICOM 医学影像脱敏工具（功能 = 子命令，策略 = -p a/b）。"
                    "⚠ 仅支持 DICOM 原图（.dcm 及各种扩展名/无前导均可），"
                    "不支持裸图像格式（.jp2/.png/.jpg 等）——此类文件无元数据可脱敏，"
                    "像素内烧录的信息无法处理。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  dicom-deid audit D:\\data\\study1\n"
               "  dicom-deid deid  D:\\data\\study1 D:\\data\\study1_deid -p a --dry-run\n"
               "  dicom-deid deid  D:\\data\\study1 D:\\data\\study1_deid -p b --yes\n",
    )
    sub = p.add_subparsers(dest="command")

    pa = sub.add_parser("audit", help="只读 PHI 审计（策略无关）")
    pa.add_argument("directory", help="DICOM 目录")
    pa.add_argument("--json", metavar="FILE", help="报告另存为 JSON")
    pa.add_argument("--needle", action="append", metavar="STR",
                    help="追加文件名泄露特征串（可多次）")
    pa.add_argument("-q", "--quiet", action="store_true", help="不显示逐文件进度")
    pa.set_defaults(func=cmd_audit)

    pd = sub.add_parser("deid", help="脱敏（必须显式指定策略）")
    pd.add_argument("src", help="源目录（只读，不会被修改）")
    pd.add_argument("out", help="输出目录（建议为空目录）")
    pd.add_argument("-p", "--profile", required=True, metavar="P",
                    help="脱敏策略：a/conservative/保守 或 b/aggressive/激进")
    pd.add_argument("--keep-filename", action="store_true",
                    help="不按新 SOPInstanceUID 重命名（⚠ 原文件名可能泄露）")
    pd.add_argument("--dry-run", action="store_true",
                    help="试运行：走完全部流程但不写任何文件")
    pd.add_argument("-y", "--yes", action="store_true", help="跳过确认（脚本化调用）")
    pd.add_argument("--force", action="store_true",
                    help="允许写入已含 .dcm 的输出目录")
    pd.add_argument("--json", metavar="FILE", help="摘要另存为 JSON")
    pd.add_argument("-q", "--quiet", action="store_true", help="不显示逐文件进度")
    pd.set_defaults(func=cmd_deid)

    pt = sub.add_parser("tui", help="交互式 TUI")
    pt.set_defaults(func=cmd_tui)

    ps = sub.add_parser("serve", help="启动 REST API 服务")
    ps.add_argument("--port", type=int, default=8080)
    ps.set_defaults(func=cmd_serve)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        # 无参数 = 交互向导（选功能 → 选策略）
        try:
            return wizard()
        except (KeyboardInterrupt, EOFError):
            print("\n已中止。")
            return EXIT_ERROR
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已中止。", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
