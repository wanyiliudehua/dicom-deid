"""同步内网安装包源码并重算校验清单。

kit 内的 src/ 是主树副本，只允许经此脚本更新（禁止手工改包内源码，改了必漂移）。
用法：python sync_kits.py   —— 更新两个 kit 的 src/ + SHA256SUMS.txt；zip 需另行重打。
"""
import hashlib
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# kit/src 内容 = 主树这些文件（dicom_deid 目录 + 单文件）
SRC_FILES = ["run_tui.py", "pyproject.toml", "LICENSE"]
KITS = {
    ROOT / "内网安装包": ["使用说明书.md"],
    ROOT / "intranet-kit-en": ["README.md"],
}


def sync(kit: Path, src_docs: list[str]) -> None:
    src_dir = kit / "src"
    dst = src_dir / "dicom_deid"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(ROOT / "dicom_deid", dst,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in SRC_FILES + src_docs:
        shutil.copy2(ROOT / name, src_dir / name)

    lines = []
    for p in sorted(kit.rglob("*")):
        rel = p.relative_to(kit)
        if (not p.is_file() or p.name == "SHA256SUMS.txt"
                or any(part.startswith(".") or part == "__pycache__" for part in rel.parts)
                or p.suffix == ".pyc"):
            continue
        lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel.as_posix()}")
    # 强制 LF：CRLF 会让 sha256sum -c 把 \r 拼进文件名而全盘 FAILED
    (kit / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"[sync] {kit.name}: src 更新 + SHA256SUMS {len(lines)} 条")


for kit, docs in KITS.items():
    sync(kit, docs)
print("done —— zip 尚未重打（覆盖前先确认备份齐），需要时再打包")
