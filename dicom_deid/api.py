"""DICOM-DeID FastAPI 接口"""
from __future__ import annotations
import base64, tempfile
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from dicom_deid.policy import Policy, Profile
from dicom_deid.deid import run as deid_run, Summary
from dicom_deid.verify import run as verify_run, VerifyResult
from dicom_deid.audit import run as audit_run, AuditReport

app = FastAPI(
    title="DICOM-DeID API",
    description="DICOM 医学影像脱敏工具 REST 接口",
    version="1.0.2",
)


def _resolve_dir(s: str) -> Path:
    """信任边界：服务端若配置了目录白名单（--root），只接受其下路径。"""
    d = Path(s).resolve()
    roots = getattr(app.state, "allowed_roots", None)
    if roots and not any(d == r or d.is_relative_to(r) for r in roots):
        raise HTTPException(400, f"路径不在允许目录内: {s}")
    return d


# ── 请求/响应模型 ──────────────────────────────────────
class DeidRequest(BaseModel):
    src_dir: str
    out_dir: Optional[str] = None
    profile: str = "a"
    rename_files: bool = True


class AuditRequest(BaseModel):
    dir: str


class VerifyRequest(BaseModel):
    dir: str


# ── 健康检查 ──────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.2"}


# ── 审计接口 ──────────────────────────────────────────
@app.post("/audit")
async def run_audit(req: AuditRequest):
    """只读扫描 DICOM 目录，输出 PHI 审计报告"""
    d = _resolve_dir(req.dir)
    if not d.is_dir():
        raise HTTPException(400, f"目录不存在: {req.dir}")

    def progress(i, total, name):
        pass  # TODO: WebSocket 推送

    rep: AuditReport = await _run_sync(lambda: audit_run(d, on_progress=progress))

    return {
        "dir": rep.dir,
        "file_count": rep.file_count,
        "parse_errors": len(rep.parse_errors),
        "phi_tags": len(rep.phi_tags),
        "person_names": len(rep.person_names),
        "private_vendor_uids": len(rep.private_vendor_uids),
        "filename_leaks": len(rep.filename_leaks),
        "dir_leaks": len(rep.dir_leaks),
        "consistency": {
            "study_uids": rep.consistency.study_uids,
            "series_uids": rep.consistency.series_uids,
            "sop_uids": rep.consistency.sop_uids,
        },
    }


# ── 脱敏接口 ──────────────────────────────────────────
@app.post("/deid")
async def run_deid(req: DeidRequest):
    """执行脱敏操作，输出到副本目录"""
    src = _resolve_dir(req.src_dir)
    if not src.is_dir():
        raise HTTPException(400, f"源目录不存在: {req.src_dir}")

    out_dir = _resolve_dir(req.out_dir) if req.out_dir else src.parent / "deid_output"
    try:
        profile = Profile.from_str(req.profile)
    except ValueError as e:
        raise HTTPException(400, str(e))

    policy = Policy(profile=profile, rename_files=req.rename_files)

    def progress(i, total, name):
        pass

    try:
        summary: Summary = await _run_sync(
            lambda: _deid_locked(src, out_dir, policy, on_progress=progress)
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    return {
        "src_files": summary.src_files,
        "out_files": summary.out_files,
        "tags_cleared": summary.tags_cleared,
        "uids_remapped": summary.uids_remapped,
        "csa_uids_replaced": summary.csa_uids_replaced,
        "renamed_files": summary.renamed_files,
        "errors": summary.errors,
        "output_dir": str(out_dir),
    }


# ── 复验接口 ──────────────────────────────────────────
@app.post("/verify")
async def run_verify(req: VerifyRequest):
    """检查脱敏产物是否残留 PHI"""
    d = _resolve_dir(req.dir)
    if not d.is_dir():
        raise HTTPException(400, f"目录不存在: {req.dir}")

    def progress(i, total, name):
        pass

    result: VerifyResult = await _run_sync(
        lambda: verify_run(d, on_progress=progress)
    )

    return {
        "file_count": result.file_count,
        "all_passed": result.all_passed,
        "filename_hits": len(result.filename_hits),
        "content_hits": dict(result.content_hits),
    }


# ── 文件上传脱敏（新功能）─────────────────────────────
@app.post("/deid/upload")
async def deid_upload(
    files: list[UploadFile] = File(...),
    profile: str = Form("a"),
    rename_files: bool = Form(True),
):
    """上传 DICOM 文件并执行脱敏，返回脱敏文件（base64）"""
    try:
        p = Profile.from_str(profile)
    except ValueError as e:
        raise HTTPException(400, str(e))

    with tempfile.TemporaryDirectory() as tmp:
        tmp_src = Path(tmp) / "src"
        tmp_out = Path(tmp) / "out"
        tmp_src.mkdir()

        # 保存上传文件（只取文件名末段，防路径穿越）
        for i, f in enumerate(files):
            name = Path(f.filename or f"upload_{i}").name
            content = await f.read()
            (tmp_src / name).write_bytes(content)

        # 脱敏
        policy = Policy(profile=p, rename_files=rename_files)
        summary = await _run_sync(lambda: deid_run(tmp_src, tmp_out, policy))

        # 读取结果
        results = [{
            "filename": fp.name,
            "size": fp.stat().st_size,
            "data": base64.b64encode(fp.read_bytes()).decode(),
        } for fp in sorted(tmp_out.rglob("*.dcm"))]

    return {
        "files": results,
        "summary": {
            "tags_cleared": summary.tags_cleared,
            "uids_remapped": summary.uids_remapped,
            "csa_replaced": summary.csa_uids_replaced,
        },
    }


# ── 异步包装 ──────────────────────────────────────────
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

_executor = ThreadPoolExecutor(max_workers=4)
_deid_lock = threading.Lock()  # 并发写同一输出目录会新旧产物混叠，脱敏整体串行化


def _deid_locked(src, out, policy, on_progress=None):
    with _deid_lock:
        return deid_run(src, out, policy, on_progress=on_progress)


async def _run_sync(fn):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, fn)


# ── 启动入口 ──────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    # 默认仅本机：对外监听须走 dicom-deid serve --host ... --root ...（目录白名单）
    uvicorn.run(app, host="127.0.0.1", port=8080)
