"""Textual TUI 交互界面"""
from __future__ import annotations
import asyncio
import os
from pathlib import Path
from threading import Thread

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Footer, Header, Label, ListItem, ListView, Static,
    Button, Input, Select, Switch, DataTable, RichLog,
)

from .policy import Policy, Profile
from .audit import AuditReport
from .deid import Summary as DeidSummary
from .verify import VerifyResult

# ── 颜色 ──────────────────────────────────────────────
ACCENT = "cyan"
DANGER = "red"
SUCCESS = "green"
MUTED = "gray50"

# ── 操作模式 ──────────────────────────────────────────
MODES = ["① 审计 (Audit)", "② 脱敏 (Deid)", "③ 复验 (Verify)"]
MODE_HELP = {
    "① 审计 (Audit)": "扫描 PHI 字段、私有块内 UID、文件名泄露",
    "② 脱敏 (Deid)": "生成脱敏副本（原目录只读）",
    "③ 复验 (Verify)": "检查脱敏产物是否残留 PHI、像素是否完整",
}


class DicomDeidApp(App):
    CSS = """
    Screen { background: $surface; }
    #sidebar { width: 28; border: solid $primary; background: $panel; }
    #main { border: solid $primary; background: $panel; }
    #title { text-align: center; color: $accent; text-style: bold; }
    .section { margin: 1 0; }
    .label { color: $text-muted; }
    Button { margin: 1 0; width: 100%; }
    Button.success { background: $success; color: white; }
    Button.danger { background: $error; color: white; }
    #log { max-height: 1fr; }
    #result_table { max-height: 1fr; }
    """

    BINDINGS = [
        Binding("1", "set_mode(0)", "审计"),
        Binding("2", "set_mode(1)", "脱敏"),
        Binding("3", "set_mode(2)", "复验"),
        Binding("a", "set_profile('a')", "A保守"),
        Binding("b", "set_profile('b')", "B激进"),
        Binding("enter", "run_action", "执行"),
        Binding("escape", "quit", "退出"),
    ]

    dir_path: reactive[str] = reactive(os.getcwd())
    mode: reactive[str] = reactive(MODES[0])
    profile: reactive[str] = reactive("a")
    running: reactive[bool] = reactive(False)
    result: reactive[dict | None] = reactive(None)

    def compose(self) -> ComposeResult:
        with Horizontal(id="sidebar"):
            with Vertical():
                yield Label("DICOM-DeID", id="title")
                yield Label("工作目录:", classes="label")
                yield Input(value=self.dir_path, id="dir_input")
                yield Label("操作模式:", classes="label")
                for idx, m in enumerate(MODES):
                    yield Button(m, id=f"mode_{idx}", classes="mode-btn")
                yield Label("脱敏策略:", classes="label")
                with Horizontal():
                    yield Button("A 保守", id="profile_a", classes="success")
                    yield Button("B 激进", id="profile_b")
                yield Label("重命名文件:", classes="label")
                yield Switch(True, id="rename_switch")
                yield Button("▶ 执行", id="run_btn", classes="success")

        with Vertical(id="main"):
            with Horizontal():
                yield Label("日志", classes="label")
                yield Label("结果", classes="label")
            yield RichLog(id="log", markup=True)
            yield DataTable(id="result_table", show_header=True)
            yield Static(MODE_HELP[self.mode], id="help_text")

        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#log").write(f"[dim]DICOM-DeID v1.0 | 目录: {self.dir_path}[/]")

    def action_set_mode(self, idx: int) -> None:
        self.mode = MODES[idx]
        self.query_one("#help_text").update(MODE_HELP.get(self.mode, ""))

    def action_set_profile(self, profile: str) -> None:
        self.profile = profile

    def on_button_pressed(self, event: Button.Pressed) -> None:
        id_ = event.button.id
        if id_.startswith("mode_"):
            idx = int(id_.split("_")[1])
            self.action_set_mode(idx)
        elif id_ == "profile_a":
            self.profile = "a"
            self.notify("策略: A 保守", severity="info")
        elif id_ == "profile_b":
            self.profile = "b"
            self.notify("策略: B 激进", severity="warning")
        elif id_ == "run_btn":
            self.run_action()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "dir_input":
            self.dir_path = event.value

    def action_run_action(self) -> None:
        if self.running:
            return

        d = Path(self.dir_path)
        if not d.exists():
            self.notify(f"目录不存在: {d}", severity="error")
            return

        self.running = True
        self.result = None
        log = self.query_one("#log")
        table = self.query_one("#result_table")
        table.clear_columns()

        def progress(msg: str):
            log.write(msg)

        def run_in_thread():
            try:
                if "审计" in self.mode:
                    from .audit import run as audit_run, collect_dicom_files
                    files = collect_dicom_files(d)
                    self.call_from_thread(lambda: log.write(
                        f"[cyan]开始审计: {len(files)} 个文件[/]"))
                    rep = audit_run(d, on_progress=lambda i, t, n:
                        self.call_from_thread(lambda: log.write(
                            f"  [{i}/{t}] {n}")))
                    self.call_from_thread(lambda: self._show_audit(rep))

                elif "脱敏" in self.mode:
                    policy = Policy(
                        profile=Profile.from_str(self.profile),
                        rename_files=self.query_one("#rename_switch").value,
                    )
                    out = d.parent / "deid_output"
                    self.call_from_thread(lambda: log.write(
                        f"[cyan]开始脱敏 → {out}[/]"))
                    from .deid import run as deid_run
                    summary = deid_run(d, out, policy,
                                       on_progress=lambda i, t, n:
                                           self.call_from_thread(lambda: log.write(
                                               f"  [{i}/{t}] {n}")))
                    self.call_from_thread(lambda: self._show_deid(summary))

                elif "复验" in self.mode:
                    from .verify import run as verify_run
                    self.call_from_thread(lambda: log.write(
                        f"[cyan]开始复验: {d}[/]"))
                    res = verify_run(d, on_progress=lambda i, t, n:
                        self.call_from_thread(lambda: log.write(
                            f"  [{i}/{t}] {n}")))
                    self.call_from_thread(lambda: self._show_verify(res))

            except Exception as e:
                self.call_from_thread(lambda: log.write(
                    f"[red]错误: {e}[/]"))
            finally:
                self.call_from_thread(lambda: setattr(self, 'running', False))

        Thread(target=run_in_thread, daemon=True).start()

    def _show_audit(self, rep: AuditReport) -> None:
        table = self.query_one("#result_table")
        table.clear_columns()
        table.add_column("项目", width=28)
        table.add_column("值", width=30)
        table.add_row("目录", rep.dir)
        table.add_row("文件数", str(rep.file_count))
        table.add_row("解析失败", str(len(rep.parse_errors)))
        table.add_row("PHI 标签数", str(len(rep.phi_tags)))
        table.add_row("人名字段", str(len(rep.person_names)))
        table.add_row("私有块 UID", str(len(rep.private_vendor_uids)))
        table.add_row("文件名泄露", str(len(rep.filename_leaks)))
        table.add_row("Study UID", str(rep.consistency.study_uids))
        table.add_row("Series UID", str(rep.consistency.series_uids))
        table.add_row("SOP UID", str(rep.consistency.sop_uids))

    def _show_deid(self, s: DeidSummary) -> None:
        table = self.query_one("#result_table")
        table.clear_columns()
        table.add_column("项目", width=28)
        table.add_column("值", width=30)
        table.add_row("源文件", str(s.src_files))
        table.add_row("输出文件", str(s.out_files))
        table.add_row("清空 PHI 标签", str(s.tags_cleared))
        table.add_row("UID 重映射", str(s.uids_remapped))
        table.add_row("CSA UID 替换", str(s.csa_uids_replaced))
        table.add_row("重命名文件", str(s.renamed_files))
        table.add_row("错误", str(len(s.errors)))

    def _show_verify(self, v: VerifyResult) -> None:
        table = self.query_one("#result_table")
        table.add_column("项目", width=28)
        table.add_column("值", width=30)
        table.add_row("文件数", str(v.file_count))
        table.add_row("最终", "✓ 全部通过" if v.all_passed else "✗ 存在问题")
        table.add_row("文件名泄露", str(len(v.filename_hits)))
        table.add_row("内容命中", str(len(v.content_hits)))
        for name, cnt in v.content_hits.items():
            table.add_row(f"  {name}", f"x{cnt}")