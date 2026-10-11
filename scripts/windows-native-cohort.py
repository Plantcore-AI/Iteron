#!/usr/bin/env python3
"""Compile each Windows feature cohort once, then execute retained native test artifacts.

Only a selected workflow_dispatch calls this driver. A Job is process custody, not a
sandbox. The product's LPAC oracles establish their own actual execution boundary.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time

TRIPLE = "x86_64-pc-windows-msvc"
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_ARTIFACTS = 512
MAX_SOURCE_FILES = 20_000
MAX_SOURCE_BYTES = 1024 * 1024 * 1024
CLEANUP_SECONDS = 10


class GateFailure(Exception):
    pass


class BasicLimits(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                ("flags", w.DWORD), ("min_working", ctypes.c_size_t),
                ("max_working", ctypes.c_size_t), ("process_limit", w.DWORD),
                ("affinity", ctypes.c_size_t), ("priority", w.DWORD),
                ("scheduling", w.DWORD)]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
                ("memory", ctypes.c_size_t * 4)]


class Accounting(ctypes.Structure):
    _fields_ = [("time", ctypes.c_int64 * 4), ("faults", w.DWORD),
                ("total", w.DWORD), ("active", w.DWORD), ("terminated", w.DWORD)]


class ThreadEntry(ctypes.Structure):
    _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("id", w.DWORD),
                ("owner", w.DWORD), ("priority", w.LONG), ("delta", w.LONG),
                ("flags", w.DWORD)]


class Native:
    def __init__(self):
        if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise GateFailure("requires actual x64 Windows")
        if (ctypes.sizeof(ExtendedLimits), ctypes.sizeof(Accounting),
                ctypes.sizeof(ThreadEntry)) != (144, 48, 28):
            raise GateFailure("native ABI shape mismatch")
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "CreateToolhelp32Snapshot": ([w.DWORD, w.DWORD], w.HANDLE),
            "Thread32First": ([w.HANDLE, ctypes.POINTER(ThreadEntry)], w.BOOL),
            "Thread32Next": ([w.HANDLE, ctypes.POINTER(ThreadEntry)], w.BOOL),
            "OpenThread": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "GetProcessIdOfThread": ([w.HANDLE], w.DWORD),
            "GetProcessId": ([w.HANDLE], w.DWORD),
            "ResumeThread": ([w.HANDLE], w.DWORD),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result

    def job(self):
        handle = self.api.CreateJobObjectW(None, None)
        if not handle:
            raise GateFailure("private native Job unavailable")
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
        if not self.api.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.api.CloseHandle(handle)
            raise GateFailure("native Job custody unavailable")
        return handle

    def active(self, job):
        accounting = Accounting()
        if not self.api.QueryInformationJobObject(job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
            raise GateFailure("native Job membership unknown")
        return accounting.active

    def resume(self, process):
        # Popen closes CreateProcess's primary-thread handle. Retain the only actual thread of
        # this still-suspended process, then verify its owner through that handle before resume.
        process_handle = int(process._handle)
        pid = self.api.GetProcessId(process_handle)
        if pid != process.pid:
            raise GateFailure("retained process identity changed")
        snapshot = self.api.CreateToolhelp32Snapshot(4, 0)
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:
            raise GateFailure("native primary thread observation unavailable")
        matches = []
        try:
            row = ThreadEntry()
            row.size = ctypes.sizeof(row)
            found = self.api.Thread32First(snapshot, ctypes.byref(row))
            for _ in range(65_536):
                if not found:
                    if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
                        raise GateFailure("native thread census incomplete")
                    break
                if row.size < 16:
                    raise GateFailure("native thread identity incomplete")
                if row.owner == pid:
                    matches.append(row.id)
                row.size = ctypes.sizeof(row)
                found = self.api.Thread32Next(snapshot, ctypes.byref(row))
            else:
                raise GateFailure("native thread census exceeds bound")
        finally:
            self.api.CloseHandle(snapshot)
        if len(matches) != 1:
            raise GateFailure("native initial thread is not unique")
        thread = self.api.OpenThread(0x802, False, matches[0])
        if not thread:
            raise GateFailure("native initial thread unavailable")
        try:
            if self.api.GetProcessIdOfThread(thread) != pid or self.api.ResumeThread(thread) != 1:
                raise GateFailure("native initial resume receipt mismatch")
        finally:
            self.api.CloseHandle(thread)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def source_identity(root):
    result, count, size = hashlib.sha256(), 0, 0
    paths = []
    for path in root.rglob("*"):
        if len(paths) >= 2 * MAX_SOURCE_FILES:
            raise GateFailure("source namespace exceeds envelope")
        paths.append(path)
    for path in sorted(paths):
        if path.is_symlink() or path.lstat().st_file_attributes & 0x400:
            raise GateFailure("source contains a reparse object")
        if not path.is_file():
            continue
        count += 1
        size += path.stat().st_size
        if count > MAX_SOURCE_FILES or size > MAX_SOURCE_BYTES:
            raise GateFailure("source identity exceeds envelope")
        result.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        result.update(bytes.fromhex(digest(path)))
    if count == 0:
        raise GateFailure("empty source identity")
    return {"sha256": result.hexdigest(), "files": count, "bytes": size}


def child_environment():
    environment = dict(os.environ)
    for key in list(environment):
        upper = key.upper()
        if any(part in upper for part in ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "API_KEY", "AUTH")) or upper.startswith("BASH_FUNC_") or upper in ("BASH_ENV", "ENV", "BASHOPTS", "SHELLOPTS", "PROMPT_COMMAND", "LD_PRELOAD") or upper.startswith("ITERON_"):
            del environment[key]
    environment.update(RUST_TEST_THREADS="1", ITERON_TEST_TIMEOUT_SCALE="10")
    return environment


class Runner:
    def __init__(self, root, output, source_sha):
        self.root, self.output, self.source_sha = root, output, source_sha
        self.native, self.rows = Native(), []
        self.source = source_identity(root)
        self.environment = child_environment()
        self.environment["ITERON_BUILD_COMMIT"] = source_sha

    def persist(self):
        value = {"source_commit": self.source_sha, "source_identity": self.source,
                 "scope": "selected native Windows cases, not full product acceptance",
                 "runs": self.rows}
        (self.output / "receipt.json").write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def run(self, name, arguments, seconds, log_limit=MAX_LOG_BYTES):
        if source_identity(self.root) != self.source:
            raise GateFailure("source changed before native command")
        if not Path(arguments[0]).is_absolute():
            raise GateFailure("native command requires an explicit executable")
        row = {"name": name, "command": list(map(str, arguments)), "state": "running",
               "stdout": str(self.output / f"{name}.stdout"),
               "stderr": str(self.output / f"{name}.stderr"), "cleanup_known": False}
        self.rows.append(row)
        self.persist()
        print(f"{name}: started source={self.source_sha}", flush=True)
        job, process, threads = self.native.job(), None, []
        rejected = threading.Event()
        errors = []

        def drain(pipe, destination):
            try:
                retained = 0
                with destination.open("xb") as log:
                    while chunk := pipe.read(16 * 1024):
                        retained += len(chunk)
                        if retained > log_limit:
                            rejected.set()
                            break
                        log.write(chunk)
            except Exception:
                errors.append("native output unavailable")
                rejected.set()

        try:
            process = subprocess.Popen(list(map(str, arguments)), cwd=self.root,
                env=self.environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, creationflags=subprocess.CREATE_SUSPENDED)
            if not self.native.api.AssignProcessToJobObject(job, int(process._handle)):
                raise GateFailure("suspended process Job assignment refused")
            if self.native.active(job) != 1:
                raise GateFailure("suspended native Job membership mismatch")
            self.native.resume(process)
            for pipe, path in [(process.stdout, Path(row["stdout"])), (process.stderr, Path(row["stderr"]))]:
                thread = threading.Thread(target=drain, args=(pipe, path), daemon=True)
                threads.append(thread)
                thread.start()
            deadline = time.monotonic() + seconds
            while process.poll() is None:
                if rejected.is_set() or time.monotonic() >= deadline:
                    raise GateFailure("native command output or deadline exceeded")
                time.sleep(0.05)
            row["exit_code"] = process.returncode
            row["state"] = "completed" if process.returncode == 0 else "failed"
        except Exception as error:
            row["state"] = "rejected"
            row["error_class"] = type(error).__name__
            if isinstance(error, GateFailure):
                row["reason"] = str(error)  # Every GateFailure message is a closed driver literal.
        finally:
            self.native.api.TerminateJobObject(job, 197)
            if process is not None:
                try:
                    process.kill()  # Exact retained leader even if Job assignment failed.
                except OSError:
                    pass
                try:
                    process.wait(timeout=CLEANUP_SECONDS)
                    waited = True
                except subprocess.TimeoutExpired:
                    waited = False
                deadline = time.monotonic() + CLEANUP_SECONDS
                empty = False
                while time.monotonic() < deadline:
                    try:
                        empty = self.native.active(job) == 0
                    except GateFailure:
                        break
                    if empty:
                        break
                    time.sleep(0.05)
                for thread in threads:
                    thread.join(timeout=2)
                streams_closed = not any(thread.is_alive() for thread in threads)
                row["cleanup_known"] = waited and empty and streams_closed
                if streams_closed:
                    process.stdout.close()
                    process.stderr.close()
            else:
                row["cleanup_known"] = True  # No process was created.
            row["job_handle_closed"] = bool(self.native.api.CloseHandle(job))
            row["source_identity_verified"] = source_identity(self.root) == self.source
            if not row["cleanup_known"] or not row["job_handle_closed"] or not row["source_identity_verified"] or rejected.is_set() or errors:
                row["state"] = "rejected"
            self.persist()
        print(f"{name}: {row['state']} cleanup_known={row['cleanup_known']}", flush=True)
        if row["state"] != "completed":
            raise GateFailure("native command did not complete with known custody")
        return Path(row["stdout"])


# Literal exact substantive sets prevent cfg-empty, helper-only and renamed-filter green results.
SUITES = []
TARGET_PACKAGES = {"iteron_support": "iteron-support", "iteron_sandbox": "iteron-sandbox",
                   "iteron_tools": "iteron-tools", "iteron": "iteron-cli",
                   "windows_state": "iteron-support", "live_scheduler_file": "iteron-workflow",
                   "windows_conpty": "iteron-cli"}

def suite(target, kind, prefix, names, helper="", seconds=600):
    SUITES.append((target, kind, prefix, tuple(prefix + name for name in names),
                   prefix + helper if helper else "", seconds))

suite("iteron_support", "lib", "owned_windows_job::tests::", [
    "owned_windows_job_assigns_before_exact_primary_resume_and_observes_actual_exit",
    "owned_windows_job_pre_resume_refusal_reaps_without_running_user_code",
    "owned_windows_job_stdio_refusal_preserves_suspended_custody_until_real_reap",
    "owned_windows_job_noninitial_resume_count_refuses_and_cleans_the_exact_tree",
    "owned_windows_job_redirected_descendant_requires_actual_job_zero_after_leader_exit",
    "owned_windows_job_future_drop_terminates_retained_members_with_real_job_observation",
    "owned_windows_job_native_host_exit_uses_kill_on_close_without_rust_destructors",
    "owned_windows_job_string_projection_retains_actual_unassigned_suspended_process_cleanup",
    "owned_windows_job_string_projection_closes_actual_assigned_tree_after_error_drop",
    "owned_windows_job_child_fixture"], "owned_windows_job_child_fixture")
suite("iteron_support", "lib", "owned_windows_job::conpty::tests::", [
    "native_conpty_real_stdin_resize_cwd_environment_wait_and_eof",
    "native_conpty_leader_exit_retires_actual_redirected_descendant_job",
    "native_conpty_drop_retains_actual_handle_custody_until_job_zero",
    "native_conpty_refused_before_resume_has_no_execution_and_known_physical_cleanup",
    "native_conpty_invalid_abi_refuses_before_any_process_or_console",
    "native_conpty_child_fixture"], "native_conpty_child_fixture")
suite("iteron_support", "lib", "owned_windows_job::piped::tests::", [
    "native_piped_stdio_is_distinct_with_real_eof_wait_and_job_zero",
    "native_piped_drop_keeps_physical_custody_until_real_job_zero",
    "native_piped_pre_resume_refusal_is_reaped_without_executing_app_code",
    "native_missing_executable_retains_unknown_origin_after_real_empty_job_cleanup",
    "native_piped_child_fixture"], "native_piped_child_fixture")
suite("iteron_support", "lib", "owned_windows_job::native_setup::tests::", [
    "native_setup_binding_refusal_retires_its_reserved_lease_without_creation",
    "native_setup_drop_keeps_installed_reservation_until_physical_cleanup",
    "native_sandbox_scratch_is_create_only_and_never_deletes_an_existing_directory",
    "native_sandbox_drop_retires_the_same_created_scratch_and_cannot_steal_a_live_owner",
    "native_sandbox_workspace_capability_mismatch_retires_only_its_created_scratch",
    "native_sandbox_scratch_retirement_unlinks_reparse_objects_without_touching_targets"])
suite("iteron_support", "lib", "windows_process_isolation::tests::", [
    "native_isolation_writes_only_admitted_workspace_and_scratch",
    "native_isolation_read_only_workspace_retains_private_scratch_write",
    "native_isolation_denies_external_network_with_actual_access_error",
    "native_second_arc_launch_cannot_retire_first_live_grants",
    "native_workspace_capability_never_substitutes_another_directory",
    "native_verbatim_system_image_uses_existing_protected_permissions",
    "native_preexisting_outside_hardlink_refuses_before_any_grant_or_child_code",
    "native_isolated_child_fixture"], "native_isolated_child_fixture")
suite("iteron_sandbox", "lib", "windows_job_tests::", [
    "owned_windows_job_collector_preserves_failed_status_with_known_real_tree_cleanup",
    "owned_windows_job_collector_ordinary_observer_does_not_fabricate_cleanup_proof",
    "owned_windows_job_collector_actual_configured_shell_releases_known_writer_cleanup"])
suite("iteron_sandbox", "lib", "windows_sandbox::tests::", [
    "required_windows_pipe_factory_preserves_streams_eof_and_real_terminal_retirement",
    "required_windows_one_shot_uses_the_same_owned_scope_and_filtered_frozen_environment",
    "required_windows_one_shot_timeout_retains_exact_job_and_bounded_pipe_cleanup"])
suite("iteron_tools", "lib", "process::windows_tests::", [
    "native_windows_registry_terminal_stdin_eof_and_cursors",
    "native_windows_registry_required_confinement_uses_lpac_on_the_actual_terminal",
    "native_windows_registry_resize_and_authoritative_stop",
    "native_windows_exec_yield_and_future_drop_retire_the_actual_job",
    "native_windows_stop_write_race_retains_every_accepted_reply"])
suite("iteron_tools", "lib", "lsp::windows_tests::", [
    "native_windows_lsp_source_retains_bytes_identity_and_utf16_positions",
    "native_windows_lsp_source_refuses_escape_stream_and_oversize",
    "native_windows_lsp_source_never_follows_a_reparse_leaf_or_root",
    "native_windows_registered_lsp_uses_real_confined_pipes_reuse_and_cleanup"])
suite("iteron", "bin", "client_effects::shell::windows_tests::", [
    "owned_windows_job_operator_shell_actual_failed_command_is_completed_and_cleanup_known",
    "owned_windows_job_operator_shell_redirected_background_is_stopped_before_lease_release",
    "owned_windows_job_operator_shell_cancel_retains_unknown_effects_after_actual_tree_reap"])
suite("windows_state", "test", "", [
    "exclusive_writer_replacement_and_reopen", "rename_failure_poison_and_restart_preserves_previous",
    "lost_snapshot_and_hardlink_are_refused", "inherited_public_directory_and_path_components_are_refused",
    "directory_junction_does_not_gain_storage_authority", "process_crash_releases_lease_and_preserves_publication",
    "windows_state_process_child"], "windows_state_process_child")
suite("live_scheduler_file", "test", "", [
    "durable_plan_reopen_preserves_cas_receipt_and_single_writer_lease",
    "lost_durable_snapshot_and_corrupt_payload_are_never_fresh_workflows",
    "untrusted_directory_symlink_and_hardlink_do_not_gain_storage_authority",
    "stored_config_migration_requires_explicit_matching_immutable_contract"])
suite("windows_conpty", "test", "", [
    "native_console_mode_wrapper_process", "console_mode_marker_ignores_adjacent_hexadecimal_terminal_data",
    "completion_wait_accepts_a_notification_delivered_after_the_ready_frame",
    "native_conpty_projects_link_and_exactly_one_capability_selected_notification",
    "native_conpty_conhost_signal_degrades_links_notifications_and_keyboard",
    "native_conpty_rejects_version_skew_before_terminal_takeover",
    "native_conpty_handshake_unicode_resize_and_keyboard_disabled"], "native_console_mode_wrapper_process", 900)


def artifacts(log, target_root, destination):
    records = []
    seen = set()
    copied_bytes = 0
    selected = {(row[0], row[1]) for row in SUITES}
    for line in log.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if value.get("reason") != "compiler-artifact" or not value.get("executable"):
            continue
        path = Path(value["executable"])
        if not path.is_absolute() or not path.resolve().is_relative_to(target_root.resolve()) or not path.is_file() or path.lstat().st_file_attributes & 0x400:
            raise GateFailure("compiler executable outside retained target")
        package_id = value["package_id"]
        package = package_id.rsplit("#", 1)[-1].split("@", 1)[0]
        identity = (value["target"]["name"], tuple(value["target"]["kind"]), value["profile"]["test"], package_id)
        if identity in seen or len(records) >= MAX_ARTIFACTS:
            raise GateFailure("compiler artifact set ambiguous or oversized")
        seen.add(identity)
        expected = digest(path)
        copy = None
        if any((identity[0], kind) in selected for kind in identity[1]) or identity[1] == ("bin",):
            copied_bytes += path.stat().st_size
            if copied_bytes > 2 * 1024 * 1024 * 1024:
                raise GateFailure("frozen native artifact bytes exceed envelope")
            copy = destination / f"{len(records):03d}-{path.name}"
            shutil.copy2(path, copy)
            if digest(copy) != expected:
                raise GateFailure("frozen artifact copy mismatch")
            copy.chmod(0o444)
        records.append({"target": identity[0], "kind": identity[1], "test": identity[2],
                        "package_id": package_id, "package_name": package,
                        "original": str(path), "copy": str(copy) if copy else None, "sha256": expected})
    if not records:
        raise GateFailure("no native compiler artifacts")
    return records


def verify_artifacts(records):
    for record in records:
        if digest(Path(record["original"])) != record["sha256"] or (record["copy"] is not None and digest(Path(record["copy"])) != record["sha256"]):
            raise GateFailure("compiled cohort bytes changed")


def main():
    sha = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch("[0-9a-f]{40}", sha) or os.environ.get("RUNNER_OS") != "Windows":
        raise GateFailure("requires one selected Windows source commit")
    root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    target_root = Path(os.environ["CARGO_TARGET_DIR"]).resolve()
    if target_root.is_relative_to(root):
        raise GateFailure("compiler output must be outside frozen source")
    run = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch("[0-9]{1,24}", run) or not re.fullmatch("[0-9]{1,8}", attempt):
        raise GateFailure("native receipt run identity unavailable")
    output = Path(os.environ["RUNNER_TEMP"]) / f"iteron-native-{sha}-{run}-{attempt}"
    output.mkdir(exist_ok=False)
    runner = Runner(root, output, sha)
    cargo = shutil.which("cargo.exe")
    if not cargo:
        raise GateFailure("pinned Cargo executable unavailable")
    failures = []
    for cohort, features in [("default", []), ("script", ["--features", "iteron-cli/script-workflows"])]:
        folder = output / cohort
        folder.mkdir()
        compile_log = runner.run(f"{cohort}-compile", [cargo, "test", "--workspace", "--all-targets", "--locked", "--target", TRIPLE, "--no-run", "--message-format=json"] + features, 2700)
        records = artifacts(compile_log, target_root, folder)
        (folder / "artifacts.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        for index, (target, kind, prefix, expected, helper, seconds) in enumerate(SUITES):
            name = f"{cohort}-{index:02d}-{target}"
            try:
                verify_artifacts(records)
                matches = [record for record in records if record["package_name"] == TARGET_PACKAGES[target] and record["target"] == target and record["kind"] == (kind,) and record["test"] is True]
                if len(matches) != 1 or len(expected) <= bool(helper):
                    raise GateFailure("required native target absent or ambiguous")
                executable = matches[0]["original"]
                listing = runner.run(name + "-list", [executable, prefix, "--list", "--color", "never"], 60, 1024 * 1024)
                actual = re.findall(r"^(\S+): test$", listing.read_text(encoding="utf-8"), re.M)
                if sorted(actual) != sorted(expected):
                    raise GateFailure("native case set missing, renamed or cfg-empty")
                arguments = [executable, prefix, "--test-threads=1", "--include-ignored", "--color", "never"]
                if helper:
                    arguments += ["--skip", helper]
                result = runner.run(name + "-execute", arguments, seconds, 8 * 1024 * 1024)
                count = len(expected) - bool(helper)
                summaries = re.findall(r"^test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured;", result.read_text(encoding="utf-8"), re.M)
                if summaries != [str(count)]:
                    raise GateFailure("native substantive execution count mismatch")
                verify_artifacts(records)
                runner.rows[-1]["exact_substantive_cases"] = count
                runner.rows[-1]["case_set"] = expected
                runner.persist()
            except GateFailure as error:
                failures.append({"cohort": cohort, "suite": name, "reason": str(error)})
        verify_artifacts(records)
    if source_identity(root) != runner.source:
        raise GateFailure("source changed after native cohorts")
    (output / "summary.json").write_text(json.dumps({"source_commit": sha, "source_identity": runner.source,
        "state": "failed" if failures else "passed", "failures": failures,
        "scope": "exact listed native Windows suites in default/script cohorts; full product acceptance separate"}, indent=2) + "\n", encoding="utf-8")
    print(f"Windows native receipts: {output}; failed suites: {len(failures)}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateFailure as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
