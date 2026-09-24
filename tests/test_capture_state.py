"""The capture state machine (§51).

PT-03: the console reported CAPTURING for a filter TShark had rejected. The
state was inferred from whether the reader *thread* was alive, which is a
different question from whether anything is being captured: dumpcap exits on a
bad filter within a second, and the thread waits for packets forever.

What is pinned here is that CAPTURING has to be earned - a real process, seen
running - and that a rejected filter is reported to the operator in words they
can act on, with nothing internal in them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from aethra_sec.integrations.pyshark_capture.filters import _readable_reason
from aethra_sec.models.traffic import CaptureState, CaptureStatistics

SERVICE = Path(__file__).resolve().parent.parent / "aethra_sec" / "services" / "packet_capture.py"
SCREEN = Path(__file__).resolve().parent.parent / "aethra_sec" / "ui" / "screens" / "traffic.py"


def _code_only(path: Path) -> str:
    """Source with docstrings removed.

    The modules explain the bug they fix, so a naive search finds the prose
    describing the mistake rather than the mistake.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                if isinstance(body[0].value.value, str):
                    node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


class TestTheStates:
    """The vocabulary itself."""

    def test_every_state_the_pipeline_can_be_in_exists(self) -> None:
        for name in ("IDLE", "STARTING", "CAPTURING", "STOPPING", "STOPPED", "FAILED"):
            assert hasattr(CaptureState, name), f"{name} missing"

    def test_only_starting_and_capturing_count_as_active(self) -> None:
        active = {s for s in CaptureState if s.is_active}
        assert active == {CaptureState.STARTING, CaptureState.CAPTURING}

    def test_a_state_renders_as_its_own_name(self) -> None:
        """The chip shows this text, so it must not read CaptureState.IDLE."""
        assert str(CaptureState.FAILED) == "FAILED"


class TestStatisticsNeverOverclaim:
    """What the screens read."""

    def test_statistics_without_a_state_never_say_capturing(self) -> None:
        """The fallback path must not invent a live capture.

        Claiming a capture is running is the one answer that has to be earned;
        a statistics object built without a state has not earned it.
        """
        assert CaptureStatistics().status_text == "IDLE"

    def test_statistics_report_the_state_they_are_given(self) -> None:
        stats = CaptureStatistics(state="FAILED", is_running=False)
        assert stats.status_text == "FAILED"

    def test_an_error_without_a_state_reads_as_failed(self) -> None:
        assert CaptureStatistics(last_error="rejected").status_text == "FAILED"


class TestRunningMeansAProcess:
    """The fix itself, read out of the source."""

    def test_is_running_checks_the_process_not_only_the_thread(self) -> None:
        """A live thread over a dead process is precisely the PT-03 state."""
        code = _code_only(SERVICE)
        assert "capture_process_alive" in code, (
            "is_running no longer consults the capture process"
        )

    def test_the_filter_is_validated_before_the_capture_starts(self) -> None:
        code = _code_only(SERVICE)
        assert "validate_capture_filter" in code
        start = code.index("def start")
        # The reader is now chosen between two decode paths, so the class is
        # named by a variable. What must hold is unchanged: the filter is
        # compiled before any reader is constructed.
        first_reader = min(
            code.index(name, start)
            for name in ("FieldCaptureReader(", "LiveCaptureReader(")
        )
        assert code.index("validate_capture_filter", start) < first_reader, (
            "the filter is checked after the reader is built"
        )

    def test_a_rejected_filter_leaves_the_pipeline_failed(self) -> None:
        code = _code_only(SERVICE)
        assert "CaptureState.FAILED" in code

    def test_the_screen_reads_the_service_state_rather_than_guessing(self) -> None:
        code = _code_only(SCREEN)
        # ast.unparse normalises quoting, so match on the call shape.
        assert "getattr(statistics, 'state'" in code, (
            "the screen derives its own state again"
        )


class TestTheReasonIsSafeToShow:
    """The operator gets the parser's words, and nothing else."""

    @pytest.mark.parametrize(
        "stderr, expected",
        [
            (
                "dumpcap: Invalid capture filter \"foo\" for interface"
                "\ndumpcap: (can't parse filter expression: syntax error)",
                "syntax error",
            ),
            ('dumpcap: "tcp port" isn\'t a valid capture filter', "not a valid capture filter"),
        ],
    )
    def test_the_parsers_own_explanation_survives(self, stderr: str, expected: str) -> None:
        assert expected in _readable_reason(stderr)

    def test_nothing_internal_survives(self) -> None:
        """A path, a device name or a command line helps no one fix a filter."""
        stderr = (
            "C:" + chr(92) + "Program Files" + chr(92) + "Wireshark" + chr(92) + "dumpcap.exe -i "
            + chr(92) + "Device" + chr(92) + "NPF_{ABC} -f bad"
            + chr(10) + "dumpcap: (can't parse filter expression: syntax error)"
        )
        reason = _readable_reason(stderr)
        for leak in ("dumpcap.exe", "Program Files", "NPF_", "-i ", "C:"):
            assert leak not in reason, f"{leak} leaked into the operator's message"

    def test_an_unrecognised_rejection_still_says_something_true(self) -> None:
        assert _readable_reason("something else entirely") == "the capture tool rejected it"


class TestNothingIsFabricated:
    """The failure path must not manufacture activity to fill the screen."""

    def test_the_service_holds_no_sample_or_placeholder_packets(self) -> None:
        code = _code_only(SERVICE).lower()
        for invented in ("random.", "fake", "sample_packet", "placeholder", "dummy"):
            assert invented not in code, f"{invented} found in the capture service"


class TestShutdownLeavesNothingBehind:
    """PT-01: dumpcap outliving the console that started it."""

    def test_shutdown_uses_the_sessionless_stop(self) -> None:
        """``stop`` requires a session; shutdown has none and must say so.

        Passing ``None`` to ``stop`` stopped raising a permission error and
        started raising a session error, so every shutdown threw before it
        stopped anything and the capture child was left running.
        """
        code = _code_only(SERVICE)
        shutdown = code[code.index("def shutdown") :]
        shutdown = shutdown[: shutdown.index("def ", 10)]
        assert "stop_for_shutdown" in shutdown
        assert "self.stop(None" not in shutdown

    def test_termination_covers_the_whole_process_tree(self) -> None:
        """TShark does not capture - dumpcap does, as its child."""
        reader = (
            Path(__file__).resolve().parent.parent
            / "aethra_sec"
            / "integrations"
            / "pyshark_capture"
            / "live_capture.py"
        )
        code = _code_only(reader)
        terminate = code[code.index("def _terminate_tshark") :]
        terminate = terminate[: terminate.index("def _run")]
        assert "children(recursive=True)" in terminate, (
            "only the tracked process is terminated; dumpcap survives it"
        )
        assert "wait_procs" in terminate, "termination is not confirmed"

    def test_liveness_and_termination_read_the_same_pids(self) -> None:
        """Two copies of the enumeration could disagree about what is running.

        The one that decides whether capture is alive and the one that decides
        what to kill have to be the same list, or a process can be reported
        running and never terminated.
        """
        reader = (
            Path(__file__).resolve().parent.parent
            / "aethra_sec"
            / "integrations"
            / "pyshark_capture"
            / "live_capture.py"
        )
        code = _code_only(reader)
        terminate = code[code.index("def _terminate_tshark") :]
        terminate = terminate[: terminate.index("def _run")]
        assert "self._child_pids()" in terminate
        assert "_current_tshark" not in terminate, (
            "termination enumerates the children a second time"
        )


class TestTheLivenessCheckIsInert:
    """It runs on a UI timer, so it must not do anything but look."""

    def test_no_module_signals_a_process_to_ask_whether_it_is_alive(self) -> None:
        """``os.kill(pid, 0)`` is a POSIX idiom that Windows reads differently.

        ``signal.CTRL_C_EVENT`` is 0, so CPython routes ``os.kill(pid, 0)`` to
        ``GenerateConsoleCtrlEvent`` and delivers a real Ctrl+C to that process
        group. Asked on every interface tick against a console-attached TShark,
        it interrupted the console the application was running in: the capture
        died, ``root.mainloop()`` raised ``KeyboardInterrupt`` and cmd.exe
        asked whether to terminate the batch job.
        """
        root = Path(__file__).resolve().parent.parent / "aethra_sec"
        offenders: list[str] = []
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                name = (
                    f"{getattr(target.value, 'id', '')}.{target.attr}"
                    if isinstance(target, ast.Attribute)
                    else getattr(target, "id", "")
                )
                if name == "os.kill":
                    offenders.append(f"{path.name}:{node.lineno}")
        assert not offenders, (
            "os.kill sends a console control event on Windows; use psutil: "
            f"{offenders}"
        )

    def test_liveness_uses_psutil(self) -> None:
        reader = (
            Path(__file__).resolve().parent.parent
            / "aethra_sec"
            / "integrations"
            / "pyshark_capture"
            / "live_capture.py"
        )
        code = _code_only(reader)
        alive = code[code.index("def capture_process_alive") :]
        alive = alive[: alive.index("def _terminate_tshark")]
        assert "psutil" in alive
        assert "is_running()" in alive, "the check does not confirm the process runs"

    def test_a_missing_psutil_does_not_mark_a_healthy_capture_failed(self) -> None:
        """Saying "dead" when the answer is unknown would fail a live capture."""
        reader = (
            Path(__file__).resolve().parent.parent
            / "aethra_sec"
            / "integrations"
            / "pyshark_capture"
            / "live_capture.py"
        )
        code = _code_only(reader)
        alive = code[code.index("def capture_process_alive") :]
        alive = alive[: alive.index("def _terminate_tshark")]
        fallback = alive[alive.index("except Exception") :]
        assert "return True" in fallback[: fallback.index("for pid")]


class TestShutdownIsAttributable:
    """An application that closes on its own must say who asked."""

    def test_shutdown_records_its_origin(self) -> None:
        application = (
            Path(__file__).resolve().parent.parent
            / "aethra_sec"
            / "core"
            / "application.py"
        )
        code = _code_only(application)
        assert "APPLICATION SHUTDOWN REQUEST" in code
        for field in ("reason=%s", "thread=%s", "capture=%s", "source=%s"):
            assert field in code, f"the shutdown log omits {field}"


class TestAStartCannotClobberARunningCapture:
    """The window between the reader starting and TShark appearing."""

    def test_the_start_guard_covers_the_starting_window(self) -> None:
        """``is_running`` is False while a capture is still coming up.

        Guarding on it let a second start slip through, overwrite the
        interface, filter and state, and leave a healthy capture reporting
        FAILED while packets were still arriving.
        """
        code = _code_only(SERVICE)
        start = code[code.index("def start") :]
        start = start[: start.index("def ", 10)]
        guard = start[: start.index("raise CaptureError")]
        assert "self.state.is_active" in guard, (
            "start() guards on is_running, which is False during STARTING"
        )


class TestForcedKillLeavesNothingRunning:
    """§61 - the case an exit path cannot cover.

    Terminating capture cleanly is the reader's job. This is the other case:
    the console killed outright by Task Manager, ``Stop-Process -Force`` or a
    crash, where no Python runs at all. An ``atexit`` handler does not fire on
    ``os._exit`` or a hard kill, so the cleanup has to belong to the kernel.
    """

    def test_the_job_module_asks_for_kill_on_close(self) -> None:
        from aethra_sec.integrations.pyshark_capture import jobs

        assert jobs._KILL_ON_JOB_CLOSE == 0x00002000  # noqa: SLF001

    def test_adoption_is_attempted_for_every_capture_child(self) -> None:
        reader = (
            Path(__file__).resolve().parent.parent
            / "aethra_sec"
            / "integrations"
            / "pyshark_capture"
            / "live_capture.py"
        )
        code = _code_only(reader)
        pids = code[code.index("def _child_pids") :]
        pids = pids[: pids.index("def capture_process_alive")]
        assert "jobs.adopt" in pids, "capture children are not adopted into the job"

    def test_hardening_never_breaks_capture(self) -> None:
        """A job that cannot be created must not stop a capture starting."""
        from aethra_sec.integrations.pyshark_capture import jobs

        # An impossible pid exercises the failure path.
        assert jobs.adopt(-1) is False
        assert jobs.adopt(0) is False

    def test_it_is_a_no_op_off_windows(self) -> None:
        """The module must import and answer safely on any platform."""
        source = (
            Path(__file__).resolve().parent.parent
            / "aethra_sec"
            / "integrations"
            / "pyshark_capture"
            / "jobs.py"
        ).read_text(encoding="utf-8")
        assert 'os.name != "nt"' in source, "no non-Windows guard"
