"""Sign-out returns to the login window instead of exiting (§62, §74).

The behaviour is exercised end-to-end by the headless GUI driver; a display is
needed to build the console, so it is not part of this suite. These tests guard
the wiring that makes the behaviour possible, so it cannot silently regress:

* the login module exposes a reusable-root flow (``prepare_root`` /
  ``prompt_login``);
* ``run_console`` reports how it ended so the caller can loop;
* signing out tears down the console but **not** the services, while quitting
  tears down everything;
* the desktop entry point loops on a sign-out.
"""

from __future__ import annotations

import inspect

from aethra_sec import main as main_module
from aethra_sec.ui import app as app_module
from aethra_sec.ui import login as login_module


class TestReusableRootFlow:
    """Login can be shown repeatedly on one long-lived root."""

    def test_login_exposes_split_flow(self) -> None:
        """The loop needs to prepare the root once and prompt many times."""
        assert callable(login_module.prepare_root)
        assert callable(login_module.prompt_login)

    def test_run_login_still_works_as_a_wrapper(self) -> None:
        """The one-shot helper is kept for callers that want it."""
        source = inspect.getsource(login_module.run_login)
        assert "prepare_root(" in source
        assert "prompt_login(" in source

    def test_closing_login_does_not_destroy_the_shared_root(self) -> None:
        """Cancelling sign-in closes only the window; the loop owns the root."""
        source = inspect.getsource(login_module.LoginWindow._quit)
        assert "self.destroy()" in source
        assert "master.destroy" not in source


class TestConsoleReportsOutcome:
    """run_console tells the caller whether to re-show login or exit."""

    def test_run_console_returns_the_outcome(self) -> None:
        """The mainloop's exit reason is returned, not discarded."""
        source = inspect.getsource(app_module.run_console)
        assert "return window.outcome" in source
        assert inspect.signature(app_module.run_console).return_annotation == "str"

    def test_default_outcome_is_quit(self) -> None:
        """A console that is never signed out defaults to a full exit."""
        source = inspect.getsource(app_module.MainWindow.__init__)
        assert 'self.outcome = "quit"' in source


class TestSignOutKeepsServicesUp:
    """Signing out must not tear down the shared services."""

    def test_sign_out_does_not_shut_the_context_down(self) -> None:
        """Only the session and this console's widgets are torn down."""
        source = inspect.getsource(app_module.MainWindow._sign_out)
        assert 'self.outcome = "sign out"' in source
        assert "self.context.sign_out(" in source
        assert "self.context.shutdown(" not in source
        # It leaves the mainloop rather than destroying the reusable root.
        assert "self.root.quit()" in source
        assert "self.root.destroy()" not in source

    def test_sign_out_stops_capture(self) -> None:
        """A new operator must not inherit a running capture.

        Teardown has no session, so it uses the named internal path.
        ``stop()`` itself now requires a session: it used to default one to
        ``None`` and check the permission only when it was supplied, which
        made authorization opt-in.
        """
        teardown = inspect.getsource(app_module.MainWindow._teardown)
        assert "capture.stop_for_shutdown(" in teardown

    def test_quit_shuts_everything_down(self) -> None:
        """The window-close path still stops the services and the root."""
        source = inspect.getsource(app_module.MainWindow.close)
        assert 'self.outcome = "quit"' in source
        assert "self.context.shutdown(" in source
        assert "dispatch.shutdown()" in source
        assert "self.root.destroy()" in source

    def test_context_sign_out_leaves_services_started(self) -> None:
        """The context's own sign_out clears the session but not the services."""
        from aethra_sec.core.application import ApplicationContext

        source = inspect.getsource(ApplicationContext.sign_out)
        # Clears the session - now through set_session(None), which also detaches
        # the automatic-assessment queue so it stops attributing scans to a
        # session that no longer exists.
        assert "self.set_session(None)" in source
        set_session = inspect.getsource(ApplicationContext.set_session)
        assert "self.current_session = session" in set_session
        # sign_out must not stop the subsystems - that is shutdown()'s job.
        assert "_started" not in source
        assert "self.shutdown(" not in source


class TestDesktopLoop:
    """The entry point re-shows login after a sign-out."""

    def test_run_desktop_loops_on_sign_out(self) -> None:
        """A sign-out continues the loop; anything else exits it."""
        source = inspect.getsource(main_module._run_desktop)
        assert "prepare_root(" in source
        assert "while True:" in source
        assert "prompt_login(" in source
        assert 'run_console(' in source
        assert '!= "sign out"' in source

    def test_run_desktop_tears_down_once_at_the_end(self) -> None:
        """The root and the dispatcher are cleaned up when the loop ends."""
        source = inspect.getsource(main_module._run_desktop)
        assert "dispatch.shutdown()" in source
        assert "root.destroy()" in source
