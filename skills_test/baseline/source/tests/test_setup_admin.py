"""Setup: one implementation, no second factor, no leaked secrets (§48).

Setup writes credentials and creates the account that administers the system,
so the parts that are easy to get quietly wrong are pinned here:

* the console path and the graphical path must share one implementation;
* a secret must never be echoed, printed back, or left in an error message;
* writing the configuration must not destroy what is already in it;
* and none of it may reintroduce the email second factor that was removed.
"""

from __future__ import annotations

import inspect
import smtplib
from pathlib import Path

import pytest

from aethra_sec.services.email_service import describe_smtp_error, mask_email
from aethra_sec.setup import configfile, provisioning
from scripts import setup_admin


class TestThereIsOneSetupImplementation:
    """setup.bat, the wizard and this script must not diverge."""

    def test_the_script_delegates_rather_than_reimplementing(self) -> None:
        source = inspect.getsource(setup_admin)
        assert "aethra_sec.setup.console" in source
        # The things it used to do itself, which are now the shared core's job.
        for reimplementation in ("getpass", "smtplib", "_write_env", "create_user"):
            assert reimplementation not in source, (
                f"setup_admin.py has grown its own {reimplementation} again; "
                "that is the duplication this file exists to prevent"
            )

    def test_the_wizard_and_the_console_use_the_same_provisioning(self) -> None:
        from aethra_sec.setup import console, wizard

        for module in (console, wizard):
            source = inspect.getsource(module)
            assert "provisioning.create_administrator" in source
            assert "provisioning.prepare_database" in source

    def test_the_health_report_has_one_renderer(self) -> None:
        from aethra_sec.setup import console, wizard

        for module in (console, wizard):
            assert "run_health_check" in inspect.getsource(module)


class TestNoSecondFactor:
    """The removal must be structural, not a configuration flag."""

    @pytest.mark.parametrize(
        "forbidden",
        [
            # Identifiers, not prose. Setup deliberately *tells* the operator
            # that there is no second factor and that no login code will ever
            # be emailed, so the words themselves have to stay allowed; what
            # must not come back is anything that could implement one.
            "OtpService",
            "OtpSettings",
            "otp_required",
            "two_factor",
            "TWO_FACTOR",
            "complete_otp",
            "resend_otp",
            "AETHRA_OTP",
        ],
    )
    def test_the_setup_package_can_never_implement_a_second_factor(
        self, forbidden: str
    ) -> None:
        from aethra_sec import setup as setup_package

        package_dir = Path(inspect.getfile(setup_package)).parent
        for path in package_dir.glob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert forbidden not in text, f"{path.name} still references {forbidden}"

    def test_setup_states_plainly_that_there_is_no_second_factor(self) -> None:
        """The absence is worth saying out loud, not merely being true."""
        from aethra_sec.setup import console, wizard

        for module in (console, wizard):
            source = inspect.getsource(module).lower()
            assert "no second factor" in source or "has no second factor" in source

    def test_no_otp_settings_exist(self) -> None:
        import aethra_sec.config.settings as settings_module

        assert not hasattr(settings_module, "OtpSettings")
        assert hasattr(settings_module, "SmtpSettings")

    def test_smtp_settings_carry_no_login_requirement(self) -> None:
        from aethra_sec.config.settings import SmtpSettings

        fields = set(SmtpSettings.__dataclass_fields__)
        for absent in ("enabled", "require_for_admin", "ttl_seconds", "max_attempts"):
            assert absent not in fields, (
                f"SmtpSettings.{absent} would only make sense for a login step"
            )


class TestMaskedAddress:
    """Setup confirms the address without printing it back in full."""

    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            ("administrator@gmail.com", "a" + "*" * 12 + "@gmail.com"),
            ("ab@x.io", "a*@x.io"),
        ],
    )
    def test_only_the_first_character_survives(
        self, address: str, expected: str
    ) -> None:
        assert mask_email(address) == expected

    @pytest.mark.parametrize("bad", ["", "no-at-sign", "@nolocal"])
    def test_an_unusable_address_reveals_nothing(self, bad: str) -> None:
        assert mask_email(bad) == "the configured address"


class TestSmtpErrorsStaySafe:
    """A failure must explain itself without echoing the credential."""

    def test_an_auth_failure_explains_the_gmail_case(self) -> None:
        message = describe_smtp_error(
            smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")
        )
        assert "App Password" in message

    def test_a_password_in_an_error_is_redacted(self) -> None:
        message = describe_smtp_error(
            ValueError("login failed for password=hunter2-not-a-real-secret")
        )
        assert "hunter2" not in message
        assert "[redacted]" in message

    def test_an_unreachable_server_says_so(self) -> None:
        message = describe_smtp_error(smtplib.SMTPConnectError(421, b"unavailable"))
        assert "could not be reached" in message


class TestTheConfigurationFileIsWrittenSafely:
    """Setup runs again over a working deployment; it must not damage it."""

    def test_an_existing_key_is_replaced_not_duplicated(self, tmp_path: Path) -> None:
        target = tmp_path / "aethra-sec.env"
        target.write_text("AETHRA_DB_HOST=old\n", encoding="utf-8")
        configfile.write({"AETHRA_DB_HOST": "new"}, target)
        text = target.read_text(encoding="utf-8")
        assert text.count("AETHRA_DB_HOST=") == 1
        assert "AETHRA_DB_HOST=new" in text

    def test_unrelated_settings_survive(self, tmp_path: Path) -> None:
        target = tmp_path / "aethra-sec.env"
        target.write_text(
            "# a comment worth keeping\nAETHRA_LOG_LEVEL=DEBUG\nAETHRA_DB_HOST=old\n",
            encoding="utf-8",
        )
        configfile.write({"AETHRA_DB_HOST": "new"}, target)
        text = target.read_text(encoding="utf-8")
        assert "AETHRA_LOG_LEVEL=DEBUG" in text
        assert "# a comment worth keeping" in text

    def test_a_missing_file_is_created(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "aethra-sec.env"
        configfile.write({"AETHRA_DB_NAME": "aethra_sec"}, target)
        assert target.is_file()
        assert configfile.load(target).get("AETHRA_DB_NAME") == "aethra_sec"

    def test_a_secret_is_never_returned_by_describe(self, tmp_path: Path) -> None:
        target = tmp_path / "aethra-sec.env"
        configfile.write(
            {
                "AETHRA_DB_PASSWORD": "not-a-real-password",
                "AETHRA_SMTP_PASSWORD": "also-not-real",
                "AETHRA_DB_HOST": "127.0.0.1",
            },
            target,
        )
        described = configfile.load(target).describe()
        assert described["AETHRA_DB_PASSWORD"] == "(set)"
        assert described["AETHRA_SMTP_PASSWORD"] == "(set)"
        assert described["AETHRA_DB_HOST"] == "127.0.0.1"
        assert "not-a-real-password" not in str(described)

    def test_the_write_is_atomic(self) -> None:
        """A half-written configuration must not be able to exist."""
        source = inspect.getsource(configfile.write)
        assert "os.replace" in source


class TestAdministratorValidation:
    """The rules are the same wherever the details were typed."""

    def test_a_short_password_is_refused(self) -> None:
        problem = provisioning.validate_admin_input(
            "operator", "short1!A", "short1!A", "a@b.com"
        )
        assert problem

    def test_mismatched_confirmation_is_refused(self) -> None:
        problem = provisioning.validate_admin_input(
            "operator", "Str0ng-Passphrase!", "Str0ng-Passphrase?", "a@b.com"
        )
        assert "do not match" in problem

    def test_a_missing_email_is_refused(self) -> None:
        problem = provisioning.validate_admin_input(
            "operator", "Str0ng-Passphrase!", "Str0ng-Passphrase!", ""
        )
        assert problem

    def test_a_valid_administrator_is_accepted(self) -> None:
        assert provisioning.validate_admin_input(
            "soc.lead", "Str0ng-Passphrase!", "Str0ng-Passphrase!", "soc@example.com"
        ) == ""

    def test_the_password_never_appears_in_a_refusal(self) -> None:
        secret = "Str0ng-Passphrase!"
        problem = provisioning.validate_admin_input("x", secret, secret + "?", "a@b.com")
        assert secret not in problem

    def test_creation_hashes_and_discards_the_plaintext(self) -> None:
        source = inspect.getsource(provisioning.create_administrator)
        assert "PasswordHashService().hash(password)" in source
        assert "del password" in source
        assert "password_hash=hashed.hash" in source


class TestNothingIsSeededButConfiguration:
    """A fresh installation must contain no security records at all."""

    def test_provisioning_seeds_only_static_configuration(self) -> None:
        source = inspect.getsource(provisioning)
        assert "seed_all" in source
        for fabricated in ("INSERT INTO hosts", "INSERT INTO snort_alerts",
                           "INSERT INTO incidents", "INSERT INTO scan_results"):
            assert fabricated not in source

    def test_existing_history_is_counted_before_it_is_touched(self) -> None:
        """An upgrade should be able to say what it is preserving."""
        source = inspect.getsource(provisioning.prepare_database)
        assert source.index("count_existing_history") < source.index("run_migrations")
