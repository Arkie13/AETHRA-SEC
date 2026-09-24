"""Hostname and operating system in the host inventory.

Neither field is a property of a packet. Capture reads an address and a MAC
off the wire; a hostname needs a reverse DNS lookup and an operating system
needs an Nmap fingerprint. An inventory a capture built therefore has neither
until something goes and asks - and the screen showed a bare dash either way,
so an operator could not tell "nobody asked" from "asked, and there is no
answer", nor what to do about it.

What is pinned here:

* the three states of a hostname cell are distinguishable, and none of them
  invents a name;
* an unscanned host says it is unscanned rather than showing a dash;
* resolving records the attempt whether or not a name came back, so a nameless
  address is asked once rather than on every pass;
* a bulk resolve is bounded, de-duplicated, and needs `host.manage`;
* the background resolver stays off until it is switched on.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY
from aethra_sec.database.migrations import LATEST_VERSION, MIGRATIONS
from aethra_sec.models.enums import RiskLevel
from aethra_sec.models.host import Host
from aethra_sec.services.host_service import (
    AUTO_RESOLVE_BATCH,
    MAX_RESOLVE_BATCH,
    HostService,
    ResolveResult,
)


def _host(**overrides: Any) -> Host:
    """A host row with the fields under test."""
    fields: dict[str, Any] = {
        "id": 1,
        "ip_address": "192.168.100.31",
        "mac_address": "30:89:4a:85:4a:c1",
        "risk_level": RiskLevel.INFORMATIONAL,
    }
    fields.update(overrides)
    return Host(**fields)  # type: ignore[arg-type]


class _Hosts:
    """The repository calls the service makes, recorded."""

    def __init__(self, hosts: list[Host], names: dict[str, str] | None = None) -> None:
        self._hosts = {host.id: host for host in hosts}
        self.names = names or {}
        self.identity_writes: list[tuple[int, str]] = []
        self.marked: list[list[int]] = []
        self.unresolved_calls: list[int] = []

    def get(self, host_id: int) -> Host | None:
        return self._hosts.get(host_id)

    def unresolved_hostnames(self, limit: int = 50) -> list[Host]:
        self.unresolved_calls.append(limit)
        pending = [
            host for host in self._hosts.values()
            if not host.hostname and host.hostname_checked_at is None
        ]
        return pending[:limit]

    def count_unresolved_hostnames(self) -> int:
        return len(self.unresolved_hostnames(limit=10_000))

    def update_identity(self, host_id: int, **fields: Any) -> None:
        self.identity_writes.append((host_id, str(fields.get("hostname", ""))))

    def mark_hostname_checked(self, host_ids: Any) -> int:
        ids = list(host_ids)
        self.marked.append(ids)
        for host_id in ids:
            host = self._hosts.get(host_id)
            if host is not None:
                host.hostname_checked_at = datetime.now(tz=timezone.utc)
        return len(ids)


class _Audit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def record(self, action: str, **fields: Any) -> None:
        self.entries.append({"action": action, **fields})


class _Access:
    def __init__(self) -> None:
        self.checks: list[str] = []

    def require(self, session: Any, permission: str, target: str = "") -> Any:
        self.checks.append(str(permission))
        return session


def _service(hosts: _Hosts) -> HostService:
    """A host service wired to the recording doubles."""
    return HostService(
        hosts, None, None, None, _Audit(), _Access()  # type: ignore[arg-type]
    )


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer lookups from the fixture rather than the network."""
    import aethra_sec.services.host_service as module

    def fake(address: str, **_kwargs: Any) -> str:
        return _no_real_dns.answers.get(address, "")  # type: ignore[attr-defined]

    _no_real_dns.answers = {}  # type: ignore[attr-defined]
    monkeypatch.setattr(module, "resolve_hostname", fake)


# ---------------------------------------------------------------------------
# What a cell says
# ---------------------------------------------------------------------------
class TestHostnameText:
    """The column answers "what is this host called", and nothing else.

    It used to answer with the *lookup's* state - "Not checked" or "Not
    resolved". Beside a completed assessment, "Not checked" read as "this host
    was skipped", which was untrue, and it was the most common cell on the
    screen. The identity column now says "Unknown"; which of the two absences
    applies is still recorded, and is shown where it is actually useful.
    """

    def test_a_resolved_name_is_shown(self) -> None:
        """The ordinary case."""
        assert _host(hostname="db01.lab").hostname_text == "db01.lab"

    def test_an_unresolved_name_reads_unknown(self) -> None:
        """Both absences read the same in the identity column."""
        assert _host().hostname_text == "Unknown"
        assert (
            _host(hostname_checked_at=datetime.now(tz=timezone.utc)).hostname_text
            == "Unknown"
        )

    def test_the_column_never_implies_the_assessment_was_skipped(self) -> None:
        """"Not checked" beside COMPLETED was the contradiction to remove."""
        for host in (
            _host(),
            _host(hostname_checked_at=datetime.now(tz=timezone.utc)),
        ):
            lowered = host.hostname_text.lower()
            for implication in ("not checked", "checked", "skipped", "pending"):
                assert implication not in lowered, (
                    f"{host.hostname_text!r} describes the lookup's progress "
                    "in a column about the host's identity"
                )

    def test_the_lookup_state_is_still_recorded_separately(self) -> None:
        """The distinction is preserved, just not in the identity column."""
        never = _host().hostname_lookup_text
        empty = _host(
            hostname_checked_at=datetime.now(tz=timezone.utc)
        ).hostname_lookup_text
        resolved = _host(hostname="db01.lab").hostname_lookup_text
        assert len({never, empty, resolved}) == 3, (
            "a lookup that was never made and one that came back empty are "
            "different facts and must stay distinguishable"
        )
        assert "not looked up" in never.lower()
        assert "no reverse dns" in empty.lower()

    def test_the_lookup_state_says_nothing_about_the_host(self) -> None:
        """A device with no DNS record is an ordinary device."""
        for text in (
            _host().hostname_lookup_text,
            _host(
                hostname_checked_at=datetime.now(tz=timezone.utc)
            ).hostname_lookup_text,
        ):
            lowered = text.lower()
            for verdict in ("offline", "down", "invalid", "fail", "error"):
                assert verdict not in lowered, (
                    f"{text!r} describes the host, not the lookup"
                )

    def test_no_state_invents_a_name(self) -> None:
        """The address is never dressed up as a hostname (§15)."""
        for host in (_host(), _host(hostname_checked_at=datetime.now(tz=timezone.utc))):
            assert host.ip_address not in host.hostname_text

    def test_display_name_still_falls_back_to_the_address(self) -> None:
        """The label used elsewhere is unchanged - it is not a status line."""
        assert _host().display_name == "192.168.100.31"


class TestOperatingSystemText:
    """An unscanned host says it is unscanned."""

    def test_a_fingerprint_is_shown_with_its_accuracy(self) -> None:
        """Accuracy matters: Nmap guesses, and says how hard it is guessing."""
        assert _host(os_name="Linux 5.0 - 5.7", os_accuracy=100).os_text == (
            "Linux 5.0 - 5.7 (100%)"
        )

    def test_a_fingerprint_without_accuracy_is_shown_plain(self) -> None:
        """Not every source reports a confidence."""
        assert _host(os_name="Windows Server 2019").os_text == "Windows Server 2019"

    def test_an_unscanned_host_says_it_is_unscanned(self) -> None:
        """Rather than a dash, which reads as "unknown for no stated reason"."""
        assert _host().os_text == "not scanned"

    def test_it_never_guesses_from_the_mac_or_the_traffic(self) -> None:
        """Only a fingerprint produces an OS name."""
        host = _host(mac_address="00:50:56:aa:bb:cc", packet_count=21904)
        assert host.os_text == "not scanned"


# ---------------------------------------------------------------------------
# Resolving
# ---------------------------------------------------------------------------
class TestBulkResolution:
    """One click has to be able to cover an inventory."""

    def test_resolved_names_are_stored(self) -> None:
        """The point of the exercise."""
        hosts = _Hosts([_host(id=1, ip_address="10.0.0.1")])
        _no_real_dns.answers["10.0.0.1"] = "gw.lab"  # type: ignore[attr-defined]
        result = _service(hosts).resolve_hostnames(object(), None)
        assert result.resolved == 1
        assert hosts.identity_writes == [(1, "gw.lab")]

    def test_a_failed_lookup_stores_nothing(self) -> None:
        """No name is invented for an address that has none (§15)."""
        hosts = _Hosts([_host(id=1, ip_address="10.0.0.1")])
        result = _service(hosts).resolve_hostnames(object(), None)
        assert result.resolved == 0
        assert hosts.identity_writes == []

    def test_the_attempt_is_recorded_even_when_nothing_resolves(self) -> None:
        """Otherwise the same nameless addresses are queried forever."""
        hosts = _Hosts([_host(id=1), _host(id=2, ip_address="10.0.0.2")])
        _service(hosts).resolve_hostnames(object(), None)
        assert sorted(hosts.marked[0]) == [1, 2]

    def test_a_second_pass_has_nothing_left_to_do(self) -> None:
        """Because the first pass recorded that it asked."""
        hosts = _Hosts([_host(id=1), _host(id=2, ip_address="10.0.0.2")])
        service = _service(hosts)
        service.resolve_hostnames(object(), None)
        assert service.resolve_hostnames(object(), None).attempted == 0

    def test_many_hosts_are_covered_by_one_call(self) -> None:
        """Ninety hosts must not mean ninety clicks."""
        hosts = _Hosts([_host(id=i, ip_address=f"10.0.0.{i}") for i in range(1, 91)])
        assert _service(hosts).resolve_hostnames(object(), None).attempted == 90

    def test_one_call_is_bounded(self) -> None:
        """A large inventory cannot become thousands of queries at once."""
        hosts = _Hosts(
            [_host(id=i, ip_address=f"10.1.{i // 256}.{i % 256}") for i in range(1, 900)]
        )
        result = _service(hosts).resolve_hostnames(object(), None)
        assert result.attempted == MAX_RESOLVE_BATCH

    def test_an_explicit_selection_is_used_as_given(self) -> None:
        """Selecting rows resolves those rows."""
        hosts = _Hosts([_host(id=i, ip_address=f"10.0.0.{i}") for i in (1, 2, 3)])
        result = _service(hosts).resolve_hostnames(object(), [2, 3])
        assert result.attempted == 2
        assert sorted(hosts.marked[0]) == [2, 3]

    def test_a_repeated_selection_is_looked_up_once(self) -> None:
        """A duplicated id is not a reason to query twice."""
        hosts = _Hosts([_host(id=1, ip_address="10.0.0.1")])
        result = _service(hosts).resolve_hostnames(object(), [1, 1, 1])
        assert result.attempted == 1

    def test_an_unknown_id_is_skipped_rather_than_failing(self) -> None:
        """A stale selection must not break the whole batch."""
        hosts = _Hosts([_host(id=1, ip_address="10.0.0.1")])
        assert _service(hosts).resolve_hostnames(object(), [1, 999]).attempted == 1

    def test_an_empty_inventory_does_nothing_quietly(self) -> None:
        """No audit entry for a round that did not happen."""
        hosts = _Hosts([])
        service = _service(hosts)
        assert service.resolve_hostnames(object(), None).attempted == 0
        assert hosts.marked == []

    def test_resolving_requires_the_manage_permission(self) -> None:
        """Writing to the inventory is not a view operation."""
        hosts = _Hosts([_host(id=1)])
        service = _service(hosts)
        service.resolve_hostnames(object(), None)
        assert "host.manage" in service._access.checks  # noqa: SLF001

    def test_the_round_is_audited_with_what_it_found(self) -> None:
        """A change to the inventory is a recorded change."""
        hosts = _Hosts([_host(id=1, ip_address="10.0.0.1")])
        _no_real_dns.answers["10.0.0.1"] = "gw.lab"  # type: ignore[attr-defined]
        service = _service(hosts)
        service.resolve_hostnames(object(), None)
        detail = service._audit.entries[-1]["detail"]  # noqa: SLF001
        assert "1 resolved" in detail


class TestResolveResult:
    """What the screen and the audit trail are told."""

    def test_addresses_without_a_record_are_counted(self) -> None:
        """Attempted minus resolved, stated rather than left to arithmetic."""
        assert ResolveResult(attempted=90, resolved=12).without_record == 78

    def test_the_summary_states_all_three_numbers(self) -> None:
        """So the status line is worth reading."""
        summary = ResolveResult(attempted=90, resolved=12).summary()
        assert "90" in summary and "12" in summary and "78" in summary

    def test_an_empty_round_says_so_plainly(self) -> None:
        """Not "0 resolved", which reads like a failure."""
        assert "No hosts" in ResolveResult().summary()

    def test_counts_can_never_go_negative(self) -> None:
        """A defensive floor, so a miscount cannot print nonsense."""
        assert ResolveResult(attempted=0, resolved=5).without_record == 0


class TestBackgroundResolver:
    """It exists so a growing inventory does not need babysitting."""

    def test_it_is_off_until_switched_on(self) -> None:
        """Every lookup is a DNS query the operator should be choosing."""
        assert SETTING_SPEC_BY_KEY["hosts.auto_resolve_hostnames"].default is False

    def test_its_interval_is_configurable(self) -> None:
        """And cannot be set to zero."""
        assert SETTING_SPEC_BY_KEY["hosts.resolve_interval_minutes"].minimum == 1

    def test_a_pass_is_smaller_than_an_operator_triggered_one(self) -> None:
        """It runs unattended and repeatedly; it should stay quiet."""
        assert AUTO_RESOLVE_BATCH < MAX_RESOLVE_BATCH

    def test_a_pass_needs_no_session(self) -> None:
        """There is no operator present on the scheduler thread."""
        hosts = _Hosts([_host(id=1, ip_address="10.0.0.1")])
        _no_real_dns.answers["10.0.0.1"] = "gw.lab"  # type: ignore[attr-defined]
        assert _service(hosts).resolve_pending().resolved == 1

    def test_a_pass_records_its_attempts_too(self) -> None:
        """So the background job does not re-query the same addresses."""
        hosts = _Hosts([_host(id=1)])
        _service(hosts).resolve_pending()
        assert hosts.marked == [[1]]

    def test_a_pass_is_bounded(self) -> None:
        """A busy network must not turn the inventory into a DNS flood."""
        hosts = _Hosts([_host(id=i, ip_address=f"10.0.0.{i}") for i in range(1, 200)])
        assert _service(hosts).resolve_pending().attempted == AUTO_RESOLVE_BATCH


class TestMigration:
    """The attempt timestamp needs a column to live in."""

    def test_the_migration_is_registered(self) -> None:
        """An existing installation upgrades on next start."""
        names = [migration.name for migration in MIGRATIONS]
        assert "hostname_lookup_state" in names
        assert LATEST_VERSION >= 4

    def test_it_is_guarded_so_it_can_run_twice(self) -> None:
        """A fresh install already has the column from the schema."""
        import inspect

        from aethra_sec.database.migrations import _apply_hostname_lookup_state

        source = inspect.getsource(_apply_hostname_lookup_state)
        assert '_column_exists(db, "hosts", "hostname_checked_at")' in source

    def test_existing_rows_start_as_never_looked_up(self) -> None:
        """Which is the truthful state: no lookup was ever recorded."""
        import inspect

        from aethra_sec.database.migrations import _apply_hostname_lookup_state

        source = inspect.getsource(_apply_hostname_lookup_state)
        assert "DATETIME(6) NULL" in source
