"""Host identity must be observed, never inferred from a frame that cannot carry it.

Found by execution during the full-system bug hunt, not by reading the code.
An integrity sweep of the live installation asked a question with only one
possible honest answer - *can this host own this MAC address?* - and 1,775 of
1,986 inventory rows answered no.

Three separate defects produced them, and they share a shape: a value was read
off a frame and stored against whichever address the frame named, without
asking whether that frame could carry that host's identity at all.

**A routed frame's source MAC is the router's.** A packet from a machine on the
internet reaches this link with the gateway's hardware address in the source
field; the remote machine's own MAC never appears on this link. Storing it
attached one gateway MAC to 528 distinct public addresses - and a MAC names
exactly one interface, so the record refuted itself.

**A broadcast frame's destination MAC belongs to nobody.** An ARP request names
a target IP and is addressed to ff:ff:ff:ff:ff:ff. Stored against the target,
it gave 260 hosts the broadcast address as their own hardware identity. IEEE
802 reserves bit 0 of the first octet for exactly this distinction, so this is
not weak evidence - it is impossible.

**An alert endpoint is not a discovered host.** Snort alerts name a remote
address at one end far more often than not, and every one of them was enrolled
into Host Inventory. Google and Facebook front-ends appeared there as if they
were devices found on the laboratory network.

What these tests pin down is narrow and deliberate: the *field* is left empty
when it cannot be known, and nothing else moves. No row is deleted, no
timestamp is rewritten, no value is substituted for the one removed. An unknown
MAC has to read as unknown - the failure mode being guarded against is a
console that answers a question it was never in a position to answer.
"""

from __future__ import annotations

import ast
import inspect
from datetime import timedelta
from pathlib import Path

import pytest

from aethra_sec.database.repositories.hosts import HostRepository
from aethra_sec.database.repositories.scans import ScanRepository
from aethra_sec.models.enums import EvidenceSource, ScanStatus
from aethra_sec.models.scan import Scan
from aethra_sec.services.snort_service import SnortService
from aethra_sec.utils.timeutil import utcnow

ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS = ROOT / "aethra_sec" / "database" / "migrations.py"


def _statements(path: Path) -> str:
    """Source with docstrings removed, so prose is not mistaken for code."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def _resolver(hosts: HostRepository, networks: tuple) -> SnortService:
    """A SnortService wired only for host resolution.

    ``_resolve_host`` reads the host repository and the sensor's own subnets
    and nothing else, so the rest of the collaborator graph is left out
    deliberately: constructing it would couple this test to services that have
    no part in the behaviour under test.
    """
    service = SnortService.__new__(SnortService)
    service._hosts = hosts  # noqa: SLF001
    service._networks = networks  # noqa: SLF001
    service._networks_read_at = utcnow()  # noqa: SLF001

    import threading

    service._network_lock = threading.Lock()  # noqa: SLF001
    return service


# ----------------------------------------------------------------------
# The MAC of a frame that cannot carry this host's identity
# ----------------------------------------------------------------------
class TestGroupMacIsNeverAHostIdentity:
    """ff:ff:ff:ff:ff:ff and friends name a set of receivers, not a machine."""

    @pytest.mark.parametrize(
        "mac",
        [
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:fb",  # IPv4 multicast
            "33:33:00:00:00:01",  # IPv6 multicast
            "01:80:c2:00:00:00",  # spanning tree
        ],
    )
    def test_a_group_address_is_refused(self, mac: str) -> None:
        from aethra_sec.services.packet_capture import _is_host_mac

        assert _is_host_mac(mac) is False

    @pytest.mark.parametrize(
        "mac",
        ["00:d4:9e:e0:aa:60", "30:89:4a:85:4a:c1", "f0-3f-95-0b-ce-77"],
    )
    def test_a_real_unicast_address_is_accepted(self, mac: str) -> None:
        from aethra_sec.services.packet_capture import _is_host_mac

        assert _is_host_mac(mac) is True

    def test_the_group_bit_is_what_decides(self) -> None:
        """Not a hardcoded list of known-bad values.

        A denylist would pass every test written against it and still admit
        the next multicast prefix nobody thought of.
        """
        from aethra_sec.services.packet_capture import _is_host_mac

        for octet in range(0, 256):
            mac = f"{octet:02x}:11:22:33:44:55"
            assert _is_host_mac(mac) is (octet % 2 == 0), mac


# ----------------------------------------------------------------------
# An alert endpoint is not a discovered host
# ----------------------------------------------------------------------
class TestSnortDoesNotEnrolRemoteEndpoints:
    """§57: alerts record addresses; they do not populate the inventory."""

    def test_an_off_link_endpoint_creates_no_inventory_row(self, clean_db) -> None:
        import ipaddress

        hosts = HostRepository(clean_db)
        service = _resolver(hosts, (ipaddress.ip_network("192.168.0.0/24"),))

        assert service._resolve_host("142.250.207.49") is None  # noqa: SLF001
        assert hosts.find_id_by_ip("142.250.207.49") is None
        assert clean_db.query_value("SELECT COUNT(*) FROM hosts") == 0

    def test_an_on_link_endpoint_is_enrolled(self, clean_db) -> None:
        import ipaddress

        hosts = HostRepository(clean_db)
        service = _resolver(hosts, (ipaddress.ip_network("192.168.0.0/24"),))

        host_id = service._resolve_host("192.168.0.77")  # noqa: SLF001
        assert host_id
        assert hosts.find_id_by_ip("192.168.0.77") == host_id

    def test_an_existing_row_is_always_linked(self, clean_db) -> None:
        """Even off-link.

        If the address is already in the inventory - put there by an operator,
        or by a scan of an authorised range - the alert must point at it. The
        guard is on *creating* identity, not on referencing what exists.
        """
        import ipaddress

        hosts = HostRepository(clean_db)
        known = hosts.upsert_observed(
            "203.0.113.9", observed_at=utcnow(), source=EvidenceSource.NMAP
        )
        service = _resolver(hosts, (ipaddress.ip_network("192.168.0.0/24"),))

        assert service._resolve_host("203.0.113.9") == known  # noqa: SLF001
        assert clean_db.query_value("SELECT COUNT(*) FROM hosts") == 1

    def test_no_subnet_known_means_nothing_is_enrolled(self, clean_db) -> None:
        """A sensor that cannot say what it is attached to must not guess."""
        hosts = HostRepository(clean_db)
        service = _resolver(hosts, ())

        assert service._resolve_host("192.168.0.77") is None  # noqa: SLF001
        assert clean_db.query_value("SELECT COUNT(*) FROM hosts") == 0

    def test_an_empty_address_is_not_a_host(self, clean_db) -> None:
        import ipaddress

        hosts = HostRepository(clean_db)
        service = _resolver(hosts, (ipaddress.ip_network("192.168.0.0/24"),))
        assert service._resolve_host("") is None  # noqa: SLF001


# ----------------------------------------------------------------------
# A scan that died is not a scan that is running
# ----------------------------------------------------------------------
class TestAbandonedScansAreClosed:
    """The scan list must not paint a four-day-old corpse as live activity."""

    @staticmethod
    def _scan(scans: ScanRepository, target: str) -> int:
        scan_id = scans.create_scan(
            Scan(target=target, profile="standard", created_at=utcnow())
        )
        scans.mark_running(scan_id, "nmap -sS " + target, "7.991")
        return scan_id

    def test_a_running_scan_is_closed_as_failed(self, clean_db) -> None:
        scans = ScanRepository(clean_db)
        scan_id = self._scan(scans, "192.168.0.1")

        closed = scans.reset_stuck_scans("Interrupted: the console stopped.")

        assert closed == [scan_id]
        row = clean_db.query_one(
            "SELECT status, finished_at, error_message FROM scans WHERE id = %s",
            (scan_id,),
        )
        assert row["status"] == str(ScanStatus.FAILED)
        assert row["finished_at"] is not None
        assert "Interrupted" in row["error_message"]

    def test_the_row_is_kept_not_deleted(self, clean_db) -> None:
        """The attempt happened. The record of it is evidence."""
        scans = ScanRepository(clean_db)
        self._scan(scans, "192.168.0.1")

        scans.reset_stuck_scans("Interrupted.")

        assert clean_db.query_value("SELECT COUNT(*) FROM scans") == 1

    def test_settled_scans_are_untouched(self, clean_db) -> None:
        scans = ScanRepository(clean_db)
        done = self._scan(scans, "192.168.0.2")
        scans.mark_completed(
            done, hosts_total=1, hosts_up=1, open_ports=3,
            findings_count=0, duration_seconds=1.5,
        )
        before = clean_db.query_one(
            "SELECT status, finished_at, error_message FROM scans WHERE id = %s",
            (done,),
        )

        assert scans.reset_stuck_scans("Interrupted.") == []

        after = clean_db.query_one(
            "SELECT status, finished_at, error_message FROM scans WHERE id = %s",
            (done,),
        )
        assert after == before

    def test_nothing_running_is_a_no_op(self, clean_db) -> None:
        scans = ScanRepository(clean_db)
        assert scans.reset_stuck_scans("Interrupted.") == []

    def test_the_reason_is_recorded_not_invented(self, clean_db) -> None:
        """The caller's text reaches the row.

        A generic "failed" would lose the distinction between a scan Nmap
        rejected and one whose console was closed, and those want different
        responses from an operator.
        """
        scans = ScanRepository(clean_db)
        scan_id = self._scan(scans, "192.168.0.3")

        scans.reset_stuck_scans("power loss during capture")

        assert clean_db.query_value(
            "SELECT error_message FROM scans WHERE id = %s", (scan_id,)
        ) == "power loss during capture"


class TestStartUpClosesAbandonedScans:
    """The reclamation has to be wired, not merely available."""

    def test_the_application_calls_it(self) -> None:
        from aethra_sec.core import application

        source = _statements(Path(inspect.getfile(application)))
        assert "reset_stuck_scans" in source

    def test_it_runs_before_the_scan_services_are_offered(self) -> None:
        """Ordering matters: a caller must never see a stale RUNNING row."""
        from aethra_sec.core import application

        source = _statements(Path(inspect.getfile(application)))
        assert source.index("reset_stuck_scans") < source.index("self.hosts = HostService")


# ----------------------------------------------------------------------
# The corrections themselves
# ----------------------------------------------------------------------
class TestCorrectionsAreConservative:
    """Both migrations clear one field and touch nothing else."""

    @pytest.mark.parametrize(
        "name", ["_apply_offlink_mac_correction", "_apply_group_mac_correction"]
    )
    def test_no_row_is_deleted(self, name: str) -> None:
        from aethra_sec.database import migrations

        body = inspect.getsource(getattr(migrations, name))
        statements = _statements_from_text(body)
        assert "DELETE" not in statements.upper()
        assert "TRUNCATE" not in statements.upper()
        assert "DROP" not in statements.upper()

    @pytest.mark.parametrize(
        "name", ["_apply_offlink_mac_correction", "_apply_group_mac_correction"]
    )
    def test_only_the_mac_field_is_written(self, name: str) -> None:
        """``updated_at = updated_at`` is a deliberate no-op, not an update.

        Rewriting the timestamp would misdate the observation - the host was
        seen when it was seen, and a correction to a derived field is not a
        new sighting.
        """
        from aethra_sec.database import migrations

        statements = _statements_from_text(
            inspect.getsource(getattr(migrations, name))
        )
        assert "SET mac_address = ''" in statements
        assert "updated_at = updated_at" in statements

    def test_nothing_is_substituted_for_the_cleared_value(self) -> None:
        """Empty, not a placeholder, not a guess, not 'unknown'."""
        from aethra_sec.database import migrations

        for name in ("_apply_offlink_mac_correction", "_apply_group_mac_correction"):
            statements = _statements_from_text(
                inspect.getsource(getattr(migrations, name))
            )
            assert "mac_address = ''" in statements

    def test_the_schema_stores_no_mac_as_empty_not_null(self) -> None:
        """The column is NOT NULL with an empty default.

        Writing NULL succeeded only because this server is not in strict
        mode; on a strict install the correction would have raised.
        """
        from aethra_sec.database import migrations

        for name in ("_apply_offlink_mac_correction", "_apply_group_mac_correction"):
            statements = _statements_from_text(
                inspect.getsource(getattr(migrations, name))
            )
            assert "mac_address = NULL" not in statements

    def test_the_group_check_uses_mod_not_a_percent_operator(self) -> None:
        """A bare "%" travels through a driver whose marker is "%s"."""
        from aethra_sec.database import migrations

        statements = _statements_from_text(
            inspect.getsource(migrations._apply_group_mac_correction)
        )
        assert "MOD(" in statements
        assert "% 2" not in statements

    def test_private_ranges_are_excluded_from_the_offlink_correction(self) -> None:
        """A private address can be on-link, so its MAC may be genuine."""
        from aethra_sec.database import migrations

        statements = _statements_from_text(
            inspect.getsource(migrations._apply_offlink_mac_correction)
        )
        for prefix in ("192.168.", "10.", "172.16.", "172.31.", "127.", "169.254."):
            assert prefix in statements, prefix


def _statements_from_text(text: str) -> str:
    """Docstring-stripped source for a single function given as text."""
    import textwrap

    tree = ast.parse(textwrap.dedent(text))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


class TestTheInventoryStaysIntact:
    """The corrections are only allowed to remove what cannot be true."""

    def test_an_on_link_mac_survives_both_corrections(self, clean_db) -> None:
        from aethra_sec.database import migrations

        hosts = HostRepository(clean_db)
        keep = hosts.upsert_observed(
            "192.168.0.42", observed_at=utcnow(), mac_address="00:d4:9e:e0:aa:60", source=EvidenceSource.PYSHARK
        )
        migrations._apply_offlink_mac_correction(clean_db)
        migrations._apply_group_mac_correction(clean_db)

        assert clean_db.query_value(
            "SELECT mac_address FROM hosts WHERE id = %s", (keep,)
        ) == "00:d4:9e:e0:aa:60"

    def test_a_public_address_loses_its_borrowed_mac(self, clean_db) -> None:
        from aethra_sec.database import migrations

        hosts = HostRepository(clean_db)
        bogus = hosts.upsert_observed(
            "142.250.207.49", observed_at=utcnow(), mac_address="d8:07:b6:6d:9e:30", source=EvidenceSource.PYSHARK
        )
        migrations._apply_offlink_mac_correction(clean_db)

        assert clean_db.query_value(
            "SELECT mac_address FROM hosts WHERE id = %s", (bogus,)
        ) == ""
        assert clean_db.query_value("SELECT COUNT(*) FROM hosts") == 1

    def test_an_on_link_broadcast_mac_is_cleared_but_the_host_kept(
        self, clean_db
    ) -> None:
        """The neighbour is real. Its recorded hardware identity is not."""
        from aethra_sec.database import migrations

        hosts = HostRepository(clean_db)
        real_host = hosts.upsert_observed(
            "192.168.1.4", observed_at=utcnow(), mac_address="ff:ff:ff:ff:ff:ff", source=EvidenceSource.PYSHARK
        )
        migrations._apply_group_mac_correction(clean_db)

        row = clean_db.query_one(
            "SELECT ip_address, mac_address FROM hosts WHERE id = %s", (real_host,)
        )
        assert row["ip_address"] == "192.168.1.4"
        assert row["mac_address"] == ""

    def test_timestamps_are_not_disturbed(self, clean_db) -> None:
        from aethra_sec.database import migrations

        hosts = HostRepository(clean_db)
        seen = utcnow() - timedelta(days=3)
        host_id = hosts.upsert_observed(
            "142.250.207.49", observed_at=seen, mac_address="d8:07:b6:6d:9e:30", source=EvidenceSource.PYSHARK
        )
        before = clean_db.query_one(
            "SELECT first_seen, last_seen, updated_at FROM hosts WHERE id = %s",
            (host_id,),
        )
        migrations._apply_offlink_mac_correction(clean_db)
        after = clean_db.query_one(
            "SELECT first_seen, last_seen, updated_at FROM hosts WHERE id = %s",
            (host_id,),
        )
        assert after == before

    def test_both_corrections_are_repeatable(self, clean_db) -> None:
        """Running them twice must not differ from running them once."""
        from aethra_sec.database import migrations

        hosts = HostRepository(clean_db)
        hosts.upsert_observed(
            "192.168.0.42", observed_at=utcnow(), mac_address="00:d4:9e:e0:aa:60", source=EvidenceSource.PYSHARK
        )
        hosts.upsert_observed(
            "8.8.8.8", observed_at=utcnow(), mac_address="d8:07:b6:6d:9e:30", source=EvidenceSource.PYSHARK
        )
        migrations._apply_offlink_mac_correction(clean_db)
        migrations._apply_group_mac_correction(clean_db)
        once = clean_db.query("SELECT ip_address, mac_address FROM hosts ORDER BY id")
        migrations._apply_offlink_mac_correction(clean_db)
        migrations._apply_group_mac_correction(clean_db)
        twice = clean_db.query("SELECT ip_address, mac_address FROM hosts ORDER BY id")

        assert once == twice
