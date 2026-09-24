"""Regressions for the interface and data-flow defects fixed after v1.0.0.

Each class pins the behaviour that was wrong, so the specific mistake cannot
come back:

* an incident showed one device even when its evidence named several;
* the sidebar counter never moved, because it counted every open incident
  rather than the ones nobody had read;
* assessment results dropped a hostname, MAC or OS the inventory already held,
  and rendered the OS accuracy onto a dash;
* the scroll container parented its content beside the canvas instead of
  inside it, and unbound the wheel as soon as the pointer touched any child;
* the row menu gave its pointer grab back while still posted, so clicking an
  entry landed on the widget underneath;
* the host inventory paired visible rows with unfiltered data when selecting
  a host another screen had asked for.

The widget cases here are the ones that need no display: the structural facts
are read from the source, exactly as the sign-out flow tests do, and the
arithmetic is called directly.
"""

from __future__ import annotations

import inspect
from datetime import datetime

import pytest

from aethra_sec.database.repositories.incidents import IncidentRepository
from aethra_sec.database.repositories.scans import ScanRepository
from aethra_sec.models.enums import HostStatus, RiskLevel
from aethra_sec.models.host import Host
from aethra_sec.models.incident import Incident
from aethra_sec.models.scan import NOT_DETECTED, ScanHostResult
from aethra_sec.services.correlation_service import CorrelationService
from aethra_sec.ui.screens import hosts as hosts_screen
from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen
from aethra_sec.ui.widgets import cards as cards_module
from aethra_sec.ui.widgets import tables as tables_module


class _Wheel:
    """The two fields :meth:`_wheel_steps` reads off a Tk event."""

    def __init__(self, *, num: int | None = None, delta: int = 0) -> None:
        self.num = num
        self.delta = delta


class _FakeHosts:
    """Stands in for the host repository during a device roll-up."""

    def __init__(self, known: dict[str, Host]) -> None:
        self._known = known
        self.lookups: list[str] = []

    def get_by_ip(self, ip_address: str) -> Host | None:
        self.lookups.append(ip_address)
        return self._known.get(ip_address)


class _Evidence:
    """A record carrying the endpoints an incident's evidence names."""

    def __init__(self, src_ip: str = "", dst_ip: str = "", ip_address: str = "") -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.ip_address = ip_address


def _devices(
    hosts: _FakeHosts,
    incident: Incident,
    alerts: list[_Evidence] = [],
    anomalies: list[_Evidence] = [],
    findings: list[_Evidence] = [],
) -> list[dict]:
    """Call the real roll-up with a stand-in repository."""
    service = object.__new__(CorrelationService)
    service._hosts = hosts  # noqa: SLF001 - the only collaborator it uses
    return CorrelationService._devices(  # noqa: SLF001
        service, incident, alerts, anomalies, findings
    )


# ---------------------------------------------------------------------------
# 1. An incident shows every device its evidence names
# ---------------------------------------------------------------------------
class TestIncidentDevices:
    """The roll-up reads the addresses out of the attached evidence."""

    def test_every_address_in_the_evidence_is_listed(self) -> None:
        """Two alerts against two targets produce three devices, not one."""
        incident = Incident(
            id=1, reference="INC-1", title="t",
            src_ip="10.0.0.5", dst_ip="10.0.0.9", affected_host_ip="10.0.0.9",
        )
        devices = _devices(
            _FakeHosts({}), incident,
            alerts=[
                _Evidence(src_ip="10.0.0.5", dst_ip="10.0.0.9"),
                _Evidence(src_ip="10.0.0.5", dst_ip="10.0.0.11"),
            ],
        )
        assert {d["ip"] for d in devices} == {"10.0.0.5", "10.0.0.9", "10.0.0.11"}
        assert devices[0]["ip"] == "10.0.0.5", "the source leads the list"
        # Each address is named once, however many records mention it.
        assert len(devices) == 3

    def test_anomalies_and_findings_contribute_devices(self) -> None:
        """Every evidence kind is read, not just Snort alerts."""
        incident = Incident(id=1, reference="INC-1", title="t")
        devices = _devices(
            _FakeHosts({}), incident,
            anomalies=[_Evidence(src_ip="192.168.1.4", dst_ip="192.168.1.7")],
            findings=[_Evidence(ip_address="192.168.1.9")],
        )
        assert {d["ip"] for d in devices} == {
            "192.168.1.4", "192.168.1.7", "192.168.1.9"
        }

    def test_the_attacker_is_listed_first_and_labelled(self) -> None:
        """An analyst looks for the source, so it leads the list."""
        incident = Incident(
            id=1, reference="INC-1", title="t", src_ip="10.0.0.5", dst_ip="10.0.0.9"
        )
        devices = _devices(_FakeHosts({}), incident)
        assert devices[0]["ip"] == "10.0.0.5"
        assert devices[0]["is_source"] is True
        assert devices[0]["role"] == "source"
        assert devices[1]["role"] == "target"

    def test_one_address_can_hold_both_roles(self) -> None:
        """A loopback scan is its own source and target; it is said once."""
        incident = Incident(
            id=1, reference="INC-1", title="t", src_ip="127.0.0.1", dst_ip="127.0.0.1"
        )
        devices = _devices(_FakeHosts({}), incident)
        assert len(devices) == 1
        assert devices[0]["role"] == "source and target"

    def test_known_devices_carry_their_inventory_detail(self) -> None:
        """Hostname, MAC and OS come from the inventory, never from a guess."""
        known = Host(
            id=7, ip_address="10.0.0.9", hostname="db01",
            mac_address="aa:bb:cc:dd:ee:ff", os_name="Debian", os_accuracy=96,
            status=HostStatus.UP, risk_level=RiskLevel.HIGH, is_trusted=True,
        )
        incident = Incident(
            id=1, reference="INC-1", title="t", src_ip="10.0.0.5", dst_ip="10.0.0.9"
        )
        devices = _devices(_FakeHosts({"10.0.0.9": known}), incident)
        target = next(d for d in devices if d["ip"] == "10.0.0.9")
        assert target["hostname"] == "db01"
        assert target["mac"] == "aa:bb:cc:dd:ee:ff"
        assert target["os"] == "Debian (96%)"
        assert target["host_id"] == 7
        assert target["is_trusted"] is True
        assert target["known"] is True

    def test_an_unknown_address_is_still_listed_but_says_so(self) -> None:
        """Nothing is invented for an address the inventory has never seen."""
        incident = Incident(id=1, reference="INC-1", title="t", src_ip="10.0.0.5")
        device = _devices(_FakeHosts({}), incident)[0]
        assert device["known"] is False
        assert device["hostname"] == ""
        assert device["os"] == ""

    def test_blank_addresses_are_skipped(self) -> None:
        """An incident with no endpoints produces no devices at all."""
        assert _devices(_FakeHosts({}), Incident(id=1, reference="INC-1", title="t")) == []

    def test_the_bundle_carries_the_devices(self) -> None:
        """The investigation view is handed the list it renders."""
        source = inspect.getsource(CorrelationService.evidence_bundle)
        assert '"devices": self._devices(' in source


# ---------------------------------------------------------------------------
# 2. The sidebar counter tracks unread incidents
# ---------------------------------------------------------------------------
class TestIncidentReadState:
    """Opening an incident has to change what the badge reports."""

    def test_the_counter_asks_for_unread_not_open(self) -> None:
        """Counting every open incident is what kept the badge frozen."""
        source = inspect.getsource(CorrelationService.open_incident_count)
        assert "count_unread()" in source
        assert "count_open()" not in source

    def test_opening_an_incident_marks_it_read(self) -> None:
        """The investigation view is where an incident becomes 'seen'."""
        source = inspect.getsource(CorrelationService.evidence_bundle)
        assert "mark_viewed(incident_id, session.user_id)" in source

    def test_marking_is_a_first_time_only_update(self) -> None:
        """The guard keeps the original reader and the original timestamp."""
        source = inspect.getsource(IncidentRepository.mark_viewed)
        assert "viewed_at IS NULL" in source

    def test_unread_means_open_and_never_viewed(self) -> None:
        """A resolved incident is not unread, whoever did or did not read it."""
        source = inspect.getsource(IncidentRepository.count_unread)
        assert "viewed_at IS NULL" in source
        assert "status IN" in source

    def test_the_incident_model_carries_the_read_state(self) -> None:
        """The screens and reports can see it, not just the counter."""
        incident = Incident(id=1, reference="INC-1", title="t")
        assert incident.viewed_at is None
        assert incident.viewed_by is None

    def test_the_schema_stores_it(self) -> None:
        """Read state survives a restart, so it has to be a column."""
        from aethra_sec.database.schema import INCIDENTS

        assert "viewed_at" in INCIDENTS
        assert "viewed_by" in INCIDENTS

    def test_an_existing_installation_gains_the_columns(self) -> None:
        """Migration 3 adds them without touching any incident data."""
        from aethra_sec.database.migrations import LATEST_VERSION, MIGRATIONS

        migration = {m.version: m for m in MIGRATIONS}[3]
        assert migration.name == "incident_read_state"
        assert LATEST_VERSION >= 3
        source = inspect.getsource(migration.apply)
        assert "ADD COLUMN viewed_at" in source
        # Idempotent: re-running against a schema that already has it is a no-op.
        assert "_column_exists(" in source


# ---------------------------------------------------------------------------
# 3. Assessment results show the hostname, MAC and OS that are known
# ---------------------------------------------------------------------------
class TestAssessmentHostFields:
    """The screen shows what the backend holds, and only what it holds."""

    def test_os_shows_the_name_with_its_accuracy(self) -> None:
        """The accuracy used to be lost whenever the name was present.

        The formatting moved from the screen onto the model, so the drawer,
        the table and the report all read the same text from one place.
        """
        host = ScanHostResult(ip_address="10.0.0.1", os_name="Ubuntu", os_accuracy=94)
        assert host.os_text == "Ubuntu (94%)"

    def test_os_without_an_accuracy_is_shown_plainly(self) -> None:
        """Nmap does not always report a confidence."""
        host = ScanHostResult(ip_address="10.0.0.1", os_name="Ubuntu")
        assert host.os_text == "Ubuntu"

    def test_an_unknown_os_never_renders_an_accuracy_onto_a_placeholder(self) -> None:
        """The old expression produced '- (94%)', which claimed nothing twice."""
        host = ScanHostResult(ip_address="10.0.0.1", os_accuracy=94)
        assert host.os_text == NOT_DETECTED

    def test_a_family_is_used_when_that_is_all_nmap_gave(self) -> None:
        """Real data, clearly labelled as the coarser answer it is."""
        host = ScanHostResult(ip_address="10.0.0.1", os_family="Linux")
        assert host.os_text == "Linux (family only)"

    def test_the_screen_reads_the_model_rather_than_reformatting_it(self) -> None:
        """One definition of the text, so the table and drawer cannot diverge."""
        source = inspect.getsource(VulnerabilitiesScreen)
        assert "host.os_text" in source
        assert "host.hostname_text" in source
        assert "_os_text" not in source

    def test_empty_scan_fields_fall_back_to_the_inventory(self) -> None:
        """A discovery sweep records no name; the inventory already has one."""
        mapped = ScanRepository._map_scan_host(
            {
                "id": 1, "scan_id": 1, "host_id": 4, "ip_address": "10.0.0.9",
                "hostname": "", "mac_address": "", "vendor": "", "status": "up",
                "os_name": "", "os_accuracy": None, "os_family": "",
                "known_hostname": "db01", "known_mac": "aa:bb:cc:dd:ee:ff",
                "known_vendor": "Dell", "known_os_name": "Debian",
                "known_os_accuracy": 96,
            }
        )
        assert mapped.hostname == "db01"
        assert mapped.mac_address == "aa:bb:cc:dd:ee:ff"
        assert mapped.vendor == "Dell"
        assert mapped.os_name == "Debian"
        assert mapped.os_accuracy == 96

    def test_what_the_scan_observed_always_wins(self) -> None:
        """A scan result is a record of that run; the inventory cannot edit it."""
        mapped = ScanRepository._map_scan_host(
            {
                "id": 1, "scan_id": 1, "host_id": 4, "ip_address": "10.0.0.9",
                "hostname": "scanned-name", "mac_address": "11:22:33:44:55:66",
                "vendor": "", "status": "up", "os_name": "Windows",
                "os_accuracy": 88, "os_family": "",
                "known_hostname": "stale-name", "known_mac": "aa:bb:cc:dd:ee:ff",
                "known_vendor": "", "known_os_name": "Debian",
                "known_os_accuracy": 96,
            }
        )
        assert mapped.hostname == "scanned-name"
        assert mapped.mac_address == "11:22:33:44:55:66"
        assert mapped.os_name == "Windows"
        assert mapped.os_accuracy == 88

    def test_nothing_is_filled_in_when_neither_source_knows(self) -> None:
        """A blank stays blank; the screen shows a dash, not a placeholder."""
        mapped = ScanRepository._map_scan_host(
            {
                "id": 1, "scan_id": 1, "host_id": None, "ip_address": "10.0.0.9",
                "hostname": "", "mac_address": "", "vendor": "", "status": "up",
                "os_name": "", "os_accuracy": None, "os_family": "",
                "known_hostname": None, "known_mac": None, "known_vendor": None,
                "known_os_name": None, "known_os_accuracy": None,
            }
        )
        assert mapped.hostname == ""
        assert mapped.os_name == ""
        assert mapped.os_accuracy is None

    def test_the_inventory_is_joined_in(self) -> None:
        """The fallback needs the host row, so the query has to fetch it."""
        source = inspect.getsource(ScanRepository.get_scan_with_results)
        assert "LEFT JOIN hosts h ON h.id = sh.host_id" in source
        assert "known_hostname" in source
        assert "known_os_name" in source


# ---------------------------------------------------------------------------
# 4. Scrolling
# ---------------------------------------------------------------------------
class TestScrollableFrame:
    """The container has to own its content and keep the wheel."""

    def test_the_content_is_a_child_of_the_canvas(self) -> None:
        """A canvas only clips and scrolls its own descendants."""
        source = inspect.getsource(cards_module.ScrollableFrame.__init__)
        assert "self.interior = ttk.Frame(self._canvas" in source

    def test_the_wheel_is_not_bound_application_wide(self) -> None:
        """``bind_all`` was shared with every other scroller on screen."""
        code = [
            line.split("#")[0]
            for line in inspect.getsource(cards_module.ScrollableFrame).splitlines()
            if not line.strip().startswith(("#", '"""', "*"))
        ]
        body = "\n".join(code)
        assert ".bind_all(" not in body
        assert ".unbind_all(" not in body

    def test_the_wheel_reaches_the_content_not_just_the_frame(self) -> None:
        """The content covers the frame, so the children carry the binding."""
        source = inspect.getsource(cards_module.ScrollableFrame._bind_wheel)
        assert "self._bind_wheel_to(self.interior)" in source
        configure = inspect.getsource(
            cards_module.ScrollableFrame._on_interior_configure
        )
        assert "_bind_wheel_to_descendants" in configure

    def test_nested_scrollables_keep_their_own_wheel(self) -> None:
        """A table inside a scrollable page must still scroll itself."""
        assert "Treeview" in cards_module._SELF_SCROLLING_CLASSES
        assert "Text" in cards_module._SELF_SCROLLING_CLASSES
        assert "Canvas" in cards_module._SELF_SCROLLING_CLASSES
        source = inspect.getsource(
            cards_module.ScrollableFrame._bind_wheel_to_descendants
        )
        assert "_SELF_SCROLLING_CLASSES" in source

    @pytest.mark.parametrize(
        "event, expected",
        [
            (_Wheel(num=4), -1),          # X11 wheel up
            (_Wheel(num=5), 1),           # X11 wheel down
            (_Wheel(delta=120), -1),      # one notch up
            (_Wheel(delta=-120), 1),      # one notch down
            (_Wheel(delta=360), -3),      # three notches at once
            (_Wheel(delta=-40), 1),       # a trackpad's partial notch
            (_Wheel(delta=40), -1),
            (_Wheel(), 0),                # not a wheel event
        ],
    )
    def test_wheel_arithmetic(self, event: _Wheel, expected: int) -> None:
        """Both wheel conventions, and a trackpad, move the view sensibly."""
        assert cards_module.ScrollableFrame._wheel_steps(event) == expected

    def test_an_unscrollable_frame_passes_the_wheel_on(self) -> None:
        """Short content must not swallow the wheel from an outer scroller."""
        source = inspect.getsource(cards_module.ScrollableFrame._on_wheel)
        assert "self._can_scroll()" in source
        assert "return None" in source


# ---------------------------------------------------------------------------
# 5. The row context menu
# ---------------------------------------------------------------------------
class TestRowContextMenu:
    """A posted menu keeps its grab, and acts on the row under the pointer."""

    def test_the_grab_is_kept_until_the_menu_is_dismissed(self) -> None:
        """Releasing it inline left the menu posted but not receiving clicks."""
        post = inspect.getsource(tables_module.DataTable._handle_context_menu)
        assert "tk_popup" in post
        assert "finally:\n            self._menu.grab_release()" not in post
        setup = inspect.getsource(tables_module.DataTable.__init__)
        assert 'self._menu.bind("<Unmap>", self._release_menu_grab' in setup

    def test_right_clicking_selects_the_row_under_the_pointer(self) -> None:
        """Otherwise an action runs against whatever was selected before."""
        source = inspect.getsource(tables_module.DataTable._handle_context_menu)
        assert "identify_row(event.y)" in source
        assert "self.tree.selection_set(row_id)" in source

    def test_each_command_is_bound_to_that_row(self) -> None:
        """The row travels with the command rather than being looked up later."""
        source = inspect.getsource(tables_module.DataTable._handle_context_menu)
        assert "data=row: run(data)" in source


# ---------------------------------------------------------------------------
# 6. Host inventory selection
# ---------------------------------------------------------------------------
class TestHostSelection:
    """Opening a host from another screen must land on that host."""

    def test_focus_pairs_visible_rows_with_visible_data(self) -> None:
        """Sorted or filtered, the row and its data have to stay together."""
        source = inspect.getsource(hosts_screen.HostsScreen._apply_focus)
        assert "rows(visible_only=True)" in source

    def test_the_detail_pane_reports_every_field(self) -> None:
        """The identity tab is where a host's own detail is read."""
        source = inspect.getsource(hosts_screen.HostsScreen._render_detail)
        for label in (
            "IP address", "Hostname", "MAC address", "Operating system",
            "Status", "Risk level", "OPEN PORTS", "FINDINGS",
        ):
            assert label in source

    def test_the_inventory_table_lists_every_field(self) -> None:
        """The same facts are on the row, so a host can be scanned for."""
        keys = [column.key for column in hosts_screen.HOST_COLUMNS]
        for key in ("ip", "hostname", "mac", "os", "risk", "ports"):
            assert key in keys


class TestOsText:
    """The inventory's own OS rendering, which the fix now matches."""

    def test_accuracy_is_included(self) -> None:
        """Nmap fingerprints an OS; how sure it was belongs with the answer."""
        host = Host(id=1, ip_address="10.0.0.1", os_name="Debian", os_accuracy=91)
        assert host.os_text == "Debian (91%)"

    def test_unknown_says_no_scan_has_run(self) -> None:
        """No OS scan has run, and the screen now says exactly that.

        It used to render a dash, which is indistinguishable from any other
        kind of missing and left an operator with nothing to act on. Capture
        cannot fingerprint an OS; only an assessment can, so the cell names
        the thing that would fill it.
        """
        assert Host(id=1, ip_address="10.0.0.1").os_text == "not scanned"


# ---------------------------------------------------------------------------
# Database-backed: the read/unread counter against the real schema
# ---------------------------------------------------------------------------
class TestReadStateAgainstTheSchema:
    """The counter queries have to run on the schema the migrations build."""

    def test_marking_and_counting(self, clean_db) -> None:
        """An open incident counts as unread until it is opened, then never."""
        from aethra_sec.utils.timeutil import to_db, utcnow

        repository = IncidentRepository(clean_db)
        now = to_db(utcnow())
        for reference, status in (
            ("INC-T001", "NEW"),
            ("INC-T002", "INVESTIGATING"),
            ("INC-T003", "RESOLVED"),
        ):
            clean_db.execute(
                "INSERT INTO incidents (reference, title, category, severity, "
                "confidence, status, correlation_key, first_seen, last_seen, "
                "created_at, updated_at) "
                "VALUES (%s, %s, 'PORT_SCAN', 'MEDIUM', 50, %s, %s, %s, %s, %s, %s)",
                (reference, f"test {reference}", status, reference, now, now, now, now),
            )

        assert repository.count_open() == 2
        assert repository.count_unread() == 2

        first = clean_db.query_value(
            "SELECT id FROM incidents WHERE reference = 'INC-T001'", default=0
        )
        assert repository.mark_viewed(int(first), None) is True
        assert repository.count_unread() == 1
        assert repository.count_open() == 2, "reading is not triaging"

        # Reading it again changes nothing and reports that it changed nothing.
        assert repository.mark_viewed(int(first), None) is False
        assert repository.count_unread() == 1

        incident = repository.get(int(first))
        assert incident is not None
        assert isinstance(incident.viewed_at, datetime)
