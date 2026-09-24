"""Seeing the open ports a scan found, not just how many there were.

The results page reported "1 host(s) up, 6 open port(s), 6 finding(s)" and
that was all an operator could read. The ports were in the database and in the
table object - `set_rows` had put six rows there - but the panel holding it was
clipped to a sliver of header below the fold.

The cause was layout, not data. The hosts card and the ports/findings row were
both packed with ``expand=True``, and both asked for more height than the
window had. Pack resolves that by shrinking whatever it placed last, so the
ports panel lost every pixel of its body while the count above it stayed
perfectly readable. Nothing in the pipeline was broken, which is why the count
was right.

What is pinned here:

* the panes are split with weights and a sash rather than stacked packs, so
  neither panel can be squeezed to nothing again;
* the ports table carries the columns an operator asked for - port, protocol,
  state, service, version, risk and the finding;
* the risk beside a port is the risk the engine assigned to *that* port, and
  where several findings share a port the most serious one is shown;
* a port with no finding says so rather than borrowing a neighbour's;
* the summary names the open ports as well as counting them;
* nothing is invented: no finding, no risk and no version is displayed that
  the scan did not produce.
"""

from __future__ import annotations

import inspect

import pytest

from aethra_sec.models.enums import HostStatus, RiskLevel, ScanStatus
from aethra_sec.models.scan import PortResult, Scan, ScanFinding, ScanHostResult
from aethra_sec.ui.screens.vulnerabilities import (
    PORT_COLUMNS,
    VulnerabilitiesScreen,
)


def _port(number: int, **kwargs: object) -> PortResult:
    """One port as Nmap would have reported it."""
    defaults = {"protocol": "tcp", "state": "open", "service": "http"}
    defaults.update(kwargs)
    return PortResult(port=number, **defaults)  # type: ignore[arg-type]


def _finding(port: int | None, risk: RiskLevel, title: str) -> ScanFinding:
    """One finding the risk engine derived from a port."""
    return ScanFinding(
        port=port, protocol="tcp", service="http", title=title, risk_level=risk
    )


def _host(**kwargs: object) -> ScanHostResult:
    """A scanned host with ports and findings."""
    host = ScanHostResult(ip_address="192.168.1.14", status=HostStatus.UP)
    for key, value in kwargs.items():
        setattr(host, key, value)
    return host


# ---------------------------------------------------------------------------
# The columns the operator asked for
# ---------------------------------------------------------------------------
def test_the_ports_table_has_every_column_that_was_asked_for() -> None:
    """Port, protocol, state, service, version, risk and finding."""
    keys = {column.key for column in PORT_COLUMNS}
    assert {"port", "protocol", "state", "service", "version", "risk", "finding"} <= keys


def test_risk_and_state_are_colour_coded() -> None:
    """A severity read as plain text is a severity nobody scans for."""
    by_key = {column.key: column for column in PORT_COLUMNS}
    assert by_key["risk"].colour_by == "severity"
    assert by_key["state"].colour_by == "state"


# ---------------------------------------------------------------------------
# Joining ports to the findings derived from them
# ---------------------------------------------------------------------------
def test_a_port_is_joined_to_its_own_finding() -> None:
    """The risk beside 445 has to be the risk raised for 445."""
    host = _host(
        ports=[_port(445), _port(80)],
        findings=[
            _finding(445, RiskLevel.HIGH, "smb exposed on 445/tcp"),
            _finding(80, RiskLevel.LOW, "http exposed on 80/tcp"),
        ],
    )
    index = VulnerabilitiesScreen._findings_by_port(host)
    assert index[(445, "tcp")].title == "smb exposed on 445/tcp"
    assert index[(80, "tcp")].title == "http exposed on 80/tcp"


def test_the_most_serious_finding_wins_a_shared_port() -> None:
    """That is the one deciding whether the port needs attention."""
    host = _host(
        ports=[_port(445)],
        findings=[
            _finding(445, RiskLevel.LOW, "a minor note"),
            _finding(445, RiskLevel.CRITICAL, "the one that matters"),
            _finding(445, RiskLevel.MEDIUM, "something in between"),
        ],
    )
    index = VulnerabilitiesScreen._findings_by_port(host)
    assert index[(445, "tcp")].title == "the one that matters"


def test_a_host_wide_finding_is_not_pinned_to_a_port() -> None:
    """Findings with no port ("several unencrypted services") belong to none."""
    host = _host(
        ports=[_port(80)],
        findings=[_finding(None, RiskLevel.MEDIUM, "Multiple unencrypted services")],
    )
    assert VulnerabilitiesScreen._findings_by_port(host) == {}


def test_a_port_without_a_finding_says_so() -> None:
    """It must not borrow the risk of a port that has one."""
    index = VulnerabilitiesScreen._findings_by_port(
        _host(ports=[_port(80), _port(8080)], findings=[_finding(80, RiskLevel.LOW, "x")])
    )
    quiet = _port(8080)
    assert VulnerabilitiesScreen._port_risk_text(index, quiet) == ""
    assert VulnerabilitiesScreen._port_finding_text(index, quiet) == "no finding raised"


def test_a_closed_port_claims_nothing_at_all() -> None:
    """A closed port is not a gap in the display; it is a result."""
    closed = _port(23, state="closed")
    assert VulnerabilitiesScreen._port_finding_text({}, closed) == ""
    assert VulnerabilitiesScreen._version_text(closed) == "-"


# ---------------------------------------------------------------------------
# Version text
# ---------------------------------------------------------------------------
def test_product_and_version_are_shown_together() -> None:
    """What Nmap reported, as it reported it."""
    assert (
        VulnerabilitiesScreen._version_text(
            _port(22, service="ssh", product="OpenSSH", version="8.9p1")
        )
        == "OpenSSH 8.9p1"
    )


def test_an_open_port_with_no_banner_says_which_it_is() -> None:
    """No version detected is a different statement from no port."""
    assert (
        VulnerabilitiesScreen._version_text(_port(4444))
        == "no version detected"
    )


# ---------------------------------------------------------------------------
# The summary names the ports, not only their number
# ---------------------------------------------------------------------------
def test_the_summary_names_the_open_ports() -> None:
    """"6 open port(s)" does not answer which six."""
    scan = Scan(
        id=1, target="192.168.1.14", status=ScanStatus.COMPLETED,
        hosts_up=1, open_ports=3, findings_count=3,
        hosts=[
            _host(
                ports=[
                    _port(445, service="microsoft-ds"),
                    _port(80, service="http"),
                    _port(22, service="ssh"),
                ]
            )
        ],
    )
    line = scan.open_ports_line
    assert "192.168.1.14:" in line
    for expected in ("22/tcp (ssh)", "80/tcp (http)", "445/tcp (microsoft-ds)"):
        assert expected in line
    # Ordered, so the same scan reads the same way twice.
    assert line.index("22/tcp") < line.index("80/tcp") < line.index("445/tcp")


def test_closed_ports_are_not_named_as_open() -> None:
    """The line is about open ports and must contain only open ports."""
    scan = Scan(
        id=1, status=ScanStatus.COMPLETED,
        hosts=[_host(ports=[_port(80), _port(23, state="closed")])],
    )
    assert "80/tcp" in scan.open_ports_line
    assert "23/tcp" not in scan.open_ports_line


def test_a_long_list_is_capped_and_says_how_many_it_hid() -> None:
    """A /24 of web servers must not push the summary off the card."""
    scan = Scan(
        id=1, status=ScanStatus.COMPLETED,
        hosts=[_host(ports=[_port(n) for n in range(1000, 1040)])],
    )
    line = scan.open_ports_line
    assert f"and {40 - Scan.OPEN_PORT_PREVIEW} more" in line


def test_nothing_open_names_nothing() -> None:
    """An empty line beats the word "none" beside a zero already on screen."""
    assert Scan(id=1, status=ScanStatus.COMPLETED, hosts=[]).open_ports_line == ""
    assert (
        Scan(
            id=1, status=ScanStatus.COMPLETED,
            hosts=[_host(ports=[_port(23, state="closed")])],
        ).open_ports_line
        == ""
    )


# ---------------------------------------------------------------------------
# The layout that caused this
# ---------------------------------------------------------------------------
def test_the_result_panes_are_split_not_stacked() -> None:
    """Two expanding packs let the last one be clipped to nothing.

    This is the actual defect: the ports were always in the table, and the
    panel showing them had no height. A split with weights divides the space
    explicitly instead of leaving it to what pack does when it runs out.
    """
    source = inspect.getsource(VulnerabilitiesScreen._build_results)
    assert "PanedWindow" in source
    assert "weight=" in source
    # The ports panel must get the larger share of the lower row.
    assert VulnerabilitiesScreen.PORTS_PANE_SHARE > 0.5


def test_the_ports_panel_fills_itself_without_being_asked() -> None:
    """A one-host scan should show that host's ports the moment it loads."""
    source = inspect.getsource(VulnerabilitiesScreen._apply_scan)
    assert "_refresh_ports()" in source
    assert "_ports_host" in source


def test_selecting_a_host_and_the_row_action_both_reach_the_ports() -> None:
    """Click to expand, or use the explicit action - the user asked for both."""
    source = inspect.getsource(VulnerabilitiesScreen._build_results)
    assert "on_select=self._show_host_ports" in source
    assert "View open ports" in source


@pytest.mark.parametrize(
    "method",
    ["_refresh_ports", "_show_host_ports", "_focus_host_ports", "_show_port_detail"],
)
def test_the_ports_panel_has_its_interactions(method: str) -> None:
    """Select, filter, focus and open in the drawer."""
    assert callable(getattr(VulnerabilitiesScreen, method))
