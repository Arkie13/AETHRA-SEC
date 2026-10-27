"""The display side of live capture: recent real packets and the display filter.

Where it sits::

    TShark -> FieldCaptureReader -> queue -> capture worker -> analysis, rules, storage
                                                   |
                                                   +-> PacketView.ingest()   (hand-off only)
                                                             |
                                                     packet-view thread
                                                       - direction, from the interface's addresses
                                                       - a bounded window of recent packets
                                                       - the active display filter
                                                       - DISPLAY_VIEW_RESET / DISPLAY_VIEW_BATCH
                                                             |
                                                     Live Monitoring table

Why it is its own thread, owned by the capture service rather than the screen:

* **Changing the display filter must not touch capture.** Applying a filter
  swaps one reference and asks this thread to re-evaluate the packets it
  retains. The reader, the worker, detection and storage never see it.
* **Filtering must not run on the Tk thread.** Re-evaluating twenty thousand
  retained packets takes this thread a few tens of milliseconds; on the
  interface thread that would be a visible freeze on every click.
* **Counts must not depend on which screen is open.** Events reach only the
  screen currently shown, so a view owned by the screen would stop counting
  whenever the analyst looked at something else.

Everything is bounded: the hand-off queue, the retained window and what one
publish carries to the table. Whatever a bound sheds is counted and reported.

Nothing here creates a packet. Every packet counted, filtered or published is
one the capture pipeline decoded from TShark's output.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from aethra_sec.analytics.display_filter import (
    MATCH_ALL,
    STATISTIC_PROTOCOLS,
    CompiledFilter,
    protocol_present,
)
from aethra_sec.analytics.traffic_direction import (
    DIRECTION_ORDER,
    Direction,
    LocalAddresses,
    classify,
    resolve_local_addresses,
)
from aethra_sec.analytics.peer_visibility import (
    PeerVisibilityTracker,
)
from aethra_sec.core.events import DisplayViewPayload, EventType
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("services.packet_view")

#: Recent packets kept so a new display filter can be applied to traffic that
#: has already arrived. Twenty thousand is a few minutes of an ordinary LAN and
#: a few seconds of a flood; the statistics say which of those it was.
RETAINED_PACKETS = 20_000

#: Most matching packets one publish carries to the table. The table itself
#: holds 2,000 rows, so carrying more would only be discarded there.
TABLE_PACKETS = 2_000

#: Packets waiting to be taken in by the view thread.
INGEST_CAPACITY = 50_000

#: How often matches and counts are published.
PUBLISH_INTERVAL_SECONDS = 0.25

#: How often the capture interface's addresses are re-read, so a DHCP renewal
#: mid-capture does not leave direction judged against a stale address.
ADDRESS_REFRESH_SECONDS = 30.0


@dataclass(frozen=True)
class ViewStatistics:
    """What the view has seen and what the active filter matched.

    Attributes:
        generation: filter generation these counts belong to.
        expression: the display filter being applied ("" for all traffic).
        interface: capture interface of the current session.
        session_packets: packets the view took in this session.
        retained: packets currently kept for re-filtering.
        retained_capacity: the most it keeps.
        evaluated: packets the current filter has been evaluated against.
        matched: packets that satisfied it.
        not_listed: matching packets beyond what the table can hold.
        ingest_dropped: packets the view could not take in (hand-off full).
        directions: session-wide count per direction.
        matched_protocols: per protocol, among matching packets.
        matched_directions: per direction, among matching packets.
        local_resolved: whether the interface's addresses are known.
        local_description: those addresses, or why they are not known.
        local_addresses: the addresses themselves, so a screen can tell a
            search for this machine from a search for another device.
    """

    generation: int = 0
    expression: str = ""
    interface: str = ""
    session_packets: int = 0
    retained: int = 0
    retained_capacity: int = RETAINED_PACKETS
    evaluated: int = 0
    matched: int = 0
    not_listed: int = 0
    ingest_dropped: int = 0
    directions: dict[str, int] = field(default_factory=dict)
    matched_protocols: dict[str, int] = field(default_factory=dict)
    matched_directions: dict[str, int] = field(default_factory=dict)
    local_resolved: bool = False
    local_description: str = ""
    local_addresses: frozenset[str] = frozenset()

    @property
    def window_limited(self) -> bool:
        """True when the filter could not be evaluated over the whole session.

        Happens when the filter was applied after more packets had arrived
        than the view retains. The count is then "matching among the packets
        evaluated", and the interface says so rather than implying a total.
        """
        return self.evaluated < self.session_packets

    def direction(self, direction: Direction | str) -> int:
        """Session-wide count for one direction."""
        return int(self.directions.get(str(direction), 0))


def _zeroed_directions() -> dict[str, int]:
    return {direction.value: 0 for direction in DIRECTION_ORDER}


def _zeroed_protocols() -> dict[str, int]:
    return {name: 0 for name, _layers in STATISTIC_PROTOCOLS}


class PacketView:
    """Holds recent captured packets and applies the display filter to them."""

    def __init__(
        self,
        publish: Callable[[str, Any], None] | None = None,
        *,
        retained: int = RETAINED_PACKETS,
        table_packets: int = TABLE_PACKETS,
        ingest_capacity: int = INGEST_CAPACITY,
        publish_interval: float = PUBLISH_INTERVAL_SECONDS,
        resolver: Callable[[str], LocalAddresses] = resolve_local_addresses,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create an idle view. No thread runs until :meth:`start`.

        Args:
            publish: ``(event_type, payload)`` sink, normally ``EventBus.publish``.
            retained: packets kept for re-filtering.
            table_packets: most matching packets carried to the table at once.
            ingest_capacity: most packets waiting for the view thread.
            publish_interval: seconds between publishes.
            resolver: finds the capture interface's addresses.
            clock: monotonic clock, injectable for tests.
        """
        self._publish_sink = publish or (lambda _type, _payload: None)
        self._retained: deque[Any] = deque(maxlen=max(1, retained))
        self._retained_lock = threading.Lock()
        self._table_packets = max(1, table_packets)
        self._ingest: deque[Any] = deque()
        self._ingest_capacity = max(1, ingest_capacity)
        self._interval = max(0.05, publish_interval)
        self._resolver = resolver
        self._clock = clock

        # Shared with producer threads; guarded by _lock.
        self._lock = threading.Lock()
        self._filter: CompiledFilter = MATCH_ALL
        self._generation = 0
        self._rescan_requested = False
        self._clear_requested = False
        self._resolve_requested = False
        self._interface = ""
        self._ingest_dropped = 0

        # Owned by the view thread (or by whoever drives step() in a test).
        self._local = LocalAddresses()
        #: Counts, from real captured frames, whose traffic is arriving.
        #: Answers "can this capture point see other devices?" from
        #: packets rather than from the host inventory, which records
        #: that a host was seen once, not that it is visible now.
        self.visibility = PeerVisibilityTracker()
        self._last_resolved = 0.0
        self._session_packets = 0
        self._directions = _zeroed_directions()
        self._evaluated = 0
        self._matched = 0
        self._not_listed = 0
        self._matched_protocols = _zeroed_protocols()
        self._matched_directions = _zeroed_directions()
        self._pending: deque[Any] = deque(maxlen=self._table_packets)
        self._active_generation = 0
        self._active_expression = ""
        self._last_publish = 0.0
        self._changed = False

        self._statistics = ViewStatistics()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Producer side - any thread
    # ------------------------------------------------------------------
    def ingest(self, packets: Iterable[Any]) -> None:
        """Hand captured packets to the view. Never blocks, never raises.

        Called by the capture worker. Over capacity the packets are counted as
        dropped *from the view* - they have still been analysed and stored.
        """
        with self._lock:
            for packet in packets:
                if len(self._ingest) >= self._ingest_capacity:
                    self._ingest_dropped += 1
                    continue
                self._ingest.append(packet)

    def begin_session(self, interface: str) -> int:
        """Start a new capture session on ``interface``.

        Retained packets and session counts belong to the previous capture, so
        they are discarded. The display filter is kept: an analyst who
        restarts capture expects the view they had.

        Returns:
            The new generation; the table clears when it is published.
        """
        with self._lock:
            self._interface = (interface or "").strip()
            self._ingest.clear()
            self._clear_requested = True
            self._resolve_requested = True
            self._generation += 1
            self._rescan_requested = True
            generation = self._generation
        self._wake.set()
        return generation

    def apply_filter(self, compiled: CompiledFilter) -> int:
        """Make ``compiled`` the active display filter.

        Only swaps the reference and asks the view thread to re-evaluate what it
        retains. Nothing about capture changes.

        Returns:
            The generation whose RESET will carry the re-filtered packets.
        """
        with self._lock:
            self._filter = compiled
            self._generation += 1
            self._rescan_requested = True
            generation = self._generation
        self._wake.set()
        return generation

    def refresh(self) -> int:
        """Re-publish the current matches under a new generation."""
        with self._lock:
            self._generation += 1
            self._rescan_requested = True
            generation = self._generation
        self._wake.set()
        return generation

    @property
    def active_filter(self) -> CompiledFilter:
        """The filter currently applied."""
        with self._lock:
            return self._filter

    @property
    def generation(self) -> int:
        """The latest generation requested."""
        with self._lock:
            return self._generation

    def statistics(self) -> ViewStatistics:
        """The most recent counts. A consistent snapshot, safe from any thread."""
        return self._statistics

    def retained_snapshot(self) -> list[Any]:
        """A copy of the retained packets, oldest first."""
        with self._retained_lock:
            return list(self._retained)

    # ------------------------------------------------------------------
    # Thread
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start the view thread. A second call while it runs does nothing."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run, name="packet-view", daemon=True
            )
            self._thread.start()
        LOGGER.info("Packet view started.")

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the view thread and wait for it."""
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None

    @property
    def is_running(self) -> bool:
        """True while the view thread is alive."""
        thread = self._thread
        return bool(thread and thread.is_alive())

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self._interval)
            self._wake.clear()
            if self._stop.is_set():
                break
            try:
                self.step()
            except Exception:  # noqa: BLE001 - one bad pass must not end the view
                LOGGER.exception("Packet view pass failed.")

    # ------------------------------------------------------------------
    # One pass - the view thread
    # ------------------------------------------------------------------
    def step(self) -> None:
        """Take in waiting packets, apply the filter, publish what changed.

        Public so a test can drive the view deterministically without a
        thread. Flags, the waiting packets and the filter are taken together
        under the lock, so every packet in a pass is classified against the
        session and judged against the filter that were current when it was
        taken.
        """
        with self._lock:
            clear = self._clear_requested
            resolve = self._resolve_requested
            self._clear_requested = False
            self._resolve_requested = False
            interface = self._interface
            batch = list(self._ingest)
            self._ingest.clear()
            rescan = self._rescan_requested
            self._rescan_requested = False
            active = self._filter
            generation = self._generation
            ingest_dropped = self._ingest_dropped

        now = self._clock()
        if clear:
            with self._retained_lock:
                self._retained.clear()
            self._session_packets = 0
            self._directions = _zeroed_directions()
            self._changed = True

        if resolve or (
            interface and now - self._last_resolved >= ADDRESS_REFRESH_SECONDS
        ):
            self._local = self._resolve(interface)
            self._last_resolved = self._clock()
            self._changed = True

        if rescan:
            self._active_generation = generation
            self._active_expression = active.expression
            self._evaluated = 0
            self._matched = 0
            self._not_listed = 0
            self._matched_protocols = _zeroed_protocols()
            self._matched_directions = _zeroed_directions()
            self._pending.clear()
            for packet in self.retained_snapshot():
                self._consider(packet, active)
            packets = tuple(self._pending)
            self._pending.clear()
            self._publish(EventType.DISPLAY_VIEW_RESET, packets, ingest_dropped, reset=True)

        if batch:
            local = self._local
            with self._retained_lock:
                for packet in batch:
                    # Count whose traffic is arriving while we already have the
                    # packet and the resolved local addresses in hand. Done
                    # here so the visibility figures and the direction column
                    # can never disagree about what "this host" means.
                    self.visibility.observe(packet, local)
                    direction = classify(packet, local).value
                    try:
                        packet.direction = direction
                    except AttributeError:  # pragma: no cover - a foreign object
                        pass
                    self._retained.append(packet)
            for packet in batch:
                self._session_packets += 1
                key = getattr(packet, "direction", "") or Direction.UNKNOWN.value
                self._directions[key] = self._directions.get(key, 0) + 1
                self._consider(packet, active)
            self._changed = True

        due = self._clock() - self._last_publish >= self._interval
        if due and (self._pending or self._changed):
            packets = tuple(self._pending)
            self._pending.clear()
            self._publish(EventType.DISPLAY_VIEW_BATCH, packets, ingest_dropped, reset=False)
        else:
            self._statistics = self._snapshot(ingest_dropped)

    def _consider(self, packet: Any, active: CompiledFilter) -> None:
        """Evaluate one packet against the active filter and count the result."""
        self._evaluated += 1
        if not active.matches(packet):
            return
        self._matched += 1
        for name, protocols in STATISTIC_PROTOCOLS:
            if any(protocol_present(packet, protocol) for protocol in protocols):
                self._matched_protocols[name] += 1
        key = getattr(packet, "direction", "") or Direction.UNKNOWN.value
        self._matched_directions[key] = self._matched_directions.get(key, 0) + 1
        if len(self._pending) == self._pending.maxlen:
            self._not_listed += 1
        self._pending.append(packet)

    def _resolve(self, interface: str) -> LocalAddresses:
        """Read the interface's addresses; an error yields an unresolved result."""
        if not interface:
            return LocalAddresses(detail="No capture interface is selected.")
        try:
            return self._resolver(interface)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Could not resolve addresses for %r: %s", interface, exc)
            return LocalAddresses(
                interface=interface,
                detail=f"The capture interface's addresses could not be read: {exc}",
            )

    def _snapshot(self, ingest_dropped: int) -> ViewStatistics:
        with self._retained_lock:
            retained = len(self._retained)
            capacity = self._retained.maxlen or retained
        return ViewStatistics(
            generation=self._active_generation,
            expression=self._active_expression,
            interface=self._interface,
            session_packets=self._session_packets,
            retained=retained,
            retained_capacity=capacity,
            evaluated=self._evaluated,
            matched=self._matched,
            not_listed=self._not_listed,
            ingest_dropped=ingest_dropped,
            directions=dict(self._directions),
            matched_protocols=dict(self._matched_protocols),
            matched_directions=dict(self._matched_directions),
            local_resolved=self._local.resolved,
            local_description=self._local.describe(),
            local_addresses=self._local.addresses,
        )

    def _publish(
        self, event_type: str, packets: tuple[Any, ...], ingest_dropped: int, *, reset: bool
    ) -> None:
        statistics = self._snapshot(ingest_dropped)
        self._statistics = statistics
        self._last_publish = self._clock()
        self._changed = False
        try:
            self._publish_sink(
                event_type,
                DisplayViewPayload(
                    generation=statistics.generation,
                    packets=packets,
                    statistics=statistics,
                    reset=reset,
                ),
            )
        except Exception:  # noqa: BLE001 - the view must outlive a bad subscriber
            LOGGER.exception("Could not publish the packet view.")
