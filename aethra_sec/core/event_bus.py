"""Thread-safe publish/subscribe bus with bounded, per-subscriber queues.

Design constraints that shaped this implementation:

* **Producers must never block.** A packet-processing worker publishing at a
  few thousand events per second cannot wait for the Tk thread. Each
  subscription therefore owns a bounded queue; when it is full the oldest event
  is discarded and a per-subscription drop counter is incremented, which the
  System Health screen displays honestly rather than hiding.
* **Tk widgets must only be touched on the Tk thread.** Subscribers registered
  in ``queued`` mode never run a callback on the producer's thread; the UI
  drains their queues from a ``root.after()`` tick.
* **A failing subscriber must not break the pipeline.** Callback exceptions are
  logged and counted, never propagated to the producer.
"""

from __future__ import annotations

import itertools
import threading
import time
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Iterable

from aethra_sec.core.events import Event
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("core.event_bus")

EventCallback = Callable[[Event], None]

DEFAULT_QUEUE_SIZE = 2000


#: Seconds between drop reports for one subscription. A full buffer
#: discards an event per publish, so without this the warning about a
#: flood would itself become one.
DROP_LOG_INTERVAL_SECONDS = 30.0

@dataclass
class Subscription:
    """One subscriber's registration.

    Attributes:
        id: monotonic identifier used to unsubscribe.
        event_types: the events this subscription receives.
        callback: invoked immediately on the publishing thread when ``queued``
            is false; ``None`` for pure queue consumers.
        queued: when true, events are buffered for later draining instead of
            being dispatched inline.
        queue: bounded buffer of pending events (newest last).
        dropped: number of events discarded because the buffer was full.
        errors: number of callback exceptions swallowed.
    """

    id: int
    event_types: frozenset[str]
    callback: EventCallback | None
    queued: bool
    max_size: int
    queue: Deque[Event] = field(default_factory=deque)
    dropped: int = 0
    errors: int = 0
    name: str = ""


class EventBus:
    """In-process event bus shared by every AETHRA-SEC subsystem."""

    def __init__(self, default_queue_size: int = DEFAULT_QUEUE_SIZE) -> None:
        """Create an empty bus.

        Args:
            default_queue_size: per-subscription buffer size for queued
                subscribers.
        """
        self._lock = threading.RLock()
        self._subscriptions: dict[int, Subscription] = {}
        #: Last drop warning per subscription, so one overflowing
        #: buffer cannot fill the log with its own failure.
        self._last_drop_log: dict[int, float] = {}
        self._by_type: dict[str, set[int]] = {}
        self._ids = itertools.count(1)
        self._default_queue_size = max(16, default_queue_size)
        self._published = 0

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------
    def subscribe(
        self,
        event_types: str | Iterable[str],
        callback: EventCallback | None = None,
        *,
        queued: bool = True,
        max_size: int | None = None,
        name: str = "",
    ) -> int:
        """Register a subscriber.

        Args:
            event_types: a single event name or an iterable of names.
            callback: invoked with each :class:`Event`. Required when
                ``queued`` is false.
            queued: buffer events instead of dispatching inline. UI subscribers
                must use ``True`` so widgets are only touched on the Tk thread.
            max_size: override the per-subscription buffer size.
            name: label shown in diagnostics.

        Returns:
            A subscription id for :meth:`unsubscribe` and :meth:`drain`.

        Raises:
            ValueError: when an inline subscription has no callback.
        """
        if isinstance(event_types, str):
            types = frozenset({event_types})
        else:
            types = frozenset(event_types)
        if not types:
            raise ValueError("At least one event type is required.")
        if not queued and callback is None:
            raise ValueError("An inline subscription requires a callback.")

        with self._lock:
            sub_id = next(self._ids)
            subscription = Subscription(
                id=sub_id,
                event_types=types,
                callback=callback,
                queued=queued,
                max_size=max_size or self._default_queue_size,
                name=name or f"subscription-{sub_id}",
            )
            self._subscriptions[sub_id] = subscription
            for event_type in types:
                self._by_type.setdefault(event_type, set()).add(sub_id)
        return sub_id

    def unsubscribe(self, subscription_id: int) -> None:
        """Remove a subscription; unknown ids are ignored."""
        with self._lock:
            subscription = self._subscriptions.pop(subscription_id, None)
            if not subscription:
                return
            for event_type in subscription.event_types:
                holders = self._by_type.get(event_type)
                if holders:
                    holders.discard(subscription_id)
                    if not holders:
                        self._by_type.pop(event_type, None)

    def clear(self) -> None:
        """Remove every subscription (used during shutdown)."""
        with self._lock:
            self._subscriptions.clear()
            self._by_type.clear()

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------
    def publish(self, event_type: str, payload: object = None) -> None:
        """Publish an event. Never raises and never blocks the caller."""
        event = Event(type=event_type, payload=payload)
        with self._lock:
            self._published += 1
            subscriber_ids = list(self._by_type.get(event_type, ()))
            targets = [
                self._subscriptions[sid]
                for sid in subscriber_ids
                if sid in self._subscriptions
            ]
            inline: list[Subscription] = []
            # Collected under the lock, logged outside it: a full buffer is
            # exactly when nothing should be held up writing to a log.
            dropped_now: list[tuple[Subscription, Event]] = []
            for subscription in targets:
                if subscription.queued:
                    if len(subscription.queue) >= subscription.max_size:
                        lost = subscription.queue.popleft()
                        subscription.dropped += 1
                        dropped_now.append((subscription, lost))
                    subscription.queue.append(event)
                else:
                    inline.append(subscription)

        for subscription, lost in dropped_now:
            self._report_drop(subscription, lost)

        # Inline callbacks run outside the lock so a slow subscriber cannot
        # stall publishers on other threads.
        for subscription in inline:
            self._invoke(subscription, event)

    def _invoke(self, subscription: Subscription, event: Event) -> None:
        """Run a subscriber callback, converting failures into log entries."""
        callback = subscription.callback
        if callback is None:
            return
        try:
            callback(event)
        except Exception:  # noqa: BLE001 - a subscriber must never break the bus
            subscription.errors += 1
            LOGGER.exception(
                "Event subscriber '%s' failed handling %s",
                subscription.name,
                event.type,
            )

    # ------------------------------------------------------------------
    # Consumption
    # ------------------------------------------------------------------
    def drain(self, subscription_id: int, limit: int = 500) -> list[Event]:
        """Remove and return up to ``limit`` buffered events.

        Called from the Tk thread; returns an empty list for unknown ids so a
        screen that has already been destroyed cannot raise during teardown.
        """
        with self._lock:
            subscription = self._subscriptions.get(subscription_id)
            if not subscription:
                return []
            count = min(limit, len(subscription.queue))
            return [subscription.queue.popleft() for _ in range(count)]

    def dispatch(self, subscription_id: int, limit: int = 500) -> int:
        """Drain a queued subscription and invoke its callback per event.

        Returns:
            The number of events dispatched.
        """
        events = self.drain(subscription_id, limit)
        if not events:
            return 0
        with self._lock:
            subscription = self._subscriptions.get(subscription_id)
        if subscription is None:
            return 0
        for event in events:
            self._invoke(subscription, event)
        return len(events)

    #: Events taken from one subscription before the clock is consulted again.
    #:
    #: Small, because the budget below can only be honoured between chunks: a
    #: single chunk always runs to completion, so this bounds how far past the
    #: deadline a dispatch can go.
    DISPATCH_CHUNK = 16

    def _report_drop(self, subscription: "Subscription", lost: Event) -> None:
        """Say that a buffer overflowed, without flooding the log itself.

        A full buffer discards one event per publish, so logging every drop
        would produce thousands of identical lines during the very burst that
        caused it. One line per subscription per interval carries what
        matters: which subscriber is behind, what kind of event was lost, and
        how many have gone in total.
        """
        now = time.monotonic()
        last = self._last_drop_log.get(subscription.id, 0.0)
        if now - last < DROP_LOG_INTERVAL_SECONDS:
            return
        self._last_drop_log[subscription.id] = now
        LOGGER.warning(
            "Event buffer full for subscription '%s' (%d slots): discarded a "
            "'%s' event; %d dropped in total. The subscriber is not keeping "
            "up and events are being lost.",
            subscription.name or subscription.id, subscription.max_size,
            getattr(lost, "type", "?"), subscription.dropped,
        )

    def dispatch_all(
        self,
        limit_per_subscription: int = 500,
        *,
        time_budget_ms: float = 0.0,
    ) -> int:
        """Dispatch every queued subscription that owns a callback.

        This is the single call the main window makes on each UI tick, and it
        runs on the Tk thread, so how long it may take is a property of the
        interface rather than of the bus.

        A count limit alone could not bound that. Measured during a real
        full-port Nmap scan of one host, with the capture pipeline raising
        ``capture.packet_batch`` at roughly 230 events a second, this call took
        **777 ms on average and 2,007 ms at worst** - 96% of the whole UI tick
        (24.09 s of 25.09 s) - and the interface stalled 69 times in 220
        seconds. The per-event cost was not the problem: it averaged 0.063 ms.
        Some individual events cost 215 ms, so any fixed count can still add up
        to seconds.

        ``time_budget_ms`` bounds it in wall-clock terms instead. Subscriptions
        are served round-robin in small chunks and the clock is checked between
        them, so one noisy subscription cannot starve the others and the Tk
        thread is handed back on time.

        Nothing is discarded here: an event not reached stays in its
        subscription's queue and is dispatched on the next tick. Events are
        only ever removed from a queue in order to be delivered. The bus's
        existing bounded buffers remain the only place an event can be dropped,
        and they already count it (``dropped_events``).

        Args:
            limit_per_subscription: most events taken from any one
                subscription in this call.
            time_budget_ms: wall-clock limit for the whole call. Zero - the
                default - means no limit, which is the historical behaviour and
                what the tests that count exhaustive delivery rely on.

        Returns:
            The number of events dispatched.
        """
        with self._lock:
            ids = [
                sub.id
                for sub in self._subscriptions.values()
                if sub.queued and sub.callback is not None
            ]
        if not ids:
            return 0
        if time_budget_ms <= 0:
            return sum(self.dispatch(sid, limit_per_subscription) for sid in ids)

        deadline = time.monotonic() + (time_budget_ms / 1000.0)
        budget = {sid: max(0, int(limit_per_subscription)) for sid in ids}
        total = 0
        active = list(ids)
        # The first pass is not interrupted, so every queued subscription gets
        # at least one chunk. Checking the clock mid-pass instead meant a
        # subscription that happened to be served first could exhaust the whole
        # budget and the others were never reached - a packet flood would then
        # hide a Snort alert or a database status change behind it. The overrun
        # this allows is bounded by (subscriptions x DISPATCH_CHUNK) events.
        first_pass = True
        while active:
            progressed = False
            for sid in list(active):
                take = min(self.DISPATCH_CHUNK, budget[sid])
                if take <= 0:
                    active.remove(sid)
                    continue
                dispatched = self.dispatch(sid, take)
                if dispatched:
                    progressed = True
                    total += dispatched
                    budget[sid] -= dispatched
                if dispatched < take:
                    # Its queue is empty; nothing more to take this round.
                    active.remove(sid)
                if not first_pass and time.monotonic() >= deadline:
                    return total
            if first_pass:
                first_pass = False
                if time.monotonic() >= deadline:
                    return total
            if not progressed:
                break
        return total

    def pending(self, subscription_id: int) -> int:
        """Number of buffered events for a subscription."""
        with self._lock:
            subscription = self._subscriptions.get(subscription_id)
            return len(subscription.queue) if subscription else 0

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------
    def statistics(self) -> dict[str, object]:
        """Real bus counters for the System Health screen."""
        with self._lock:
            return {
                "published": self._published,
                "subscriptions": len(self._subscriptions),
                "queued_events": sum(
                    len(s.queue) for s in self._subscriptions.values()
                ),
                "dropped_events": sum(s.dropped for s in self._subscriptions.values()),
                "subscriber_errors": sum(
                    s.errors for s in self._subscriptions.values()
                ),
            }

    def subscription_details(self) -> list[dict[str, object]]:
        """Per-subscription counters (diagnostics only)."""
        with self._lock:
            return [
                {
                    "id": s.id,
                    "name": s.name,
                    "events": sorted(s.event_types),
                    "pending": len(s.queue),
                    "dropped": s.dropped,
                    "errors": s.errors,
                }
                for s in self._subscriptions.values()
            ]
