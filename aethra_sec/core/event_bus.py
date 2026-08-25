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
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Iterable

from aethra_sec.core.events import Event
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("core.event_bus")

EventCallback = Callable[[Event], None]

DEFAULT_QUEUE_SIZE = 2000


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
            for subscription in targets:
                if subscription.queued:
                    if len(subscription.queue) >= subscription.max_size:
                        subscription.queue.popleft()
                        subscription.dropped += 1
                    subscription.queue.append(event)
                else:
                    inline.append(subscription)

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

    def dispatch_all(self, limit_per_subscription: int = 500) -> int:
        """Dispatch every queued subscription that owns a callback.

        This is the single call the main window makes on each UI tick.
        """
        with self._lock:
            ids = [
                sub.id
                for sub in self._subscriptions.values()
                if sub.queued and sub.callback is not None
            ]
        return sum(self.dispatch(sid, limit_per_subscription) for sid in ids)

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
