"""Attribute a server address to a domain, using only evidence on the wire.

Measured on this machine's own browsing - 2,343 frames in 30 seconds - a domain
name is present in almost none of them:

    TLS SNI (ClientHello only)        8 frames   0.34%
    DNS query                        22 frames   0.94%
    cleartext HTTP Host               2 frames   0.09%
    no domain available at all    ~2,311 frames  ~98.6%

``_ws.col.protocol`` read plain ``TCP`` for 1,864 of those frames. The name is
carried once, in the handshake; every later frame of the same connection
carries addresses and nothing else. A view that reads each frame in isolation
can therefore only ever label a fraction of its rows, which is exactly what
"it only shows some websites" looks like from the outside.

This module closes that gap without inventing anything. It remembers what was
actually observed - a DNS answer mapping a name to an address, or a TLS
ClientHello whose own destination *is* the server it named - and answers, for a
later frame, "which domain did this address belong to, and how do we know?".

What it will not do:

* it never guesses. No evidence, no attribution: the caller shows
  ``Unknown/Encrypted`` and that is the honest answer;
* it never assumes the most recent lookup explains the next connection. Entries
  are keyed by server address, not by recency, so a connection to an address
  nobody resolved stays unattributed however many other lookups just happened;
* it never grows without bound. Entries expire on time and the map is capped,
  evicting least-recently-used, so a long capture cannot fill memory;
* it never claims more than the evidence type supports. Every answer carries
  the source that produced it, so the interface can say *why* it believes a
  name rather than presenting a guess and a fact identically.

A known limitation, stated rather than hidden: the reader runs TShark with
``-E occurrence=f``, so when a DNS answer carries several A records only the
first is learned. Traffic to one of the other addresses is left unattributed.
That is lossy, and deliberately so - the alternative is attributing an address
the capture never actually tied to the name.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta

#: Shown when the capture carries no evidence for this address. Not a failure
#: and not a placeholder for a value that exists elsewhere: for encrypted
#: traffic whose handshake was not observed, this is the whole truth.
UNKNOWN = "Unknown/Encrypted"

#: Evidence kinds, most trustworthy first. SNI is exact - the ClientHello's own
#: destination is the server that was named. A DNS answer is one step removed:
#: it proves the name resolved to the address, not that this flow used it.
SOURCE_SNI = "TLS SNI"
SOURCE_DNS = "DNS answer"
SOURCE_HTTP_HOST = "HTTP Host header"

#: How long an observation is allowed to explain later traffic. DNS TTLs are
#: commonly shorter than this and CDN addresses are reassigned, so an old
#: mapping is dropped rather than trusted.
DEFAULT_TTL_SECONDS = 600

#: Hard cap on remembered addresses, evicting least-recently-used. A busy
#: capture sees thousands of distinct servers; this bounds the cost of that.
DEFAULT_MAX_ENTRIES = 4096


@dataclass(frozen=True)
class Attribution:
    """A domain, and the observation that justifies it."""

    domain: str
    source: str
    observed_at: datetime

    @property
    def is_exact(self) -> bool:
        """True when the evidence tied the name to this address directly."""
        return self.source in (SOURCE_SNI, SOURCE_HTTP_HOST)

    def describe(self) -> str:
        """One line naming the domain and how it is known."""
        return f"{self.domain} (from {self.source})"


class DomainResolver:
    """Bounded, expiring map of server address to observed domain.

    Safe to call from the capture worker and read from another thread: every
    operation takes one lock, and the lock is never held across a callback.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        self._ttl = timedelta(seconds=max(1, int(ttl_seconds)))
        self._max_entries = max(1, int(max_entries))
        self._lock = threading.Lock()
        #: address -> Attribution, ordered least-recently-used first.
        self._entries: "OrderedDict[str, Attribution]" = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._expired = 0
        self._evicted = 0

    # ------------------------------------------------------------------
    # Learning
    # ------------------------------------------------------------------
    def observe_sni(self, server_ip: str, sni: str, at: datetime) -> None:
        """A TLS ClientHello named ``sni`` while addressed to ``server_ip``.

        The strongest evidence available without decryption: the frame that
        carries the name is the same frame addressed to the server.
        """
        self._record(server_ip, sni, SOURCE_SNI, at)

    def observe_http_host(self, server_ip: str, host: str, at: datetime) -> None:
        """A cleartext HTTP request carried a Host header to this address."""
        self._record(server_ip, host, SOURCE_HTTP_HOST, at)

    def observe_dns_answer(self, address: str, name: str, at: datetime) -> None:
        """A DNS answer resolved ``name`` to ``address``.

        Weaker than SNI and recorded as such: it establishes that the name
        resolves here, not that any particular flow to here used that name.
        """
        self._record(address, name, SOURCE_DNS, at)

    def _record(self, address: str, domain: str, source: str, at: datetime) -> None:
        address = (address or "").strip()
        domain = (domain or "").strip().rstrip(".")
        if not address or not domain:
            return
        with self._lock:
            existing = self._entries.get(address)
            # Exact evidence is never replaced by inference. A DNS answer
            # arriving after a ClientHello must not downgrade what is known.
            if (
                existing is not None
                and existing.is_exact
                and source == SOURCE_DNS
                and at - existing.observed_at < self._ttl
            ):
                self._entries.move_to_end(address)
                return
            self._entries[address] = Attribution(domain, source, at)
            self._entries.move_to_end(address)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
                self._evicted += 1

    # ------------------------------------------------------------------
    # Answering
    # ------------------------------------------------------------------
    def attribution_for(self, address: str, at: datetime) -> Attribution | None:
        """What is known about ``address`` now, or None when nothing is.

        None is a real answer, not a failure. The caller shows :data:`UNKNOWN`.
        """
        address = (address or "").strip()
        if not address:
            return None
        with self._lock:
            entry = self._entries.get(address)
            if entry is None:
                self._misses += 1
                return None
            if at - entry.observed_at > self._ttl:
                # Addresses are reassigned; a stale mapping is worse than none.
                del self._entries[address]
                self._expired += 1
                self._misses += 1
                return None
            self._entries.move_to_end(address)
            self._hits += 1
            return entry

    def domain_for(self, address: str, at: datetime) -> str:
        """The observed domain for ``address``, or :data:`UNKNOWN`."""
        entry = self.attribution_for(address, at)
        return entry.domain if entry is not None else UNKNOWN

    # ------------------------------------------------------------------
    # Housekeeping and reporting
    # ------------------------------------------------------------------
    def purge_expired(self, at: datetime) -> int:
        """Drop every entry older than the TTL. Returns how many went."""
        with self._lock:
            dead = [
                address
                for address, entry in self._entries.items()
                if at - entry.observed_at > self._ttl
            ]
            for address in dead:
                del self._entries[address]
            self._expired += len(dead)
            return len(dead)

    def clear(self) -> None:
        """Forget everything. Used when a capture session ends."""
        with self._lock:
            self._entries.clear()

    def statistics(self) -> dict[str, int]:
        """Real counters, for the capture diagnostic."""
        with self._lock:
            return {
                "entries": len(self._entries),
                "max_entries": self._max_entries,
                "ttl_seconds": int(self._ttl.total_seconds()),
                "hits": self._hits,
                "misses": self._misses,
                "expired": self._expired,
                "evicted": self._evicted,
            }

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


def learn_from_packet(resolver: DomainResolver, packet) -> None:  # noqa: ANN001
    """Feed one captured packet's observable names into ``resolver``.

    Reads only fields the capture already carries, so this costs no extra
    dissection per packet. Called from the capture worker, never the UI thread.
    """
    at = getattr(packet, "captured_at", None)
    if at is None:
        return
    destination = getattr(packet, "dst_ip", "") or ""

    sni = getattr(packet, "tls_sni", "") or ""
    if sni and destination:
        resolver.observe_sni(destination, sni, at)

    host = getattr(packet, "http_host", "") or ""
    if host and destination:
        # Strip any :port the Host header carried.
        resolver.observe_http_host(destination, host.rsplit(":", 1)[0], at)

    name = getattr(packet, "dns_query", "") or ""
    answer = getattr(packet, "dns_answer_address", "") or ""
    if name and answer and getattr(packet, "dns_response", None):
        resolver.observe_dns_answer(answer, name, at)
