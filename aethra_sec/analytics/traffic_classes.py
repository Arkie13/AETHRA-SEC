"""Manuscript traffic classifications computed from measured counters.

Two definitions from the manuscript, applied to real capture figures only:

* §4.5.4 Data Size Classification - traffic intensity by packets per second:
  small below 100 pps, medium 100 to 1,000 pps, large above 1,000 pps.
* §3.9.10 Traffic Analysis Accuracy - capture reliability by packet loss rate,
  dropped divided by total, reliable below 1% (ITU-T Y.1541).

Neither is computed without a measurement: no rate means no load class, and
no packets means no loss rate.
"""

from __future__ import annotations

from dataclasses import dataclass

#: §4.5.4 band edges, in packets per second.
SMALL_LOAD_CEILING = 100.0
LARGE_LOAD_FLOOR = 1000.0
#: §3.9.10: a capture is reliable while loss stays below this percentage.
RELIABLE_LOSS_PERCENT = 1.0


def traffic_load_class(packets_per_second: float | None) -> str:
    """The §4.5.4 load class for a measured rate, or "" without one."""
    if packets_per_second is None:
        return ""
    if packets_per_second < SMALL_LOAD_CEILING:
        return "Small (< 100 pps)"
    if packets_per_second <= LARGE_LOAD_FLOOR:
        return "Medium (100-1,000 pps)"
    return "Large (> 1,000 pps)"


@dataclass(frozen=True)
class CaptureReliability:
    """§3.9.10 capture reliability from real counters."""

    captured: int
    dropped: int

    @property
    def total(self) -> int:
        """Packets the capture was offered: delivered plus dropped."""
        return self.captured + self.dropped

    @property
    def loss_percent(self) -> float | None:
        """Dropped / total x 100, or None before any packet."""
        if self.total <= 0:
            return None
        return self.dropped / self.total * 100.0

    @property
    def reliable(self) -> bool | None:
        """True below 1% loss; None when not measurable."""
        loss = self.loss_percent
        if loss is None:
            return None
        return loss < RELIABLE_LOSS_PERCENT

    def describe(self) -> str:
        """One line for the counters strip."""
        loss = self.loss_percent
        if loss is None:
            return "packet loss not measured yet"
        verdict = "reliable" if self.reliable else "NOT reliable - repeat the capture"
        return f"packet loss {loss:.2f}% ({verdict}; §3.9.10 requires < 1%)"
