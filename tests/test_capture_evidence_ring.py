"""The evidence pcap is bounded, and detail still works across a rotation.

The live path was already the architecture it should be: TShark reads the
wire through Npcap in its own process, the reader asks for a fixed field list
rather than a full decode, the queue between them is bounded and sheds with a
counter, the UI is fed in batches from a bounded deque, and the database is
written in batches under a row-rate cap. Measured on this machine's Wi-Fi over
150 seconds - 47,268 packets, peak 538/s - the queue never exceeded 62 of
20,000 and TShark reported no drops.

One thing was not bounded: the evidence pcap. ``-w`` wrote a single file for
the whole session, 31.8 MB in those 150 seconds - roughly 18 GB a day - with
nothing to stop it filling the disk.

It is now a ring. These tests hold the two halves of that:

* the disk stays bounded, because TShark keeps a fixed number of files and
  deletes the oldest;
* a packet can still be inspected in detail, because each one records the
  file it was actually written to. Frame numbers restart at 1 in every ring
  file, so a stale path would have pointed at the wrong frame - worse than
  none. The reader notices a rotation from the frame number going backwards,
  which costs nothing in the hot path.
"""

from __future__ import annotations

import inspect
import queue
from pathlib import Path

import pytest

from aethra_sec.integrations.pyshark_capture.field_reader import FieldCaptureReader
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.utils.timeutil import utcnow


def _reader(**kwargs) -> FieldCaptureReader:  # noqa: ANN003
    base = {
        "output_file": Path("C:/tmp/evidence.pcapng"),
        "tshark_path": Path("C:/Program Files/Wireshark/tshark.exe"),
    }
    base.update(kwargs)
    return FieldCaptureReader("eth0", queue.Queue(maxsize=10), **base)


def _packet(number: int, path: str = "") -> CapturedPacket:
    return CapturedPacket(
        captured_at=utcnow(), interface="eth0", number=number, pcap_path=path
    )


# ---------------------------------------------------------------------------
# The ring bounds the disk
# ---------------------------------------------------------------------------
class TestTheRingIsRequested:
    def test_the_ring_arguments_are_passed_to_tshark(self) -> None:
        command = _reader(ring_filesize_kb=65_536, ring_files=8)._command()
        assert "filesize:65536" in command
        assert "files:8" in command
        assert command.count("-b") == 2

    def test_a_single_file_is_still_possible(self) -> None:
        """Either bound at zero restores the old unbounded single file."""
        for kwargs in (
            {"ring_filesize_kb": 0, "ring_files": 8},
            {"ring_filesize_kb": 65_536, "ring_files": 0},
            {},
        ):
            command = _reader(**kwargs)._command()
            assert "-b" not in command

    def test_no_ring_without_a_capture_file(self) -> None:
        """Nothing to rotate when no evidence is being written."""
        command = _reader(
            output_file=None, ring_filesize_kb=65_536, ring_files=8
        )._command()
        assert "-b" not in command
        assert "-w" not in command

    def test_the_write_argument_is_still_there(self) -> None:
        """The ring bounds the evidence; it must not remove it."""
        command = _reader(ring_filesize_kb=1024, ring_files=4)._command()
        assert "-w" in command

    def test_negative_bounds_are_refused(self) -> None:
        reader = _reader(ring_filesize_kb=-5, ring_files=-1)
        assert reader._ring_filesize_kb == 0
        assert reader._ring_files == 0


class TestTheDefaultsAreBounded:
    def test_the_settings_exist_and_bound_the_disk(self) -> None:
        from aethra_sec.config.defaults import CAPTURE_SETTINGS

        specs = {s.key: s for s in CAPTURE_SETTINGS}
        assert specs["capture.pcap_ring_mb"].default == 64
        assert specs["capture.pcap_ring_files"].default == 8

    def test_the_default_total_is_a_sane_cap(self) -> None:
        """64 MB x 8 = 512 MB, against 18 GB/day unbounded before."""
        from aethra_sec.config.defaults import CAPTURE_SETTINGS

        specs = {s.key: s for s in CAPTURE_SETTINGS}
        total_mb = (
            specs["capture.pcap_ring_mb"].default
            * specs["capture.pcap_ring_files"].default
        )
        assert 100 <= total_mb <= 2_048

    def test_the_service_reads_both_settings(self) -> None:
        from aethra_sec.services.packet_capture import PacketCaptureService

        body = inspect.getsource(PacketCaptureService.start)
        assert "capture.pcap_ring_mb" in body
        assert "capture.pcap_ring_files" in body
        assert "ring_filesize_kb" in body and "ring_files" in body


# ---------------------------------------------------------------------------
# Rotation tracking keeps packet detail working
# ---------------------------------------------------------------------------
class TestRotationIsFollowed:
    def test_a_rising_frame_number_is_not_a_rotation(self) -> None:
        reader = _reader(ring_filesize_kb=64, ring_files=3)
        reader._pcap_text = "first.pcapng"
        for number in (1, 2, 3, 40):
            reader._follow_rotation(_packet(number))
        assert reader._pcap_text == "first.pcapng", (
            "the directory was re-read without a rotation, which would stat "
            "the disk on every packet"
        )

    def test_a_falling_frame_number_triggers_a_re_resolve(self, tmp_path) -> None:  # noqa: ANN001
        """Frame numbers restart at 1 in each ring file; that is the signal."""
        base = tmp_path / "evidence.pcapng"
        (tmp_path / "evidence_00001_x.pcapng").write_bytes(b"")
        (tmp_path / "evidence_00002_x.pcapng").write_bytes(b"")
        reader = _reader(output_file=base, ring_filesize_kb=64, ring_files=3)

        reader._follow_rotation(_packet(94))
        (tmp_path / "evidence_00003_x.pcapng").write_bytes(b"")
        reader._follow_rotation(_packet(1))

        assert reader._pcap_text.endswith("evidence_00003_x.pcapng")

    def test_the_newest_is_chosen_by_counter_not_mtime(self, tmp_path) -> None:  # noqa: ANN001
        """Two files written in the same second are ordinary."""
        base = tmp_path / "evidence.pcapng"
        for n in (1, 2, 10, 9):
            (tmp_path / f"evidence_{n:05d}_x.pcapng").write_bytes(b"")
        reader = _reader(output_file=base, ring_filesize_kb=64, ring_files=3)
        reader._resolve_current_ring_file()
        assert reader._pcap_text.endswith("evidence_00010_x.pcapng")

    def test_each_packet_records_the_file_it_was_written_to(self, tmp_path) -> None:  # noqa: ANN001
        base = tmp_path / "evidence.pcapng"
        (tmp_path / "evidence_00001_x.pcapng").write_bytes(b"")
        reader = _reader(output_file=base, ring_filesize_kb=64, ring_files=3)
        reader._pcap_text = str(tmp_path / "evidence_00001_x.pcapng")

        packet = _packet(5)
        reader._follow_rotation(packet)
        assert packet.pcap_path.endswith("evidence_00001_x.pcapng"), (
            "a packet carries no path, so its detail cannot be looked up"
        )

    def test_a_packet_with_no_frame_number_is_ignored(self) -> None:
        reader = _reader(ring_filesize_kb=64, ring_files=3)
        reader._pcap_text = "first.pcapng"
        reader._follow_rotation(_packet(None))  # type: ignore[arg-type]
        assert reader._pcap_text == "first.pcapng"

    def test_a_missing_directory_does_not_raise(self, tmp_path) -> None:  # noqa: ANN001
        """A capture must not end because the evidence directory went away."""
        reader = _reader(
            output_file=tmp_path / "gone" / "evidence.pcapng",
            ring_filesize_kb=64, ring_files=3,
        )
        reader._follow_rotation(_packet(10))
        reader._follow_rotation(_packet(1))  # no exception

    def test_rotation_is_only_followed_when_a_ring_is_configured(self) -> None:
        """A single-file capture never rotates, so it never re-reads the disk."""
        from aethra_sec.integrations.pyshark_capture import field_reader

        body = inspect.getsource(field_reader.FieldCaptureReader._run)
        assert "if self._ring_active:" in body


# ---------------------------------------------------------------------------
# What must not have been disturbed
# ---------------------------------------------------------------------------
class TestThePipelineIsUnchanged:
    """The measured architecture was already right; only the pcap changed."""

    def test_the_queue_is_still_bounded_and_sheds_with_a_count(self) -> None:
        from aethra_sec.integrations.pyshark_capture import field_reader

        body = inspect.getsource(field_reader.FieldCaptureReader._run)
        assert "put_nowait" in body
        assert "except Full" in body
        assert "counters.dropped += 1" in body

    def test_drops_are_read_from_tshark_not_inferred(self) -> None:
        """§35/§36: a drop figure must come from the capture engine."""
        source = inspect.getsource(
            __import__(
                "aethra_sec.integrations.pyshark_capture.field_reader",
                fromlist=["x"],
            )
        )
        assert "packets dropped" in source, (
            "the drop count is no longer parsed from TShark's own reporting"
        )

    def test_the_capture_filter_is_still_applied_by_tshark(self) -> None:
        """§11: filtering belongs below the Python layer."""
        command = _reader(bpf_filter="tcp port 80")._command()
        assert "-f" in command
        assert "tcp port 80" in command

    def test_the_reader_still_asks_for_fields_not_a_full_decode(self) -> None:
        """§3: the whole point of this path."""
        command = _reader()._command()
        assert "-T" in command and "fields" in command
        assert "-V" not in command and "-T pdml" not in " ".join(command)

    def test_capture_runs_in_its_own_process(self) -> None:
        """§5/§6: never inside the UI."""
        from aethra_sec.integrations.pyshark_capture import field_reader

        body = inspect.getsource(field_reader.FieldCaptureReader.start)
        assert "subprocess.Popen" in body

    def test_a_second_start_does_not_spawn_a_second_tshark(self) -> None:
        """§7: the single most expensive mistake this could make."""
        from aethra_sec.integrations.pyshark_capture import field_reader

        body = inspect.getsource(field_reader.FieldCaptureReader.start)
        assert "if self.is_running:" in body
        assert "return" in body


# ---------------------------------------------------------------------------
# The first ring file, before any rotation has happened
# ---------------------------------------------------------------------------
class TestTheFirstRingFileIsFound:
    """Regression: every packet before the first rotation had a dead path.

    ``-w`` alone writes the base path, so the reader seeded ``pcap_path`` with
    it. ``-b`` does not: TShark writes ``<base>_00001_<timestamp>.pcapng`` and
    never creates the base at all. Rotation was followed correctly, but nothing
    resolved the *first* file, so every packet captured before the first
    rotation - the first 64 MB, by default - carried a path that had never
    existed. Opening one said "the capture file is no longer present" while the
    capture was still running.

    The tests above missed it because they each assigned ``_pcap_text`` by hand
    before exercising rotation, which is precisely the state that was broken.
    """

    def test_a_ring_reader_does_not_start_on_the_base_path(self, tmp_path) -> None:  # noqa: ANN001
        base = tmp_path / "evidence.pcapng"
        reader = _reader(output_file=base, ring_filesize_kb=64, ring_files=3)
        assert reader._pcap_text != str(base), (
            "the base path is never created under -b, so every packet before "
            "the first rotation would point at a file that cannot exist"
        )

    def test_the_first_packet_resolves_the_first_ring_file(self, tmp_path) -> None:  # noqa: ANN001
        base = tmp_path / "evidence.pcapng"
        (tmp_path / "evidence_00001_x.pcapng").write_bytes(b"")
        reader = _reader(output_file=base, ring_filesize_kb=64, ring_files=3)

        packet = _packet(1)
        reader._follow_rotation(packet)

        assert packet.pcap_path.endswith("evidence_00001_x.pcapng")
        assert Path(packet.pcap_path).exists()

    def test_resolution_is_retried_until_the_file_appears(self, tmp_path) -> None:  # noqa: ANN001
        """A capture may see the directory before TShark has created the file."""
        base = tmp_path / "evidence.pcapng"
        reader = _reader(output_file=base, ring_filesize_kb=64, ring_files=3)

        early = _packet(1)
        reader._follow_rotation(early)
        assert early.pcap_path == "", "a path was invented before one existed"

        (tmp_path / "evidence_00001_x.pcapng").write_bytes(b"")
        later = _packet(2)
        reader._follow_rotation(later)
        assert later.pcap_path.endswith("evidence_00001_x.pcapng")

    def test_a_single_file_capture_still_uses_the_base_path(self, tmp_path) -> None:  # noqa: ANN001
        """Without a ring, -w writes exactly the base path and it is correct."""
        base = tmp_path / "evidence.pcapng"
        reader = _reader(output_file=base)
        assert reader._pcap_text == str(base)

    def test_one_bound_alone_is_not_a_ring(self, tmp_path) -> None:  # noqa: ANN001
        """_command() needs both bounds; the reader must agree, or it would
        hunt for rotated files the command never asked TShark to write."""
        base = tmp_path / "evidence.pcapng"
        for kwargs in ({"ring_filesize_kb": 64}, {"ring_files": 3}):
            reader = _reader(output_file=base, **kwargs)
            assert "-b" not in reader._command()
            assert reader._pcap_text == str(base), (
                "no ring was requested, so the base path is the real file"
            )
