"""Generate the IDS detection siren, ``assets/ids-siren.wav``.

The siren is synthesised, not recorded, so it can be rebuilt exactly from this
file and carries no third-party licence. It uses the standard library only.

Design - a classic "wail": the pitch sweeps smoothly up and back down, twice.
A pure sine at a fixed pitch reads as a chime (which is what Windows'
"SystemHand" sound was on this installation, and why a detection did not sound
like one); a continuous up-and-down sweep is what people recognise as a siren.
A little third harmonic is added so it carries on small laptop speakers.

* 2 sweeps of 1.2 s each, 650 Hz -> 1,450 Hz -> 650 Hz, 2.4 s in total
* 22,050 Hz, 16-bit mono PCM - played natively by Windows ``PlaySound``
* 25 ms fade in and out, peak at 70% of full scale, so it never clips

The output is deterministic: running this twice produces byte-identical files.

Usage:
    python scripts/generate_siren.py            # writes assets/ids-siren.wav
    python scripts/generate_siren.py --check    # verifies the file is current
"""

from __future__ import annotations

import argparse
import hashlib
import io
import math
import struct
import sys
import wave
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = PROJECT_ROOT / "assets" / "ids-siren.wav"

SAMPLE_RATE = 22_050
SWEEPS = 2
SWEEP_SECONDS = 1.2
LOW_HZ = 650.0
HIGH_HZ = 1_450.0
PEAK = 0.70
FADE_SECONDS = 0.025
HARMONIC_3 = 0.18


def synthesise() -> bytes:
    """Return the siren as a complete WAV file, in memory."""
    total = int(SAMPLE_RATE * SWEEPS * SWEEP_SECONDS)
    fade = int(SAMPLE_RATE * FADE_SECONDS)
    norm = PEAK / (1.0 + HARMONIC_3)
    phase = 0.0
    frames = bytearray()
    for n in range(total):
        t = n / SAMPLE_RATE
        # Position inside the current sweep, 0..1, mapped onto a raised
        # cosine so the pitch rises and falls smoothly rather than jumping.
        position = (t % SWEEP_SECONDS) / SWEEP_SECONDS
        lift = 0.5 - 0.5 * math.cos(2.0 * math.pi * position)
        frequency = LOW_HZ + (HIGH_HZ - LOW_HZ) * lift
        # Phase is accumulated, so a changing pitch never clicks.
        phase += 2.0 * math.pi * frequency / SAMPLE_RATE
        value = math.sin(phase) + HARMONIC_3 * math.sin(3.0 * phase)
        envelope = 1.0
        if n < fade:
            envelope = n / fade
        elif n >= total - fade:
            envelope = (total - 1 - n) / fade
        sample = int(round(value * norm * envelope * 32767))
        frames += struct.pack("<h", max(-32768, min(32767, sample)))

    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(SAMPLE_RATE)
        wav.writeframes(bytes(frames))
    return buffer.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed file differs from a rebuild")
    args = parser.parse_args()

    data = synthesise()
    digest = hashlib.sha256(data).hexdigest()
    if args.check:
        current = OUTPUT.read_bytes() if OUTPUT.is_file() else b""
        if current != data:
            print(f"{OUTPUT} is missing or stale; run without --check.")
            return 1
        print(f"{OUTPUT.name} is current ({len(data):,} bytes, sha256 {digest[:16]})")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(data)
    seconds = SWEEPS * SWEEP_SECONDS
    print(f"Wrote {OUTPUT} - {seconds:.1f} s, {len(data):,} bytes, "
          f"sha256 {digest[:16]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
