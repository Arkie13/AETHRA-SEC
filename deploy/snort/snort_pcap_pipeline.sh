#!/bin/bash
# Feeds Snort real captured traffic via pcap files instead of live interface
# capture, so it sees traffic WSL2's mirrored networking cannot: third-party
# unicast packets addressed directly to the Windows host (see
# deploy/snort/README.md "Running Snort in WSL" for why live -i capture on
# the mirrored interface misses this).
#
# The capture itself is a Windows-side tshark ring buffer (started
# separately - see the README) writing 10-second pcap chunks to
# C:\Snort-wsl\capture, using the same Npcap capture path AETHRA-SEC's own
# PyShark monitoring already relies on. This script processes each
# completed chunk through Snort in read mode (-r), appending real,
# signature-matched alerts to the same alert file the live pipeline used.
set -u

CAPDIR=/mnt/c/Snort-wsl/capture
PROCESSED="$CAPDIR/processed"
LOGDIR=/mnt/c/Snort-wsl/log
CONF=/mnt/c/xampp/htdocs/AETHRA-SEC/deploy/snort/snort.wsl.conf

mkdir -p "$PROCESSED"

echo "Snort pcap pipeline started: watching $CAPDIR"

while true; do
    # Sorted list of completed ring-buffer chunks. The newest file is
    # excluded - tshark may still be writing it when this loop wakes up.
    mapfile -t files < <(ls -1 "$CAPDIR"/cap_*.pcap 2>/dev/null | sort)
    count=${#files[@]}
    if [ "$count" -gt 1 ]; then
        for ((i = 0; i < count - 1; i++)); do
            f="${files[$i]}"
            if [ -s "$f" ]; then
                snort -c "$CONF" -r "$f" -l "$LOGDIR" -q 2>>/tmp/snort_pipeline_errors.log
            fi
            mv "$f" "$PROCESSED/" 2>/dev/null
        done
    fi
    # Keep at most 50 processed chunks around for later inspection.
    ls -1t "$PROCESSED"/cap_*.pcap 2>/dev/null | tail -n +51 | xargs -r rm -f
    sleep 3
done
