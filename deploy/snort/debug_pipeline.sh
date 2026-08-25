#!/bin/bash
CAPDIR=/mnt/c/Snort-wsl/capture
mapfile -t files < <(ls -1 "$CAPDIR"/cap_*.pcap 2>/dev/null | sort)
echo "count=${#files[@]}"
printf '%s\n' "${files[@]}"
