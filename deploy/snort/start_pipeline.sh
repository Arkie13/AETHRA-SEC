#!/bin/bash
setsid nohup bash /mnt/c/xampp/htdocs/AETHRA-SEC/deploy/snort/snort_pcap_pipeline.sh > /tmp/pipeline.log 2>&1 < /dev/null &
disown
echo "PID=$!"
sleep 2
cat /tmp/pipeline.log
