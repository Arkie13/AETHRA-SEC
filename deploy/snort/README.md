# Running Snort against AETHRA-SEC

AETHRA-SEC does not launch Snort. It **listens** for the alerts Snort emits, so
Snort runs as its own process and the two are wired together by a socket path.
This directory holds a working minimal configuration.

## 1. Install Snort

```bash
sudo apt-get install -y snort          # Debian/Ubuntu, ships Snort 2.9
snort -V
```

## 2. Install this configuration

```bash
sudo mkdir -p /etc/aethra-snort /var/log/snort
sudo cp snort.conf local.rules /etc/aethra-snort/
sudo snort -c /etc/aethra-snort/snort.conf -T      # validate
```

`local.rules` holds three deliberately broad rules (ICMP echo, TCP SYN, UDP to
port 53). They exist to prove the ingest path end to end on a lab network; on a
real network replace them with a rule set suited to it, because rules this broad
will alert on ordinary traffic.

## 3. Point AETHRA-SEC at the alert socket

In `.env`:

```ini
AETHRA_SNORT_TRANSPORT=unixsock
AETHRA_SNORT_SOCKET_PATH=/var/log/snort/snort_alert
AETHRA_SNORT_PATH=/usr/sbin/snort
AETHRA_SNORT_CONFIG=/etc/aethra-snort/snort.conf
```

## 4. Start them in the right order

AETHRA-SEC **binds** the socket and Snort connects to it, so AETHRA-SEC starts
first. Start the application, then:

```bash
sudo snort -c /etc/aethra-snort/snort.conf -i <interface> \
           -A unsock -l /var/log/snort -q -N
```

The Alerts screen then shows `RUNNING · transport: unixsock`, and its counters
(received / stored / duplicates folded / parse failures) are live.

## Troubleshooting

**"could not bind" / ingest OFFLINE.** Another process already owns the socket
- usually a Snort left running from a previous session. `pkill snort`, remove
`/var/log/snort/snort_alert`, and restart AETHRA-SEC.

**Alerts received but none stored.** That is deduplication, not a fault: a flood
matching one rule folds into a single row whose `duplicates folded` counter
climbs. The Alerts screen shows both numbers.

**`-A unsock` vs `output alert_unixsock`.** Either works; the config here sets
the output plugin, and the command line flag makes the intent explicit.
