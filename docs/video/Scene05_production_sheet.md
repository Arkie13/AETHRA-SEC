# Scene 5 — Controlled Testing Environment

**Written for:** whoever edits and narrates the AETHRA-SEC defense video.

**Slot:** 4:30–5:15 (45 s) · **Objective 3 (setup)**

---

## Assets in this folder

| File | Use |
|---|---|
| `Fig_4.1_Controlled_Testing_Environment.png` | 1920×1080 · the scene's main visual |
| `Fig_4.1_Controlled_Testing_Environment.svg` | editable source — change labels here, re-export |
| `Scene05_lower_third.png` | 1920×1080 **transparent** overlay · the on-screen text |
| `Scene05_lower_third.svg` | editable source |

The figure is drawn in the console's own palette (background `#0B0E14`, accent
`#5B8DEF`, alert `#F58A3C`), so it cuts against the AETHRA-SEC screen-recording
footage without a colour jump.

---

## Timing

Narration is **80 words**. At 45 s that is **107 words per minute** — deliberate,
which suits a technical explanation and leaves room to breathe on the holds.

| In | Out | On screen | Narration |
|---|---|---|---|
| 4:30 | 4:36 | Fig. 4.1 fades up, full frame | ¶1 — "After implementation and integration…" |
| 4:36 | 4:38 | Lower third fades in | *(hold)* |
| 4:38 | 4:52 | Hold on figure; optional slow push-in to the three machines | ¶2 — "The setup has a monitoring server…" |
| 4:52 | 4:55 | Lower third fades out | *(hold)* |
| 4:55 | 5:09 | Push down to the scenario strip along the bottom | ¶3 — "The test scenarios are…" |
| 5:09 | 5:15 | Hold full frame, then cross-dissolve to Scene 6 | *(silence under the hold)* |

**If you have laboratory b-roll**, use it under ¶1 (4:30–4:38) with the lower
third over it, then cut to Fig. 4.1 on "The setup has…". The figure then
illustrates the sentence that describes it, which reads better than showing the
diagram before the narration explains it.

---

## On-screen text

```
CONTROLLED TESTING — ISOLATED LAB NETWORK
No production or internet-connected systems · Each scenario repeated 5–10 times under identical conditions
```

The isolation caption the script calls for is **also inside the figure**, as the
orange banner across the top — so if you only show Fig. 4.1 without the lower
third, the claim is still on screen.

---

## What the figure asserts, and where each claim comes from

Everything below is either in your script or verified in the codebase. Nothing
is invented.

| Element | Source |
|---|---|
| Monitoring server · PyShark / TShark, Snort IDS, Nmap | Verified — these are the integrations the application actually runs |
| MariaDB evidence store | Verified — the console connects to MariaDB 10.4.32 |
| Port scanning · TCP SYN flood · UDP flood · ICMP flood · abnormal HTTP volume | Verified — these are exactly the five rules in `analytics/anomaly_rules.py` |
| 200 SYN/s · 300 UDP/s · 120 ICMP/s · 10 HTTP req/s | Verified — `MANUSCRIPT_THRESHOLDS`, cited there as manuscript §3.9.8 |
| Router, switch, attacker machine, target device, isolation | Your script (Scene 5 screen actions) |
| "5–10 times under identical conditions" | Your narration |
| Port mirroring (SPAN) | **My addition** — see below |

### Why I added port mirroring

Your script lists a switch but not how the monitor sees the traffic. That gap
matters: **a switch forwards a frame only to its destination port**, so a
monitoring server plugged into an ordinary port sees none of the
attacker-to-target traffic — only broadcast and its own. Detection would
measure nothing.

This is not hypothetical for this project. Earlier peer-visibility testing on
this installation recorded **zero peer unicast frames** even with the adapter in
promiscuous mode, because the network gave the monitor no copy of other devices'
traffic. A mirrored (SPAN) port is what closes that gap.

So the figure shows it explicitly, with a short panel explaining why. If an
examiner asks "how does the monitor see traffic between two other machines?",
the answer is already on screen. **If your lab switch is unmanaged and does not
mirror**, tell me — the figure should then show a network TAP or a hub segment
instead, and that changes the diagram.

### Two things I deliberately left out

I first wrote "Kali Linux · hping3, nmap, curl" on the attacker machine and
"Known services on known ports" on the target. Your script states neither, and I
have no way to verify them, so I removed both rather than put a specific claim
about your lab on screen. If you want your real tooling named, give me the list
and I'll add it.

---

## One thing to check before you record

The figure states the lab is **air-gapped, with no internet-connected systems**.
That claim has to match your footage.

When I exercised the system today it was monitoring **Wi-Fi network
192.168.100.0/24**, and the inventory held phones and laptops — an ordinary
connected network, not an isolated lab segment. The automatic assessment's own
scope line, which appears on the Vulnerability Assessment screen, reads:

```
Automatic assessment scope: 192.168.100.0/24 (monitored interface Wi-Fi, …)
```

If your demo footage is recorded on that network and this scene says the
environment is isolated, the two contradict each other on screen, and the scope
line is visible in the console. Either:

1. **record the demo in the actual lab segment**, so the on-screen scope matches
   the figure — the stronger option for a defense; or
2. **soften the claim** to describe the lab used for the measured trials while
   the walkthrough footage is a separate development environment, and say so.

I can't tell from here which is the case — only that the two would need to
agree. Worth settling before recording rather than in the Q&A.
