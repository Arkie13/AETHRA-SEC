# AETHRA-SEC usability and satisfaction instrument

## Status of this document

**This is NOT the project's official Section 3.5 instrument.**

The repository was searched for the evaluation instrument referenced as Section
3.5 of the project documentation. It is not present: `docs/` contains
`ARCHITECTURE.md`, `DATABASE.md`, `INSTALL_WINDOWS.md`, `SECURITY.md`,
`SNORT_INTEGRATION.md`, `SNORT_WINDOWS_SETUP.md`, `UI_SCREEN_MAP.md` and
`USER_GUIDE.md`, none of which contains a questionnaire, a rating scale or a
participant protocol.

> **Official Section 3.5 instrument was not available to the implementation.**

What follows is therefore an **additional evaluation instrument**, offered so
that real participants can be run. If the official instrument exists outside
the repository, use that one instead and discard this.

**No participant has completed this instrument. No responses exist. Any report
presenting scores for these items without real respondents would be
fabrication.**

---

## Part A — Task protocol

Each participant attempts the tasks below unaided. The facilitator records
observations only; they do not assist unless the participant abandons the task.

For each task record: **completed (Y/N)**, **time in seconds**, **errors**
(actions that had to be undone or retried), **assists required**, and any
**verbatim comment**.

| ID | Task | Success criterion |
|----|------|-------------------|
| U01 | Open Live Monitoring | The live packet view is on screen |
| U02 | State which network interface is being captured | Participant names the interface correctly |
| U03 | Point to a packet that has just arrived | Participant identifies a row and its timestamp |
| U04 | Find traffic from a given source address | The address is located in the view |
| U05 | Apply a capture filter | The filter is applied and the state is understood |
| U06 | Identify a detected security event | Participant locates a real alert or anomaly |
| U07 | Open that event and say why it was raised | Participant states the rule and the threshold crossed |
| U08 | Investigate the host involved | The host record is opened |
| U09 | Open the related incident | The incident is opened from the event |
| U10 | Find the evidence behind the detection | Participant reaches the underlying packets |
| U11 | Read the mitigation guidance | Participant states the recommended action |
| U12 | Export a report | A report file is produced |
| U13 | Switch between dark and light themes | Both themes render and remain readable |
| U14 | Change a system setting and confirm it took effect | The change is visible after saving |
| U15 | Recover from an invalid capture filter | Participant reads the error and corrects the filter |
| U16 | Stop capture, then start it again | Both transitions succeed and the state is understood |

### Derived measures

- **Task completion rate** = completed tasks / attempted tasks
- **Mean time on task**, reported per task, with the range
- **Error rate** = errors / task
- **Assist rate** = tasks needing an assist / tasks attempted

---

## Part B — Post-task questionnaire

Seven-point scale: **1 = strongly disagree … 7 = strongly agree**.
Items marked (R) are reverse-scored.

### Functional suitability
1. The system did what I needed it to do for monitoring.
2. Information I needed was missing when I needed it. (R)

### Performance efficiency
3. The interface responded quickly enough to keep up with me.
4. I waited noticeably for screens or tables to update. (R)

### Usability — learnability
5. I understood what the main screens were for without being told.
6. I had to guess what a control would do. (R)

### Usability — operability
7. Carrying out a task took a reasonable number of steps.
8. I found it easy to move between related pieces of information.

### Usability — error prevention and recovery
9. When I made a mistake, the system made it clear what had gone wrong.
10. I could correct a mistake without losing my place.
11. An error message told me what to do next.

### Information clarity
12. I could tell why a security event had been raised.
13. I could reach the evidence behind a detection.
14. I could tell how serious an event was.
15. I was unsure whether what I was looking at was real or a placeholder. (R)

### Status visibility
16. I always knew whether capture was running.
17. I could tell which interface was in use.
18. The system told me when something had failed.

### Reliability and trust
19. I would trust this system's output in a real investigation.
20. I would be confident acting on a mitigation recommendation it made.

### Overall
21. I would be willing to use this system regularly.
22. Learning to use this system would take a reasonable amount of time.

### Free response
- What was the single most confusing thing?
- What would you change first?
- Was there any point at which you did not trust what you were shown? Why?

---

## Part C — Facilitator observation sheet

Recorded by the facilitator, not the participant.

| Observation | Notes |
|-------------|-------|
| Points where the participant hesitated more than ~5 seconds | |
| Controls the participant looked for and could not find | |
| Any moment the participant misread the system state | |
| Any moment the participant believed data was real when it was not, or the reverse | |
| Tasks abandoned, and at what step | |

---

## Reporting rules

1. Report the **number of participants**. A study with fewer than five
   participants is exploratory and must say so.
2. Report **per-item means with the spread**, not a single overall score.
3. Report **completion rate and time separately**; a task completed slowly is
   not the same as a task failed.
4. Do **not** aggregate reverse-scored items without reversing them.
5. Where an item was not answered, report it as missing rather than imputing it.
6. Quote free-response answers verbatim, including unfavourable ones.
