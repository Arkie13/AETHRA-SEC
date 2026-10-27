# Code Changes Against the Baseline

Generated 2026-10-06T15:55:16.

- files matching the baseline: 223
- modified: 28
- deleted: 0
- added (not in the baseline): 19

## Modified files

- `aethra_sec/analytics/display_filter.py`
- `aethra_sec/analytics/traffic_direction.py`
- `aethra_sec/config/defaults.py`
- `aethra_sec/core/event_bus.py`
- `aethra_sec/core/events.py`
- `aethra_sec/database/migrations.py`
- `aethra_sec/database/repositories/users.py`
- `aethra_sec/database/schema.py`
- `aethra_sec/integrations/nmap/runner.py`
- `aethra_sec/integrations/pyshark_capture/field_reader.py`
- `aethra_sec/models/traffic.py`
- `aethra_sec/models/user.py`
- `aethra_sec/services/assessment_queue.py`
- `aethra_sec/services/audio_alert_service.py`
- `aethra_sec/services/nmap_service.py`
- `aethra_sec/services/notification_service.py`
- `aethra_sec/services/packet_capture.py`
- `aethra_sec/services/packet_view.py`
- `aethra_sec/ui/app.py`
- `aethra_sec/ui/screens/about.py`
- `aethra_sec/ui/screens/traffic.py`
- `aethra_sec/ui/screens/users.py`
- `aethra_sec/ui/screens/vulnerabilities.py`
- `aethra_sec/ui/widgets/chips.py`
- `aethra_sec/utils/net.py`
- `tests/test_capture_evidence_ring.py`
- `tests/test_display_filter.py`
- `tests/test_flood_resilience.py`

## Deleted files

_none_

## Added files

- `aethra_sec/analytics/adapter_capability.py`
- `aethra_sec/analytics/domain_correlation.py`
- `aethra_sec/analytics/peer_visibility.py`
- `aethra_sec/diagnostics/__init__.py`
- `aethra_sec/diagnostics/flood_probe.py`
- `aethra_sec/services/capture_diagnostic.py`
- `scripts/build_user_manual.py`
- `scripts/check_peer_visibility.py`
- `scripts/manual_content.py`
- `tests/test_alert_sound_pipeline.py`
- `tests/test_assessment_ui_responsiveness.py`
- `tests/test_capture_diagnostic.py`
- `tests/test_chip_repaint_cost.py`
- `tests/test_domain_correlation.py`
- `tests/test_event_dispatch_budget.py`
- `tests/test_flood_probe.py`
- `tests/test_live_packet_filters.py`
- `tests/test_peer_visibility.py`
- `tests/test_user_date_modified.py`

## Findings

### BODY_CHANGED - `aethra_sec/analytics/traffic_direction.py` :: `os_interfaces`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/analytics/traffic_direction.py::os_interfaces
+++ current/aethra_sec/analytics/traffic_direction.py::os_interfaces
@@ -9,7 +9,8 @@
     except ImportError:  # pragma: no cover - psutil is a declared dependency
         return {}
-    try:
-        table = psutil.net_if_addrs()
-    except Exception:  # noqa: BLE001 - never break capture over this
+    # Through the shared cache: the enumeration does not release the GIL, and
+    # this runs on the capture path. See ADAPTER_CACHE_SECONDS.
+    table, _stats = adapter_tables()
+    if not table:
         return {}
 
```

### SIGNATURE_CHANGED - `aethra_sec/core/event_bus.py` :: `EventBus.dispatch_all`

- severity: CRITICAL
- baseline: def dispatch_all(self, limit_per_subscription: int=500)
current : def dispatch_all(self, limit_per_subscription: int=500, *, time_budget_ms: float=0.0)

```diff
--- baseline/aethra_sec/core/event_bus.py::EventBus.dispatch_all
+++ current/aethra_sec/core/event_bus.py::EventBus.dispatch_all
@@ -1,6 +1,43 @@
-    def dispatch_all(self, limit_per_subscription: int = 500) -> int:
+    def dispatch_all(
+        self,
+        limit_per_subscription: int = 500,
+        *,
+        time_budget_ms: float = 0.0,
+    ) -> int:
         """Dispatch every queued subscription that owns a callback.
 
-        This is the single call the main window makes on each UI tick.
+        This is the single call the main window makes on each UI tick, and it
+        runs on the Tk thread, so how long it may take is a property of the
+        interface rather than of the bus.
+
+        A count limit alone could not bound that. Measured during a real
+        full-port Nmap scan of one host, with the capture pipeline raising
+        ``capture.packet_batch`` at roughly 230 events a second, this call took
+        **777 ms on average and 2,007 ms at worst** - 96% of the whole UI tick
+        (24.09 s of 25.09 s) - and the interface stalled 69 times in 220
+        seconds. The per-event cost was not the problem: it averaged 0.063 ms.
+        Some individual events cost 215 ms, so any fixed count can still add up
+        to seconds.
+
+        ``time_budget_ms`` bounds it in wall-clock terms instead. Subscriptions
+        are served round-robin in small chunks and the clock is checked between
+        them, so one noisy subscription cannot starve the others and the Tk
+        thread is handed back on time.
+
+        Nothing is discarded here: an event not reached stays in its
+        subscription's queue and is dispatched on the next tick. Events are
+        only ever removed from a queue in order to be delivered. The bus's
+        existing bounded buffers remain the only place an event can be dropped,
+        and they already count it (``dropped_events``).
+
+        Args:
+            limit_per_subscription: most events taken from any one
+                subscription in this call.
+            time_budget_ms: wall-clock limit for the whole call. Zero - the
+                default - means no limit, which is the historical behaviour and
+                what the tests that count exhaustive delivery rely on.
+
+        Returns:
+            The number of events dispatched.
         """
         with self._lock:
@@ -10,3 +47,42 @@
                 if sub.queued and sub.callback is not None
             ]
-        return sum(self.dispatch(sid, limit_per_subscription) for sid in ids)
+        if not ids:
+            return 0
+        if time_budget_ms <= 0:
+            return sum(self.dispatch(sid, limit_per_subscription) for sid in ids)
+
+        deadline = time.monotonic() + (time_budget_ms / 1000.0)
+        budget = {sid: max(0, int(limit_per_subscription)) for sid in ids}
+        total = 0
+        active = list(ids)
+        # The first pass is not interrupted, so every queued subscription gets
+        # at least one chunk. Checking the clock mid-pass instead meant a
+        # subscription that happened to be served first could exhaust the whole
+        # budget and the others were never reached - a packet flood would then
+        # hide a Snort alert or a database status change behind it. The overrun
+        # this allows is bounded by (subscriptions x DISPATCH_CHUNK) events.
+        first_pass = True
+        while active:
+            progressed = False
+            for sid in list(active):
+                take = min(self.DISPATCH_CHUNK, budget[sid])
+                if take <= 0:
+                    active.remove(sid)
+                    continue
+                dispatched = self.dispatch(sid, take)
+                if dispatched:
+                    progressed = True
+                    total += dispatched
+                    budget[sid] -= dispatched
+                if dispatched < take:
+                    # Its queue is empty; nothing more to take this round.
+                    active.remove(sid)
+                if not first_pass and time.monotonic() >= deadline:
+                    return total
+            if first_pass:
+                first_pass = False
+                if time.monotonic() >= deadline:
+                    return total
+            if not progressed:
+                break
+        return total
```

### ADDED_FUNCTION - `aethra_sec/database/migrations.py` :: `_apply_user_date_modified`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### BODY_CHANGED - `aethra_sec/database/repositories/users.py` :: `UserRepository._map_user`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/database/repositories/users.py::UserRepository._map_user
+++ current/aethra_sec/database/repositories/users.py::UserRepository._map_user
@@ -20,4 +20,5 @@
             created_at=as_dt(row.get("created_at")),
             updated_at=as_dt(row.get("updated_at")),
+            date_modified=as_dt(row.get("date_modified")),
             created_by=as_int(row.get("created_by")),
         )
```

### BODY_CHANGED - `aethra_sec/database/repositories/users.py` :: `UserRepository.update_profile`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/database/repositories/users.py::UserRepository.update_profile
+++ current/aethra_sec/database/repositories/users.py::UserRepository.update_profile
@@ -8,8 +8,18 @@
         is_active: bool,
     ) -> None:
-        """Update editable account fields."""
+        """Update editable account fields.
+
+        This is an administrator changing the account's identity, so it stamps
+        ``date_modified`` as well as ``updated_at``. The two are not the same
+        thing: ``updated_at`` also moves on sign-in and on a failed-login
+        count, which is why it cannot answer "when was this account edited".
+        """
+        now = to_db(utcnow())
         self.db.execute(
             "UPDATE users SET full_name = %s, email = %s, role_id = %s, "
-            "is_active = %s, updated_at = %s WHERE id = %s",
-            (full_name, email, role_id, 1 if is_active else 0, to_db(utcnow()), user_id),
+            "is_active = %s, updated_at = %s, date_modified = %s WHERE id = %s",
+            (
+                full_name, email, role_id, 1 if is_active else 0,
+                now, now, user_id,
+            ),
         )
```

### BODY_CHANGED - `aethra_sec/database/repositories/users.py` :: `UserRepository.set_password`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/database/repositories/users.py::UserRepository.set_password
+++ current/aethra_sec/database/repositories/users.py::UserRepository.set_password
@@ -13,5 +13,8 @@
             "password_changed_at = %s, must_change_password = %s, "
             "failed_login_count = 0, is_locked = 0, locked_until = NULL, "
-            "updated_at = %s WHERE id = %s",
-            (password_hash, algorithm, now, 1 if must_change else 0, now, user_id),
+            "updated_at = %s, date_modified = %s WHERE id = %s",
+            (
+                password_hash, algorithm, now, 1 if must_change else 0,
+                now, now, user_id,
+            ),
         )
```

### BODY_CHANGED - `aethra_sec/database/repositories/users.py` :: `UserRepository.set_active`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/database/repositories/users.py::UserRepository.set_active
+++ current/aethra_sec/database/repositories/users.py::UserRepository.set_active
@@ -1,6 +1,12 @@
     def set_active(self, user_id: int, active: bool) -> None:
-        """Activate or deactivate an account."""
+        """Activate or deactivate an account.
+
+        An administrator's decision about the account, so it stamps
+        ``date_modified``.
+        """
+        now = to_db(utcnow())
         self.db.execute(
-            "UPDATE users SET is_active = %s, updated_at = %s WHERE id = %s",
-            (1 if active else 0, to_db(utcnow()), user_id),
+            "UPDATE users SET is_active = %s, updated_at = %s, "
+            "date_modified = %s WHERE id = %s",
+            (1 if active else 0, now, now, user_id),
         )
```

### SIGNATURE_CHANGED - `aethra_sec/integrations/nmap/runner.py` :: `probe_nmap`

- severity: CRITICAL
- baseline: def probe_nmap(configured_path: Path | None=None)
current : def probe_nmap(configured_path: Path | None=None, *, refresh: bool=False)

```diff
--- baseline/aethra_sec/integrations/nmap/runner.py::probe_nmap
+++ current/aethra_sec/integrations/nmap/runner.py::probe_nmap
@@ -1,53 +1,19 @@
-def probe_nmap(configured_path: Path | None = None) -> NmapAvailability:
+def probe_nmap(
+    configured_path: Path | None = None, *, refresh: bool = False
+) -> NmapAvailability:
     """Check whether Nmap can actually be executed.
 
     Runs ``nmap --version`` with a fixed argument list (no shell) and reports
-    the real version string.
+    the real version string. The result is cached for
+    :data:`NMAP_PROBE_CACHE_SECONDS`; pass ``refresh=True`` to re-probe now.
     """
-    if not PYTHON_NMAP_AVAILABLE:
-        return NmapAvailability(
-            available=False,
-            detail=(
-                f"The python-nmap library is not installed "
-                f"({PYTHON_NMAP_IMPORT_ERROR}). Run: pip install python-nmap"
-            ),
-            library_available=False,
-        )
-
-    executable = find_nmap(configured_path)
-    if executable is None:
-        return NmapAvailability(available=False, detail=NMAP_MISSING_MESSAGE)
-
-    try:
-        completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False
-            [str(executable), "--version"],
-            capture_output=True,
-            text=True,
-            timeout=20,
-            check=False,
-        )
-    except (OSError, subprocess.SubprocessError) as exc:
-        return NmapAvailability(
-            available=False,
-            executable=str(executable),
-            detail=f"Nmap was found at {executable} but could not be executed: {exc}",
-        )
-
-    if completed.returncode != 0:
-        return NmapAvailability(
-            available=False,
-            executable=str(executable),
-            detail=(
-                f"'{executable} --version' exited with code "
-                f"{completed.returncode}: {completed.stderr.strip()[:200]}"
-            ),
-        )
-
-    version_line = (completed.stdout or "").strip().splitlines()
-    version = version_line[0].strip() if version_line else "unknown version"
-    return NmapAvailability(
-        available=True,
-        executable=str(executable),
-        version=version,
-        detail=f"{version} at {executable}",
-    )
+    key = str(configured_path or "")
+    if not refresh:
+        with _probe_lock:
+            cached = _probe_cache.get(key)
+            if cached is not None and (time.monotonic() - cached[0]) <= NMAP_PROBE_CACHE_SECONDS:
+                return cached[1]
+    result = _probe_nmap_uncached(configured_path)
+    with _probe_lock:
+        _probe_cache[key] = (time.monotonic(), result)
+    return result
```

### ADDED_FUNCTION - `aethra_sec/integrations/nmap/runner.py` :: `invalidate_nmap_probe`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### ADDED_FUNCTION - `aethra_sec/integrations/nmap/runner.py` :: `_probe_nmap_uncached`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### BODY_CHANGED - `aethra_sec/integrations/pyshark_capture/field_reader.py` :: `parse_line`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/integrations/pyshark_capture/field_reader.py::parse_line
+++ current/aethra_sec/integrations/pyshark_capture/field_reader.py::parse_line
@@ -110,4 +110,9 @@
         dns_response=_flag(parts, "dns.flags.response"),
         dns_srv_target=_text(parts, "dns.srv.target"),
+        # A over AAAA: both are recorded by the dissector when a response
+        # carries both, and either alone is enough to join the name to a flow.
+        dns_answer_address=(
+            _address(parts, "dns.a") or _address(parts, "dns.aaaa")
+        ),
         icmp_type=icmp_type,
         icmp_code=icmp_code,
```

### BODY_CHANGED - `aethra_sec/integrations/pyshark_capture/field_reader.py` :: `FieldCaptureReader.__init__`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/integrations/pyshark_capture/field_reader.py::FieldCaptureReader.__init__
+++ current/aethra_sec/integrations/pyshark_capture/field_reader.py::FieldCaptureReader.__init__
@@ -27,6 +27,4 @@
         self._tshark_path = tshark_path
         self._output_file = output_file
-        #: Recorded on every packet so the inspector can find its frame again.
-        self._pcap_text = str(output_file) if output_file is not None else ""
         #: Ring-buffer bounds for the evidence pcap. Zero means one
         #: unbounded file, which is what this used to be: measured at
@@ -35,4 +33,24 @@
         self._ring_filesize_kb = max(0, int(ring_filesize_kb))
         self._ring_files = max(0, int(ring_files))
+        #: A ring needs both bounds. One alone leaves TShark writing the
+        #: single file at ``-w``, so every site that asks "is this a ring?"
+        #: has to agree, or the reader looks for rotated files that the
+        #: command never asked for.
+        self._ring_active = bool(self._ring_filesize_kb and self._ring_files)
+        #: Recorded on every packet so the inspector can find its frame again.
+        #:
+        #: With ``-b`` TShark never creates the base path: it writes
+        #: ``<base>_00001_<timestamp>.pcapng`` and so on. Seeding this with the
+        #: base path would hand every packet captured before the first
+        #: rotation - the first ``filesize`` kilobytes, 64 MB by default - a
+        #: path that does not exist and never will, and their detail would
+        #: read "the capture file is no longer present" while the capture was
+        #: still running. So under a ring it starts unknown and
+        #: :meth:`_follow_rotation` resolves it from the directory.
+        self._pcap_text = (
+            ""
+            if output_file is None or self._ring_active
+            else str(output_file)
+        )
         #: Last frame number seen, to notice a rotation.
         self._last_frame_number: int | None = None
```

### BODY_CHANGED - `aethra_sec/integrations/pyshark_capture/field_reader.py` :: `FieldCaptureReader._command`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/integrations/pyshark_capture/field_reader.py::FieldCaptureReader._command
+++ current/aethra_sec/integrations/pyshark_capture/field_reader.py::FieldCaptureReader._command
@@ -18,5 +18,5 @@
             # evidence path keeps the packet.
             command += ["-w", str(self._output_file)]
-            if self._ring_filesize_kb and self._ring_files:
+            if self._ring_active:
                 # A ring, so a long session cannot fill the disk. Total on
                 # disk is bounded by filesize x files; TShark deletes the
```

### BODY_CHANGED - `aethra_sec/integrations/pyshark_capture/field_reader.py` :: `FieldCaptureReader._follow_rotation`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/integrations/pyshark_capture/field_reader.py::FieldCaptureReader._follow_rotation
+++ current/aethra_sec/integrations/pyshark_capture/field_reader.py::FieldCaptureReader._follow_rotation
@@ -23,5 +23,12 @@
         if number is None:
             return
-        if self._last_frame_number is not None and number < self._last_frame_number:
+        if not self._pcap_text:
+            # Not resolved yet. The first file exists by the time its first
+            # packet reaches us, but a capture that starts on a silent
+            # interface can see the directory before TShark creates it, so
+            # this retries per packet only while unresolved - never once a
+            # path is known.
+            self._resolve_current_ring_file()
+        elif self._last_frame_number is not None and number < self._last_frame_number:
             self._resolve_current_ring_file()
         self._last_frame_number = number
```

### BODY_CHANGED - `aethra_sec/integrations/pyshark_capture/field_reader.py` :: `FieldCaptureReader._run`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/integrations/pyshark_capture/field_reader.py::FieldCaptureReader._run
+++ current/aethra_sec/integrations/pyshark_capture/field_reader.py::FieldCaptureReader._run
@@ -15,5 +15,5 @@
                         self.counters.decode_errors += 1
                     continue
-                if self._ring_files:
+                if self._ring_active:
                     self._follow_rotation(packet)
                 with self.counters._lock:  # noqa: SLF001
```

### ADDED_FUNCTION - `aethra_sec/integrations/pyshark_capture/field_reader.py` :: `FieldCaptureReader.pid`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### BODY_CHANGED - `aethra_sec/services/assessment_queue.py` :: `AssessmentQueueService._is_own_address`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/services/assessment_queue.py::AssessmentQueueService._is_own_address
+++ current/aethra_sec/services/assessment_queue.py::AssessmentQueueService._is_own_address
@@ -11,13 +11,10 @@
             if parsed == network.network_address:
                 return True
+        # Asked once per candidate host, so the adapter read behind this must
+        # be the cached one. Enumerating the adapters per host is what made
+        # eligibility cost 88 ms a host and froze the interface; see
+        # ADAPTER_CACHE_SECONDS.
         try:
-            import psutil
-            import socket
-
-            for entries in psutil.net_if_addrs().values():
-                for entry in entries:
-                    if entry.family == socket.AF_INET and entry.address == address:
-                        return True
-        except Exception:  # noqa: BLE001
+            return address in local_ipv4_addresses()
+        except Exception:  # noqa: BLE001 - absence is "not our address"
             return False
-        return False
```

### BODY_CHANGED - `aethra_sec/services/assessment_queue.py` :: `AssessmentQueueService.statistics`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/services/assessment_queue.py::AssessmentQueueService.statistics
+++ current/aethra_sec/services/assessment_queue.py::AssessmentQueueService.statistics
@@ -31,5 +31,15 @@
                 candidates = []
             stats.due_now = sum(1 for host in candidates if self.eligibility(host)[0])
-        except Exception:  # noqa: BLE001
-            pass
+        except Exception as exc:  # noqa: BLE001 - never break the caller
+            # Was silently swallowed, which left "0 due now" on screen whether
+            # nothing was due or the question could not be answered. Those are
+            # different states and an operator has to be able to tell them
+            # apart, so the failure is logged and said out loud.
+            LOGGER.exception("The assessment due-now figure could not be computed.")
+            stats.due_now_available = False
+            detail = (
+                "The number of hosts due for assessment could not be "
+                f"determined: {exc}"
+            )
+            stats.detail = f"{stats.detail}  {detail}".strip() if stats.detail else detail
         return stats
```

### ADDED_FUNCTION - `aethra_sec/services/audio_alert_service.py` :: `AudioAlertService.diagnose`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### BODY_CHANGED - `aethra_sec/services/nmap_service.py` :: `NmapService.stop_scan`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/services/nmap_service.py::NmapService.stop_scan
+++ current/aethra_sec/services/nmap_service.py::NmapService.stop_scan
@@ -1,8 +1,13 @@
     def stop_scan(self, session: Session, scan_id: int) -> bool:
-        """Request cancellation of a running scan.
+        """Stop a running scan now.
 
-        Nmap runs as a synchronous child process, so cancellation takes effect
-        when the current invocation returns; the scan is then marked CANCELLED
-        and its partial results are discarded rather than stored as if complete.
+        The runner owns the Nmap process and keeps its handle, so cancelling
+        kills that process immediately rather than waiting for it to finish on
+        its own - which, for a scan stalled on an unresponsive host, could be
+        never. The scan is then marked CANCELLED and its partial results are
+        discarded rather than stored as if the assessment had completed.
+
+        Only this scan's own process is signalled, by handle and not by name,
+        so an Nmap another tool started is never touched.
         """
         live = self._access.require(session, Permission.SCAN_STOP, target=str(scan_id))
```

### BODY_CHANGED - `aethra_sec/services/notification_service.py` :: `NotificationService._store`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/services/notification_service.py::NotificationService._store
+++ current/aethra_sec/services/notification_service.py::NotificationService._store
@@ -1,6 +1,20 @@
     def _store(self, notification: Notification) -> None:
-        """Persist a notification and trim the retained list."""
+        """Persist a notification, then announce that it exists.
+
+        The announcement is the point. Storing a row is what makes the badge
+        count rise, but nothing was ever published afterwards, so the interface
+        never learned that a notification had appeared and the alert sound -
+        which is driven by that event - never played. 101 real alert
+        notifications were sitting in this installation's database, including
+        SYN floods from the operator's own testing, every one of them silent.
+
+        It is published *after* a successful insert and carries the real row
+        id, so three things follow for free: a notification that failed to
+        persist cannot sound, the sound and the badge are driven by the same
+        record rather than by two guesses at it, and the audio service has an
+        immutable identifier to fold repeats against.
+        """
         try:
-            self._repository.create(notification)
+            notification_id = self._repository.create(notification)
             with self._lock:
                 self._raised += 1
@@ -10,2 +24,28 @@
         except Exception:  # noqa: BLE001
             LOGGER.debug("Could not store a notification.", exc_info=True)
+            return
+
+        LOGGER.info(
+            "[NOTIFY] Stored: id=%s level=%s category=%s ref=%s:%s",
+            notification_id,
+            notification.level,
+            notification.category,
+            notification.reference_type or "-",
+            notification.reference_id if notification.reference_id else "-",
+        )
+        try:
+            self._bus.publish(
+                EventType.NOTIFICATION_STORED,
+                NotificationPayload(
+                    title=notification.title,
+                    message=notification.message,
+                    level=notification.level,
+                    category=notification.category,
+                    reference_type=notification.reference_type,
+                    reference_id=notification.reference_id,
+                    notification_id=notification_id,
+                ),
+            )
+        except Exception:  # noqa: BLE001 - a failed announcement must not
+            # undo a stored notification, nor break the producer's work.
+            LOGGER.exception("Could not announce notification %s", notification_id)
```

### BODY_CHANGED - `aethra_sec/services/packet_capture.py` :: `PacketCaptureService.__init__`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/services/packet_capture.py::PacketCaptureService.__init__
+++ current/aethra_sec/services/packet_capture.py::PacketCaptureService.__init__
@@ -33,4 +33,10 @@
         )
         self.rules = AnomalyRuleEngine(thresholds_from_settings(settings.get))
+        #: Server address -> the domain the capture actually observed for
+        #: it. Bounded and expiring; see analytics.domain_correlation.
+        self.domains = DomainResolver(
+            ttl_seconds=settings.get_int("capture.domain_ttl_seconds", 600),
+            max_entries=settings.get_int("capture.domain_cache_entries", 4096),
+        )
         self.counters = PipelineCounters()
         #: Recent packets and the display filter applied to them. Owned here,
```

### BODY_CHANGED - `aethra_sec/services/packet_capture.py` :: `PacketCaptureService._handle_packet`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/services/packet_capture.py::PacketCaptureService._handle_packet
+++ current/aethra_sec/services/packet_capture.py::PacketCaptureService._handle_packet
@@ -11,4 +11,9 @@
 
         self.analyzer.observe(packet)
+        # Learn any domain this frame actually states, so the frames that
+        # follow it - which carry an address and no name - can be attributed.
+        # Reads fields already extracted, so it costs no extra dissection, and
+        # it runs here on the worker rather than on the Tk thread.
+        learn_from_packet(self.domains, packet)
         ui_batch.append(packet)
         self._accumulate_host(packet)
```

### ADDED_FUNCTION - `aethra_sec/services/packet_capture.py` :: `PacketCaptureService.reader_pid`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### BODY_CHANGED - `aethra_sec/services/packet_view.py` :: `PacketView.__init__`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/services/packet_view.py::PacketView.__init__
+++ current/aethra_sec/services/packet_view.py::PacketView.__init__
@@ -43,4 +43,9 @@
         # Owned by the view thread (or by whoever drives step() in a test).
         self._local = LocalAddresses()
+        #: Counts, from real captured frames, whose traffic is arriving.
+        #: Answers "can this capture point see other devices?" from
+        #: packets rather than from the host inventory, which records
+        #: that a host was seen once, not that it is visible now.
+        self.visibility = PeerVisibilityTracker()
         self._last_resolved = 0.0
         self._session_packets = 0
```

### BODY_CHANGED - `aethra_sec/services/packet_view.py` :: `PacketView.step`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/services/packet_view.py::PacketView.step
+++ current/aethra_sec/services/packet_view.py::PacketView.step
@@ -56,4 +56,9 @@
             with self._retained_lock:
                 for packet in batch:
+                    # Count whose traffic is arriving while we already have the
+                    # packet and the resolved local addresses in hand. Done
+                    # here so the visibility figures and the direction column
+                    # can never disagree about what "this host" means.
+                    self.visibility.observe(packet, local)
                     direction = classify(packet, local).value
                     try:
```

### BODY_CHANGED - `aethra_sec/ui/app.py` :: `MainWindow.__init__`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/app.py::MainWindow.__init__
+++ current/aethra_sec/ui/app.py::MainWindow.__init__
@@ -32,4 +32,8 @@
         self._badge_job_running = False
         self._badge_refreshed_at = 0.0
+        #: The unread-notification count is a query, so it is asked on a
+        #: worker. These keep one worker at a time; see refresh_notifications.
+        self._notification_count_running = False
+        self._notification_count_again = False
         #: How this console ended: "sign out" returns to the login window,
         #: "quit" exits the application. run_console() returns this.
```

### BODY_CHANGED - `aethra_sec/ui/app.py` :: `MainWindow._on_event`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/app.py::MainWindow._on_event
+++ current/aethra_sec/ui/app.py::MainWindow._on_event
@@ -10,5 +10,11 @@
             self._refresh_status_strip()
 
-        if event.type == EventType.NOTIFICATION_RAISED:
+        # NOTIFICATION_STORED, not NOTIFICATION_RAISED. The latter is a
+        # *request* for a notification - only the backup service publishes it -
+        # and the notification service converts it, along with Snort alerts,
+        # scans and subsystem failures, into a stored record. Sounding on the
+        # request meant a real IDS alert never sounded at all, because nothing
+        # ever requested one for it: the record was written and never announced.
+        if event.type == EventType.NOTIFICATION_STORED:
             payload = event.payload
             title = str(getattr(payload, "title", "Notification"))
@@ -19,5 +25,12 @@
             audio = getattr(self.context, "audio_alerts", None)
             if audio is not None:
-                audio.notify(payload)
+                queued = audio.notify(payload)
+                LOGGER.info(
+                    "[NOTIFY] Sound %s: notification_id=%s ref=%s:%s",
+                    "queued" if queued else "not played",
+                    getattr(payload, "notification_id", None),
+                    getattr(payload, "reference_type", "") or "-",
+                    getattr(payload, "reference_id", None) or "-",
+                )
             self.set_status(f"{title}: {message}")
             self._toasts.show(
```

### BODY_CHANGED - `aethra_sec/ui/app.py` :: `MainWindow._tick`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/app.py::MainWindow._tick
+++ current/aethra_sec/ui/app.py::MainWindow._tick
@@ -4,5 +4,14 @@
             return
         try:
-            self.context.event_bus.dispatch_all(limit_per_subscription=400)
+            # Budgeted, because this runs on the Tk thread. During a real
+            # Nmap port scan the capture pipeline raised events faster than
+            # they could be handled and this call alone held the main loop for
+            # up to 2,007 ms, which is the interface not answering the OS.
+            # Events not reached stay queued and are handled on the next tick;
+            # none is discarded here.
+            self.context.event_bus.dispatch_all(
+                limit_per_subscription=400,
+                time_budget_ms=self.EVENT_BUDGET_MS,
+            )
         except Exception:  # noqa: BLE001
             LOGGER.exception("Event dispatch failed.")
```

### BODY_CHANGED - `aethra_sec/ui/app.py` :: `MainWindow.refresh_notifications`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/app.py::MainWindow.refresh_notifications
+++ current/aethra_sec/ui/app.py::MainWindow.refresh_notifications
@@ -1,12 +1,50 @@
     def refresh_notifications(self) -> None:
-        """Update the unread badge on the bell."""
+        """Update the unread badge on the bell, counting off the Tk thread.
+
+        The count is a database query, and this is called from ``_on_event``
+        for every stored notification. Running it inline put a query on the Tk
+        thread on the busiest path there is: during a real Nmap port scan the
+        capture pipeline raises notifications in bursts, and each one blocked
+        the main loop for the duration of a round trip.
+
+        Single-flight, because a burst would otherwise start a thread per
+        notification to ask the same question. A refresh that arrives while one
+        is in flight sets a flag and the worker asks once more on the way out,
+        so the badge still ends up showing the latest count.
+        """
         service = self.context.notifications
         if service is None:
             return
-        try:
-            count = service.unread_count(self.session)
-        except Exception:  # noqa: BLE001 - the bell must not break the shell
+        if self._notification_count_running:
+            self._notification_count_again = True
             return
-        self._notification_badge.set_count(count)
-        if self._notification_panel.winfo_ismapped():
-            self._populate_notifications()
+
+        session = self.session
+
+        def runner() -> None:
+            while True:
+                try:
+                    count = service.unread_count(session)
+                except Exception:  # noqa: BLE001 - the bell must not break the shell
+                    count = None
+
+                def deliver(value: int | None = count) -> None:
+                    self._notification_count_running = False
+                    if self._closing or value is None:
+                        return
+                    self._notification_badge.set_count(value)
+                    if self._notification_panel.winfo_ismapped():
+                        self._populate_notifications()
+
+                if not self._notification_count_again:
+                    dispatch.post(deliver)
+                    return
+                # Another refresh was requested while this one was out; ask
+                # again rather than deliver a count already known to be stale.
+                self._notification_count_again = False
+
+        self._notification_count_running = True
+        self._notification_count_again = False
+        threading.Thread(
+            target=runner, name="notification-count", daemon=True
+        ).start()
```

### BODY_CHANGED - `aethra_sec/ui/app.py` :: `run_console`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/app.py::run_console
+++ current/aethra_sec/ui/app.py::run_console
@@ -11,4 +11,11 @@
     window.refresh_notifications()
     window._refresh_status_strip()  # noqa: SLF001 - initial paint
-    root.mainloop()
+    # Off unless AETHRA_FLOOD_PROBE is set, and it observes only: no capture
+    # setting, queue or counter is touched by it. See diagnostics/flood_probe.
+    probe = flood_probe.install(root, context, window)
+    try:
+        root.mainloop()
+    finally:
+        if probe is not None:
+            probe.stop()
     return window.outcome
```

### ADDED_FUNCTION - `aethra_sec/ui/app.py` :: `MainWindow.refresh_notifications.runner`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### BODY_CHANGED - `aethra_sec/ui/screens/about.py` :: `HelpScreen._monitoring`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/screens/about.py::HelpScreen._monitoring
+++ current/aethra_sec/ui/screens/about.py::HelpScreen._monitoring
@@ -31,5 +31,5 @@
   stored. CAPTURED keeps counting; DISPLAYED says how many packets match.
     Presets     All Traffic, Incoming, Outgoing, Transit; HTTP, HTTPS/TLS,
-                Web, Sites, TCP, UDP, ICMP, DNS, ARP. A direction and a
+                Sites, TCP, UDP, ICMP, DNS, ARP. A direction and a
                 protocol combine. Pressing the active protocol again clears it.
     IP, Port    searched against captured packets as source, destination or
```

### BODY_CHANGED - `aethra_sec/ui/screens/traffic.py` :: `TrafficScreen._build_filter_bar`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/screens/traffic.py::TrafficScreen._build_filter_bar
+++ current/aethra_sec/ui/screens/traffic.py::TrafficScreen._build_filter_bar
@@ -39,9 +39,4 @@
         )
         Tooltip(self._protocol_buttons["HTTPS"], HTTPS_NOTICE)
-        Tooltip(
-            self._protocol_buttons["WEB"],
-            "HTTP and HTTPS/TLS together, each identified by the protocol TShark "
-            "decoded - never by port number.",
-        )
         Tooltip(
             self._protocol_buttons["SITES"],
```

### BODY_CHANGED - `aethra_sec/ui/screens/users.py` :: `UsersScreen._apply`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/screens/users.py::UsersScreen._apply
+++ current/aethra_sec/ui/screens/users.py::UsersScreen._apply
@@ -7,4 +7,5 @@
                 {
                     "_id": user.id,
+                    "id": user.id,
                     "username": user.username,
                     "full_name": user.full_name or "-",
@@ -16,4 +17,8 @@
                     "last_host": user.last_login_host or "-",
                     "created": format_local(user.created_at, "%d %b %Y"),
+                    # The stored value, or a dash. format_local already
+                    # renders None as a dash, so a never-edited account is
+                    # not given a date it never earned.
+                    "date_modified": format_local(user.date_modified),
                 }
                 for user in user_list
```

### BODY_CHANGED - `aethra_sec/ui/screens/vulnerabilities.py` :: `VulnerabilitiesScreen.on_tick`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/screens/vulnerabilities.py::VulnerabilitiesScreen.on_tick
+++ current/aethra_sec/ui/screens/vulnerabilities.py::VulnerabilitiesScreen.on_tick
@@ -7,4 +7,4 @@
         if not on_automation_tab or self._automation_loading:
             return
-        if (time.monotonic() - self._automation_refreshed_at) >= self.AUTOMATION_REFRESH_SECONDS:
+        if (time.monotonic() - self._automation_refreshed_at) >= self._automation_interval():
             self._refresh_automation()
```

### BODY_CHANGED - `aethra_sec/ui/screens/vulnerabilities.py` :: `VulnerabilitiesScreen._stop_scan`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/screens/vulnerabilities.py::VulnerabilitiesScreen._stop_scan
+++ current/aethra_sec/ui/screens/vulnerabilities.py::VulnerabilitiesScreen._stop_scan
@@ -7,5 +7,14 @@
         self.run_async(
             lambda: nmap.stop_scan(session, self._active_scan_id or 0),
-            lambda _r: self.status("Stop requested; the scan ends after the current step."),
+            # Says what actually happens: the runner holds the process handle
+            # and kills it, so the scan stops now. The old wording promised
+            # "after the current step", which was true only of the superseded
+            # python-nmap path that could not be interrupted at all.
+            lambda stopped: self.status(
+                "Scan stopped. Nmap was terminated and the assessment is "
+                "recorded as CANCELLED; partial results are not stored."
+                if stopped else
+                "That scan is no longer running, so there was nothing to stop."
+            ),
             name="scan-stop",
         )
```

### ADDED_FUNCTION - `aethra_sec/ui/screens/vulnerabilities.py` :: `VulnerabilitiesScreen._automation_interval`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### BODY_CHANGED - `aethra_sec/ui/widgets/chips.py` :: `Chip.__init__`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/widgets/chips.py::Chip.__init__
+++ current/aethra_sec/ui/widgets/chips.py::Chip.__init__
@@ -44,4 +44,6 @@
         self._pulse_job: str | None = None
         self._dot_item: int | None = None
+        #: Built on first use and kept; see :meth:`_measure`.
+        self._measurer: Any = None
 
         if on_click is not None:
```

### BODY_CHANGED - `aethra_sec/ui/widgets/chips.py` :: `Chip.set_value`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/widgets/chips.py::Chip.set_value
+++ current/aethra_sec/ui/widgets/chips.py::Chip.set_value
@@ -1,4 +1,16 @@
     def set_value(self, text: str, colour: str | None = None) -> None:
-        """Update the label and, optionally, the accent colour."""
+        """Update the label and, optionally, the accent colour.
+
+        Returns immediately when neither has changed. The header repaints the
+        whole status strip on every UI tick so it is correct even before the
+        first status change is published, which means almost every call asks
+        for the chip it is already showing. Measured with capture running, that
+        unconditional repaint cost 441-568 ms of the Tk thread per tick, worst
+        1,271 ms - the application froze for a second or more, recovered, and
+        froze again on the next tick. Redrawing only on a real change costs
+        nothing when nothing changed.
+        """
+        if text == self._text and (not colour or colour == self._colour):
+            return
         self._text = text
         if colour:
```

### BODY_CHANGED - `aethra_sec/ui/widgets/chips.py` :: `Chip._measure`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/widgets/chips.py::Chip._measure
+++ current/aethra_sec/ui/widgets/chips.py::Chip._measure
@@ -1,8 +1,18 @@
     def _measure(self) -> None:
-        """Size the canvas to fit the text."""
+        """Size the canvas to fit the text.
+
+        The measuring font is built once and kept. It used to be constructed
+        on every call, and each construction allocates a Tcl font command that
+        Tk must later reclaim - paid once per chip per repaint, on the Tk
+        thread. Caching it is free: the font never changes for the life of the
+        widget, because a theme change rebuilds the chip.
+        """
         try:
-            from tkinter import font as tkfont
+            measurer = self._measurer
+            if measurer is None:
+                from tkinter import font as tkfont
 
-            width = tkfont.Font(font=self._font).measure(self._text or "")
+                measurer = self._measurer = tkfont.Font(root=self, font=self._font)
+            width = measurer.measure(self._text or "")
         except Exception:  # noqa: BLE001 - font measurement is best effort
             width = 8 * len(self._text or "")
```

### BODY_CHANGED - `aethra_sec/ui/widgets/chips.py` :: `StatusChip.set_text`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/widgets/chips.py::StatusChip.set_text
+++ current/aethra_sec/ui/widgets/chips.py::StatusChip.set_text
@@ -1,4 +1,11 @@
     def set_text(self, text: str, *, colour: str = "") -> None:
-        """Replace the label and colour without changing the bound state."""
+        """Replace the label and colour without changing the bound state.
+
+        Guarded like :meth:`set_value`: this is the call the header's status
+        strip makes for every chip on every UI tick, so it is almost always
+        asked for what the chip already shows.
+        """
+        if text == self._text and (not colour or colour == self._colour):
+            return
         self._text = text
         if colour:
```

### BODY_CHANGED - `aethra_sec/ui/widgets/chips.py` :: `CountBadge.__init__`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/widgets/chips.py::CountBadge.__init__
+++ current/aethra_sec/ui/widgets/chips.py::CountBadge.__init__
@@ -17,3 +17,8 @@
         self._size = size
         self._font = fonts.small_bold if fonts else ("TkDefaultFont", 8, "bold")
-        self._count = 0
+        #: -1 means "never painted", so the first set_count always draws -
+        #: including the first zero, which is what hides the badge.
+        self._count = -1
+        #: Built on first use and kept; constructing a font per paint
+        #: allocates a Tcl command each time.
+        self._measurer: Any = None
```

### BODY_CHANGED - `aethra_sec/ui/widgets/chips.py` :: `CountBadge.set_surface`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/ui/widgets/chips.py::CountBadge.set_surface
+++ current/aethra_sec/ui/widgets/chips.py::CountBadge.set_surface
@@ -12,3 +12,3 @@
         except tk.TclError:  # pragma: no cover - torn down
             return
-        self.set_count(self._count, colour=self._colour)
+        self.set_count(self._count, colour=self._colour, force=True)
```

### SIGNATURE_CHANGED - `aethra_sec/ui/widgets/chips.py` :: `CountBadge.set_count`

- severity: CRITICAL
- baseline: def set_count(self, count: int, colour: str | None=None)
current : def set_count(self, count: int, colour: str | None=None, *, force: bool=False)

```diff
--- baseline/aethra_sec/ui/widgets/chips.py::CountBadge.set_count
+++ current/aethra_sec/ui/widgets/chips.py::CountBadge.set_count
@@ -1,5 +1,20 @@
-    def set_count(self, count: int, colour: str | None = None) -> None:
-        """Show a count, hiding the badge when it is zero."""
-        self._count = max(0, int(count))
+    def set_count(
+        self, count: int, colour: str | None = None, *, force: bool = False
+    ) -> None:
+        """Show a count, hiding the badge when it is zero.
+
+        Returns immediately when the count and colour are unchanged. The
+        sidebar badges are refreshed on every UI tick, so this is nearly
+        always asked for the number already on screen; repainting it anyway
+        cost 305 ms of the Tk thread per tick with capture running.
+        """
+        count = max(0, int(count))
+        if (
+            not force
+            and count == self._count
+            and (not colour or colour == self._colour)
+        ):
+            return
+        self._count = count
         if colour:
             self._colour = colour
@@ -11,7 +26,10 @@
         text = "99+" if self._count > 99 else str(self._count)
         try:
-            from tkinter import font as tkfont
+            measurer = self._measurer
+            if measurer is None:
+                from tkinter import font as tkfont
 
-            text_width = tkfont.Font(font=self._font).measure(text)
+                measurer = self._measurer = tkfont.Font(root=self, font=self._font)
+            text_width = measurer.measure(text)
         except Exception:  # noqa: BLE001
             text_width = 8 * len(text)
```

### BODY_CHANGED - `aethra_sec/utils/net.py` :: `list_interfaces`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/utils/net.py::list_interfaces
+++ current/aethra_sec/utils/net.py::list_interfaces
@@ -12,8 +12,6 @@
         return []
 
-    try:
-        addresses = psutil.net_if_addrs()
-        stats = psutil.net_if_stats()
-    except Exception:
+    addresses, stats = adapter_tables()
+    if not addresses:
         return []
 
```

### BODY_CHANGED - `aethra_sec/utils/net.py` :: `local_ipv4_networks`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/utils/net.py::local_ipv4_networks
+++ current/aethra_sec/utils/net.py::local_ipv4_networks
@@ -12,10 +12,7 @@
     """
     networks: list[ipaddress.IPv4Network] = []
+    addresses, _stats = adapter_tables()
     try:
-        import psutil
-    except ImportError:  # pragma: no cover - psutil is a declared dependency
-        return ()
-    try:
-        for entries in psutil.net_if_addrs().values():
+        for entries in addresses.values():
             for entry in entries:
                 if entry.family != socket.AF_INET or not entry.netmask:
```

### BODY_CHANGED - `aethra_sec/utils/net.py` :: `service_name_for_port`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/aethra_sec/utils/net.py::service_name_for_port
+++ current/aethra_sec/utils/net.py::service_name_for_port
@@ -4,5 +4,6 @@
         return COMMON_PORT_SERVICES[port]
     try:
-        return socket.getservbyport(port, protocol.lower())
-    except (OSError, TypeError, ValueError):
+        number = int(port)
+    except (TypeError, ValueError):
         return ""
+    return _system_service_name(number, (protocol or "tcp").lower())
```

### ADDED_FUNCTION - `aethra_sec/utils/net.py` :: `invalidate_adapter_cache`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### ADDED_FUNCTION - `aethra_sec/utils/net.py` :: `adapter_tables`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### ADDED_FUNCTION - `aethra_sec/utils/net.py` :: `local_ipv4_addresses`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### ADDED_FUNCTION - `aethra_sec/utils/net.py` :: `_system_service_name`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### BODY_CHANGED - `tests/test_capture_evidence_ring.py` :: `TestRotationIsFollowed.test_rotation_is_only_followed_when_a_ring_is_configured`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/tests/test_capture_evidence_ring.py::TestRotationIsFollowed.test_rotation_is_only_followed_when_a_ring_is_configured
+++ current/tests/test_capture_evidence_ring.py::TestRotationIsFollowed.test_rotation_is_only_followed_when_a_ring_is_configured
@@ -4,3 +4,3 @@
 
         body = inspect.getsource(field_reader.FieldCaptureReader._run)
-        assert "if self._ring_files:" in body
+        assert "if self._ring_active:" in body
```

### ADDED_FUNCTION - `tests/test_capture_evidence_ring.py` :: `TestTheFirstRingFileIsFound.test_a_ring_reader_does_not_start_on_the_base_path`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### ADDED_FUNCTION - `tests/test_capture_evidence_ring.py` :: `TestTheFirstRingFileIsFound.test_the_first_packet_resolves_the_first_ring_file`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### ADDED_FUNCTION - `tests/test_capture_evidence_ring.py` :: `TestTheFirstRingFileIsFound.test_resolution_is_retried_until_the_file_appears`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### ADDED_FUNCTION - `tests/test_capture_evidence_ring.py` :: `TestTheFirstRingFileIsFound.test_a_single_file_capture_still_uses_the_base_path`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### ADDED_FUNCTION - `tests/test_capture_evidence_ring.py` :: `TestTheFirstRingFileIsFound.test_one_bound_alone_is_not_a_ring`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### BODY_CHANGED - `tests/test_display_filter.py` :: `TestPresetsAndComposition.test_every_required_preset_exists`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/tests/test_display_filter.py::TestPresetsAndComposition.test_every_required_preset_exists
+++ current/tests/test_display_filter.py::TestPresetsAndComposition.test_every_required_preset_exists
@@ -1,3 +1,3 @@
     def test_every_required_preset_exists(self) -> None:
-        assert {p.key for p in PROTOCOL_PRESETS} == {"HTTP", "HTTPS", "WEB", "SITES", "TCP", "UDP", "ICMP", "DNS", "ARP"}
+        assert {p.key for p in PROTOCOL_PRESETS} == {"HTTP", "HTTPS", "SITES", "TCP", "UDP", "ICMP", "DNS", "ARP"}
         assert {p.key for p in DIRECTION_PRESETS} == {"INCOMING", "OUTGOING", "TRANSIT"}
```

### MISSING_FUNCTION - `tests/test_display_filter.py` :: `TestPresetsAndComposition.test_web_is_http_plus_tls`

- severity: CRITICAL
- Present in the baseline, absent from the current file.

### BODY_CHANGED - `tests/test_display_filter.py` :: `TestPresetsAndComposition.test_a_disjunctive_preset_is_parenthesised_when_combined`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/tests/test_display_filter.py::TestPresetsAndComposition.test_a_disjunctive_preset_is_parenthesised_when_combined
+++ current/tests/test_display_filter.py::TestPresetsAndComposition.test_a_disjunctive_preset_is_parenthesised_when_combined
@@ -1,3 +1,4 @@
     def test_a_disjunctive_preset_is_parenthesised_when_combined(self) -> None:
-        composed = compose_filter(FilterRequest(protocol="WEB", direction="OUTGOING"))
-        assert composed.expression == "(http || tls) && direction == outgoing"
+        """Without the brackets the && would bind tighter than the ||."""
+        composed = compose_filter(FilterRequest(protocol="ICMP", direction="OUTGOING"))
+        assert composed.expression == "(icmp || icmpv6) && direction == outgoing"
```

### BODY_CHANGED - `tests/test_display_filter.py` :: `TestPresetsAndComposition.test_the_https_views_are_marked_encrypted`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/tests/test_display_filter.py::TestPresetsAndComposition.test_the_https_views_are_marked_encrypted
+++ current/tests/test_display_filter.py::TestPresetsAndComposition.test_the_https_views_are_marked_encrypted
@@ -1,5 +1,5 @@
     def test_the_https_views_are_marked_encrypted(self) -> None:
         assert compose_filter(FilterRequest(protocol="HTTPS")).encrypted
-        assert compose_filter(FilterRequest(protocol="WEB")).encrypted
+        assert compose_filter(FilterRequest(protocol="SITES")).encrypted
         assert compose_filter(FilterRequest(expression="tls.handshake.type == 1")).encrypted
         assert not compose_filter(FilterRequest(protocol="HTTP")).encrypted
```

### MISSING_FUNCTION - `tests/test_display_filter.py` :: `TestTlsSegmentsTheTlsDissectorHandled.test_it_is_also_counted_as_https_and_web`

- severity: CRITICAL
- Present in the baseline, absent from the current file.

### MISSING_FUNCTION - `tests/test_display_filter.py` :: `TestTlsTheDnsDissectorParsed.test_it_is_in_neither_the_https_nor_the_web_view`

- severity: CRITICAL
- Present in the baseline, absent from the current file.

### ADDED_FUNCTION - `tests/test_display_filter.py` :: `TestPresetsAndComposition.test_the_web_view_is_gone`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### ADDED_FUNCTION - `tests/test_display_filter.py` :: `TestTlsSegmentsTheTlsDissectorHandled.test_it_is_also_counted_as_https`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### ADDED_FUNCTION - `tests/test_display_filter.py` :: `TestTlsTheDnsDissectorParsed.test_it_is_not_in_the_https_view`

- severity: INFO
- Not in the baseline. This is only a note, not a fault.

### BODY_CHANGED - `tests/test_flood_resilience.py` :: `TestDisplayViews.test_the_required_views_are_offered`

- severity: WARNING
- The body differs from the baseline.

```diff
--- baseline/tests/test_flood_resilience.py::TestDisplayViews.test_the_required_views_are_offered
+++ current/tests/test_flood_resilience.py::TestDisplayViews.test_the_required_views_are_offered
@@ -3,4 +3,4 @@
         assert {key for key, _label in DIRECTION_BUTTONS} == {"", "INCOMING", "OUTGOING", "TRANSIT"}
         assert {key for key, _label in PROTOCOL_BUTTONS} == {
-            "HTTP", "HTTPS", "WEB", "SITES", "TCP", "UDP", "ICMP", "DNS", "ARP",
+            "HTTP", "HTTPS", "SITES", "TCP", "UDP", "ICMP", "DNS", "ARP",
         }
```
