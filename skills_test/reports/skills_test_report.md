# AETHRA-SEC Skills Test Report

- **Run:** 2026-10-06T15:55:13
- **Baseline recorded:** 2026-09-22T17:24:32+00:00
- **Baseline files:** 251
- **Version control:** none (no Git repository present)
- **Result:** PASS

## Stages

| Stage | Result | Detail |
|---|---|---|
| Environment | PASS | Python 3.13.5 |
| Dependencies | PASS | all required packages import |
| Code Integrity | FAIL | 28 changed, 0 deleted, 6 critical |
| Behavioural Tests | PASS | 53 behavioural tests passed |
| Database | PASS | server reachable |
| Module Imports | SKIP |  |
| Code Recovery | NONE NEEDED |  |

## Behavioural tests

- total: 53
- failed: 0

## All differences from the baseline

| Severity | Kind | File | Function |
|---|---|---|---|
| WARNING | BODY_CHANGED | `aethra_sec/analytics/traffic_direction.py` | `os_interfaces` |
| CRITICAL | SIGNATURE_CHANGED | `aethra_sec/core/event_bus.py` | `EventBus.dispatch_all` |
| WARNING | BODY_CHANGED | `aethra_sec/database/repositories/users.py` | `UserRepository._map_user` |
| WARNING | BODY_CHANGED | `aethra_sec/database/repositories/users.py` | `UserRepository.update_profile` |
| WARNING | BODY_CHANGED | `aethra_sec/database/repositories/users.py` | `UserRepository.set_password` |
| WARNING | BODY_CHANGED | `aethra_sec/database/repositories/users.py` | `UserRepository.set_active` |
| CRITICAL | SIGNATURE_CHANGED | `aethra_sec/integrations/nmap/runner.py` | `probe_nmap` |
| WARNING | BODY_CHANGED | `aethra_sec/integrations/pyshark_capture/field_reader.py` | `parse_line` |
| WARNING | BODY_CHANGED | `aethra_sec/integrations/pyshark_capture/field_reader.py` | `FieldCaptureReader.__init__` |
| WARNING | BODY_CHANGED | `aethra_sec/integrations/pyshark_capture/field_reader.py` | `FieldCaptureReader._command` |
| WARNING | BODY_CHANGED | `aethra_sec/integrations/pyshark_capture/field_reader.py` | `FieldCaptureReader._follow_rotation` |
| WARNING | BODY_CHANGED | `aethra_sec/integrations/pyshark_capture/field_reader.py` | `FieldCaptureReader._run` |
| WARNING | BODY_CHANGED | `aethra_sec/services/assessment_queue.py` | `AssessmentQueueService._is_own_address` |
| WARNING | BODY_CHANGED | `aethra_sec/services/assessment_queue.py` | `AssessmentQueueService.statistics` |
| WARNING | BODY_CHANGED | `aethra_sec/services/nmap_service.py` | `NmapService.stop_scan` |
| WARNING | BODY_CHANGED | `aethra_sec/services/notification_service.py` | `NotificationService._store` |
| WARNING | BODY_CHANGED | `aethra_sec/services/packet_capture.py` | `PacketCaptureService.__init__` |
| WARNING | BODY_CHANGED | `aethra_sec/services/packet_capture.py` | `PacketCaptureService._handle_packet` |
| WARNING | BODY_CHANGED | `aethra_sec/services/packet_view.py` | `PacketView.__init__` |
| WARNING | BODY_CHANGED | `aethra_sec/services/packet_view.py` | `PacketView.step` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/app.py` | `MainWindow.__init__` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/app.py` | `MainWindow._on_event` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/app.py` | `MainWindow._tick` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/app.py` | `MainWindow.refresh_notifications` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/app.py` | `run_console` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/screens/about.py` | `HelpScreen._monitoring` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/screens/traffic.py` | `TrafficScreen._build_filter_bar` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/screens/users.py` | `UsersScreen._apply` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/screens/vulnerabilities.py` | `VulnerabilitiesScreen.on_tick` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/screens/vulnerabilities.py` | `VulnerabilitiesScreen._stop_scan` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/widgets/chips.py` | `Chip.__init__` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/widgets/chips.py` | `Chip.set_value` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/widgets/chips.py` | `Chip._measure` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/widgets/chips.py` | `StatusChip.set_text` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/widgets/chips.py` | `CountBadge.__init__` |
| WARNING | BODY_CHANGED | `aethra_sec/ui/widgets/chips.py` | `CountBadge.set_surface` |
| CRITICAL | SIGNATURE_CHANGED | `aethra_sec/ui/widgets/chips.py` | `CountBadge.set_count` |
| WARNING | BODY_CHANGED | `aethra_sec/utils/net.py` | `list_interfaces` |
| WARNING | BODY_CHANGED | `aethra_sec/utils/net.py` | `local_ipv4_networks` |
| WARNING | BODY_CHANGED | `aethra_sec/utils/net.py` | `service_name_for_port` |
| WARNING | BODY_CHANGED | `tests/test_capture_evidence_ring.py` | `TestRotationIsFollowed.test_rotation_is_only_followed_when_a_ring_is_configured` |
| WARNING | BODY_CHANGED | `tests/test_display_filter.py` | `TestPresetsAndComposition.test_every_required_preset_exists` |
| CRITICAL | MISSING_FUNCTION | `tests/test_display_filter.py` | `TestPresetsAndComposition.test_web_is_http_plus_tls` |
| WARNING | BODY_CHANGED | `tests/test_display_filter.py` | `TestPresetsAndComposition.test_a_disjunctive_preset_is_parenthesised_when_combined` |
| WARNING | BODY_CHANGED | `tests/test_display_filter.py` | `TestPresetsAndComposition.test_the_https_views_are_marked_encrypted` |
| CRITICAL | MISSING_FUNCTION | `tests/test_display_filter.py` | `TestTlsSegmentsTheTlsDissectorHandled.test_it_is_also_counted_as_https_and_web` |
| CRITICAL | MISSING_FUNCTION | `tests/test_display_filter.py` | `TestTlsTheDnsDissectorParsed.test_it_is_in_neither_the_https_nor_the_web_view` |
| WARNING | BODY_CHANGED | `tests/test_flood_resilience.py` | `TestDisplayViews.test_the_required_views_are_offered` |

## Manual repair

This system never edits source. For each diagnosis above: open the
file, find the function, paste the known-good code, save, and run
`test.bat` again.
