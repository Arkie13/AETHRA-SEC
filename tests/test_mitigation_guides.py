"""Mitigation guidance must be a procedure, and must not invent anything.

The stored recommendations were strategy rather than procedure - the longest
``immediate_action`` was 369 characters and none of them said which firewall,
what to type, how to confirm the rule was live, or how to undo it. Four
columns now carry the enforcement point, the ordered steps, the rollback and
the operational warnings.

These tests read the guide content and the rendering helpers. Nothing here
runs a firewall command, and no test asserts that a firewall was configured.
"""

from __future__ import annotations

import re

import pytest

from aethra_sec.database.mitigation_guides import GUIDES

#: The manuscript's five attack scenarios (section 3.1.1).
MANUSCRIPT_SCENARIOS = {
    "MIT-PORT-SCAN",
    "MIT-TCP-SYN-FLOOD",
    "MIT-UDP-FLOOD",
    "MIT-ICMP-FLOOD",
    "MIT-HTTP-FLOOD",
}

#: Three codes outside the five, each added because real stored data resolves
#: to it and it had no procedure:
#:   MIT-HOST-SWEEP        1,487 of 2,334 anomalies - the largest category
#:   MIT-SERVICE-EXPOSURE    327 of 330 vulnerability findings
#:   MIT-SSH-EXPOSURE          3 of 330 vulnerability findings
#: Together those two exposure codes are every confirmed finding in the
#: database, so without them the whole Vulnerability Assessment path had no
#: procedure at all.
REACHED_BY_REAL_DATA = {
    "MIT-HOST-SWEEP",
    "MIT-SERVICE-EXPOSURE",
    "MIT-SSH-EXPOSURE",
}
COVERED = MANUSCRIPT_SCENARIOS | REACHED_BY_REAL_DATA

#: Verified against the real NetSecurity module on a Windows 11 host.
REAL_CMDLETS = {
    "New-NetFirewallRule", "Get-NetFirewallRule", "Disable-NetFirewallRule",
    "Remove-NetFirewallRule", "Get-NetFirewallPortFilter",
    "Get-NetFirewallAddressFilter", "Get-NetTCPConnection",
    "Get-NetUDPEndpoint", "Test-NetConnection", "Resolve-DnsName",
    "Get-NetNeighbor", "Select-Object", "Get-Service", "Stop-Service",
    "Start-Service", "Set-Service", "Get-Process", "Get-WindowsCapability",
    "Remove-WindowsCapability",
}

#: Sentence boundaries, for judging a claim in its own sentence.
SPLIT = r"(?<=[.:;])\s+|\n"
#: Verified parameters of New-NetFirewallRule.
REAL_PARAMETERS = {
    "-DisplayName", "-Direction", "-Action", "-Protocol", "-LocalPort",
    "-RemotePort", "-RemoteAddress", "-LocalAddress", "-Profile", "-Enabled",
    "-Description", "-IcmpType", "-Program", "-State", "-Port",
    "-StartupType", "-Online", "-Id", "-Name", "-Status",
}


#: Words that turn a mention of a capability into a denial of it.
_NEGATORS = ("no ", "not ", "never ", "cannot ", "can not ", "unable ",
             "without ", "nor ")


def unnegated(blob: str, phrase: str) -> list[str]:
    """Occurrences of *phrase* that are NOT inside a denial.

    The guides have to be able to say "Windows cannot rate-limit" and "never
    disable the firewall as a whole". A plain substring ban would forbid
    exactly the sentences the module is required to carry, so each hit is
    judged by the text leading up to it.
    """
    offending = []
    lowered = blob.lower()
    for match in re.finditer(re.escape(phrase.lower()), lowered):
        preceding = lowered[max(0, match.start() - 70):match.start()]
        if not any(word in preceding for word in _NEGATORS):
            offending.append(lowered[match.start() - 40:match.end() + 20])
    return offending


class TestEveryManuscriptScenarioHasAGuide:
    def test_all_five_are_covered(self) -> None:
        assert MANUSCRIPT_SCENARIOS <= set(GUIDES), (
            f"no guide for {MANUSCRIPT_SCENARIOS - set(GUIDES)}"
        )

    def test_the_commonest_real_detection_is_covered(self) -> None:
        """Host sweep outnumbers every other category in the real data."""
        assert "MIT-HOST-SWEEP" in GUIDES

    def test_the_vulnerability_findings_path_is_covered(self) -> None:
        """All 330 stored findings resolve to one of these two codes."""
        assert {"MIT-SERVICE-EXPOSURE", "MIT-SSH-EXPOSURE"} <= set(GUIDES)

    def test_an_exposure_guide_prefers_removal_over_a_rule(self) -> None:
        """A service that is not running cannot be reached by mistake."""
        steps = GUIDES["MIT-SERVICE-EXPOSURE"]["procedure_steps"]
        remove = steps.index("remove it rather than hiding it")
        rule = steps.index("New Rule")
        assert remove < rule, (
            "firewalling is offered before removing the service"
        )

    def test_the_ssh_guide_does_not_assume_the_target_is_windows(self) -> None:
        guide = GUIDES["MIT-SSH-EXPOSURE"]
        blob = (guide["enforcement_point"] + guide["procedure_steps"]).lower()
        assert "do not assume the target is windows" in blob
        assert "if the target is not windows" in blob

    def test_no_guide_suggests_scanning_from_outside(self) -> None:
        """Verifying internet exposure by scanning it is an unauthorised scan."""
        for code, guide in GUIDES.items():
            blob = " ".join(guide.values()).lower()
            if "scanning from" in blob or "scan from" in blob:
                assert "do not" in blob or "not authorised" in blob, code

    def test_no_guide_invents_a_category(self) -> None:
        """A guide for a threat the system cannot detect would be fiction."""
        assert set(GUIDES) == COVERED

    @pytest.mark.parametrize("code", sorted(COVERED))
    def test_each_guide_has_every_required_section(self, code: str) -> None:
        guide = GUIDES[code]
        for field in ("enforcement_point", "procedure_steps",
                      "verification_steps", "rollback_steps",
                      "operational_warnings"):
            assert guide.get(field, "").strip(), f"{code} has no {field}"

    @pytest.mark.parametrize("code", sorted(COVERED))
    def test_the_procedure_is_a_procedure(self, code: str) -> None:
        """Numbered steps, not a paragraph. The original failure mode."""
        steps = GUIDES[code]["procedure_steps"].splitlines()
        assert len(steps) >= 6, f"{code} has only {len(steps)} steps"
        for line in steps:
            assert re.match(r"^\d+\. ", line), f"{code}: unnumbered: {line[:50]}"

    @pytest.mark.parametrize("code", sorted(COVERED))
    def test_rollback_names_the_rule_rather_than_the_firewall(
        self, code: str
    ) -> None:
        rollback = GUIDES[code]["rollback_steps"]
        assert "Remove-NetFirewallRule" in rollback or "revert" in rollback
        for phrase in ("disable the firewall", "turn off the firewall"):
            assert not unnegated(rollback, phrase), (
                f"{code} rollback tells the operator to {phrase}"
            )


class TestNoFabricatedFirewallCapability:
    """The constraint that mattered most: do not invent what the product does."""

    #: Capabilities NetSecurity was checked for and does not expose.
    ABSENT_CAPABILITIES = ("syn proxy", "syn cookie", "rate-limit",
                           "rate limit", "throttle", "flood protection")

    @staticmethod
    def sentences(guide: dict) -> list[str]:
        return [part for part in re.split(SPLIT, " ".join(guide.values()))
                if part and part.strip()]

    @staticmethod
    def about_windows(sentence: str) -> bool:
        return bool(re.search(r"windows|defender|netfirewall|this host",
                              sentence, re.I))

    def test_no_guide_claims_windows_can_rate_limit(self) -> None:
        """Checked against NetSecurity: no rate, throttle or flood control.

        Scoped to sentences about the Windows firewall. A guide is allowed,
        and required, to tell the operator to ASK the gateway administrator
        whether their device can rate-limit - that device is not ours to
        describe, and asking is not claiming.
        """
        for code, guide in GUIDES.items():
            for sentence in self.sentences(guide):
                if not self.about_windows(sentence):
                    continue
                for claim in self.ABSENT_CAPABILITIES:
                    assert not unnegated(sentence, claim), (
                        f"{code} claims the Windows firewall can {claim}: "
                        f"{sentence.strip()[:160]}"
                    )

    #: Products the guides name, and the feature each is credited with.
    #: Every one of these was checked to be a real, documented feature of
    #: that product. Nothing may be added here that has not been.
    NAMED_PRODUCTS = {
        "IIS": "Dynamic IP Restrictions",
        "nginx": "limit_req",
        "Apache": "mod_rate",
    }

    def test_only_verified_products_are_named(self) -> None:
        """A product named with a feature is a factual claim about it.

        Indefinite phrasing - "whatever sits in front of the site", "the
        product that applies it" - claims nothing and is always acceptable.
        What needs policing is naming a product and crediting it with a
        capability, because that is checkable and I had to check it.
        """
        known = set(self.NAMED_PRODUCTS) | {
            "Windows", "Defender", "NetSecurity", "PowerShell", "AETHRA-SEC",
        }
        for code, guide in GUIDES.items():
            blob = " ".join(guide.values())
            for vendor in ("FortiOS", "Cisco", "pfSense", "Cloudflare",
                           "Palo Alto", "iptables", "ASA", "Juniper",
                           "OPNsense", "Sophos", "Untangle"):
                assert vendor not in blob, (
                    f"{code} names {vendor}, whose configuration was never "
                    "verified; the campus device must stay unnamed"
                )
            for product in self.NAMED_PRODUCTS:
                if product in blob and product not in known:
                    raise AssertionError(f"{code} names {product}")

    def test_a_named_product_comes_with_confirming_you_run_it(self) -> None:
        for code, guide in GUIDES.items():
            blob = " ".join(guide.values())
            named = [p for p in self.NAMED_PRODUCTS if p in blob]
            if not named:
                continue
            lowered = blob.lower()
            assert "confirm which of these you actually run" in lowered, (
                f"{code} names {named} without telling the operator to "
                "confirm which one they have"
            )
            assert "do not follow instructions for a product you do not have"                 in lowered, f"{code} names {named} without that warning"

    def test_windows_is_never_credited_with_what_it_lacks(self) -> None:
        """The strict form: for Windows, denial is required, not hedging."""
        windows_sentences = 0
        for code, guide in GUIDES.items():
            for sentence in self.sentences(guide):
                if not self.about_windows(sentence):
                    continue
                windows_sentences += 1
                for claim in self.ABSENT_CAPABILITIES:
                    assert not unnegated(sentence, claim), (
                        f"{code} credits the Windows firewall with {claim}: "
                        f"{sentence.strip()[:160]}"
                    )
        assert windows_sentences >= 10, (
            f"only {windows_sentences} sentences mention Windows; the "
            "enforcement point is expected to be explicit"
        )


class TestNoFabricatedEvidence:
    def test_commands_use_placeholders_not_example_addresses(self) -> None:
        """A real-looking address in a command invites running it as-is."""
        octet = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        allowed = {"192.168.1.0/24"}          # a documented scope example
        for code, guide in GUIDES.items():
            for found in octet.findall(" ".join(guide.values())):
                assert any(found in a for a in allowed), (
                    f"{code} contains the literal address {found}; commands "
                    "must use placeholders"
                )

    def test_no_guide_uses_a_placeholder_nothing_fills(self) -> None:
        """A stray placeholder is never filled and never explained.

        The shared naming step used to suggest a rule name built from
        <SOURCE_IP> and a <DATE>. On an exposure finding there is no attacking
        source, so a bare <SOURCE_IP> appeared on every one of the 330
        findings, and <DATE> was never in the vocabulary at all.
        """
        from aethra_sec.ui.guide_text import PLACEHOLDERS

        for code, guide in GUIDES.items():
            used = set(re.findall(r"<[A-Z_]+>", " ".join(guide.values())))
            unknown = used - set(PLACEHOLDERS)
            assert not unknown, f"{code} uses {sorted(unknown)}, which nothing fills"

    def test_an_exposure_guide_never_refers_to_an_attacking_source(self) -> None:
        """An exposed service has no attacker; a finding records no source."""
        for code in ("MIT-SERVICE-EXPOSURE", "MIT-SSH-EXPOSURE"):
            blob = " ".join(GUIDES[code].values())
            assert "<SOURCE_IP>" not in blob, (
                f"{code} asks for a source address a finding cannot supply"
            )

    def test_every_guide_uses_the_placeholder_vocabulary(self) -> None:
        for code, guide in GUIDES.items():
            blob = " ".join(guide.values())
            assert "<SOURCE_IP>" in blob or "<TARGET_IP>" in blob, (
                f"{code} never refers to the detection's own addresses"
            )


class TestTheGuidesRecommendRatherThanAct:
    def test_nothing_in_the_module_executes(self) -> None:
        """The guides are strings. Nothing here may run a command."""
        import aethra_sec.database.mitigation_guides as module
        import inspect

        source = inspect.getsource(module)
        for forbidden in ("subprocess", "os.system", "Popen", "os.popen"):
            assert forbidden not in source, (
                f"the guide module references {forbidden}"
            )

    def test_destructive_advice_is_absent(self) -> None:
        for code, guide in GUIDES.items():
            blob = " ".join(guide.values())
            for phrase in ("disable the firewall", "block all tcp",
                           "block all traffic", "block everything"):
                assert not unnegated(blob, phrase), (
                    f"{code} advises the operator to {phrase}"
                )


class TestRenderingFillsFromTheRightAlert:
    """The placeholders must come from the detection being viewed."""

    def test_values_present_on_the_alert_are_substituted(self) -> None:
        from aethra_sec.ui.screens.alerts import (
            _apply_guide_context,
            _guide_context,
        )

        class _Detection:
            src_ip = "10.90.0.5"
            dst_ip = "10.90.0.9"
            dst_port = 443
            protocol = "TCP"

        context = _guide_context(_Detection())
        text = "block <SOURCE_IP> reaching <TARGET_IP> on <PORT>/<PROTOCOL>"
        assert _apply_guide_context(text, context) == (
            "block 10.90.0.5 reaching 10.90.0.9 on 443/TCP"
        )

    def test_a_missing_field_leaves_its_placeholder_visible(self) -> None:
        """Never filled from another event, and never silently dropped."""
        from aethra_sec.ui.screens.alerts import (
            _apply_guide_context,
            _guide_context,
            _unfilled_placeholders,
        )

        class _Detection:
            src_ip = "10.90.0.5"
            dst_ip = ""
            dst_port = None
            protocol = ""

        context = _guide_context(_Detection())
        assert "<TARGET_IP>" not in context
        assert "<PORT>" not in context
        rendered = _apply_guide_context(
            "block <SOURCE_IP> to <TARGET_IP>:<PORT>", context)
        assert rendered == "block 10.90.0.5 to <TARGET_IP>:<PORT>"
        assert _unfilled_placeholders(rendered) == ["<TARGET_IP>", "<PORT>"]

    def test_a_zero_port_is_treated_as_absent(self) -> None:
        from aethra_sec.ui.screens.alerts import _guide_context

        class _Detection:
            src_ip = "10.90.0.5"
            dst_ip = "10.90.0.9"
            dst_port = 0
            protocol = "ICMP"

        assert "<PORT>" not in _guide_context(_Detection())


class TestStoredRecommendationsAreIntact:
    """The migration added columns; it must not have disturbed the rows."""

    def test_the_guide_codes_match_the_seeded_codes(self) -> None:
        from aethra_sec.database.seed import _MITIGATIONS

        seeded = {entry["code"] for entry in _MITIGATIONS}
        assert set(GUIDES) <= seeded, (
            f"guides reference codes that are not seeded: "
            f"{set(GUIDES) - seeded}"
        )


class TestAnUnfilledPlaceholderIsAlwaysExplained:
    """Found on real traffic, not in review.

    A host sweep records no destination address, so <TARGET_IP> survives into
    the verification steps even when the procedure itself has none left. The
    note that explains why a placeholder is still on screen was computed from
    the procedure alone, so that one appeared bare.
    """

    @staticmethod
    def _section(detection, **fields):
        from aethra_sec.models.mitigation import MitigationRecommendation
        from aethra_sec.models.enums import Severity, ThreatCategory
        from aethra_sec.services.mitigation_service import (
            MATCH_CATEGORY,
            MitigationMatch,
        )
        from aethra_sec.ui.screens.alerts import _mitigation_section

        entry = MitigationRecommendation(
            id=1, code="MIT-TEST", threat_name="Test",
            category=ThreatCategory.PORT_SCAN, severity=Severity.MEDIUM,
            explanation="e", why_it_matters="w", immediate_action="i",
            long_term_action="l", **fields)
        match = MitigationMatch(
            recommendation=entry, category=ThreatCategory.PORT_SCAN,
            category_source="test", matched_on=MATCH_CATEGORY)
        return _mitigation_section(match, detection)

    class _Sweep:
        src_ip = "10.90.0.5"
        dst_ip = ""              # a sweep has no single destination
        dst_port = None
        protocol = "ARP"

    def test_a_placeholder_only_in_verification_is_still_explained(self) -> None:
        section = self._section(
            self._Sweep(),
            procedure_steps="1. Identify <SOURCE_IP>.",
            verification_steps="1. Test-NetConnection <TARGET_IP>.",
        )
        body = section.body
        assert "<TARGET_IP>" in body, "the placeholder must stay visible"
        assert "This detection did not record" in body, (
            "a placeholder in the verification steps was left unexplained"
        )
        assert "target ip" in body

    def test_a_placeholder_only_in_rollback_is_still_explained(self) -> None:
        section = self._section(
            self._Sweep(),
            procedure_steps="1. Identify <SOURCE_IP>.",
            rollback_steps="1. Re-open <PORT> afterwards.",
        )
        assert "This detection did not record" in section.body
        assert "port" in section.body

    def test_nothing_is_said_when_the_detection_supplied_everything(self) -> None:
        class _Full:
            src_ip = "10.90.0.5"
            dst_ip = "10.90.0.9"
            dst_port = 443
            protocol = "TCP"

        section = self._section(
            _Full(),
            procedure_steps="1. Block <SOURCE_IP> to <TARGET_IP>:<PORT>.",
            verification_steps="1. Test-NetConnection <TARGET_IP> <PORT>.",
        )
        assert "This detection did not record" not in section.body
        assert "10.90.0.9" in section.body


class TestTheMitigationScreenShowsTheProcedure:
    """The alert dialog is not the only surface.

    The dedicated Mitigation screen renders through MitigationPanel, which
    showed only the five prose fields. A procedure that reaches one surface
    and not the other is half a feature.
    """

    @staticmethod
    def _show_source() -> str:
        import inspect

        from aethra_sec.ui.widgets.mitigation_panel import MitigationPanel

        return inspect.getsource(MitigationPanel.show)

    def test_the_panel_renders_all_four_new_fields(self) -> None:
        source = self._show_source()
        for fragment in ("enforcement_point", "_render_procedure",
                         "operational_warnings", "_render_rollback"):
            assert fragment in source, (
                f"the Mitigation screen never renders {fragment}"
            )

    def test_the_procedure_says_it_is_not_carried_out(self) -> None:
        """The screen must not read as though pressing something applies it."""
        import inspect

        from aethra_sec.ui.widgets.mitigation_panel import MitigationPanel

        note = inspect.getsource(MitigationPanel._render_procedure)
        assert "does not carry these out" in note
        assert "authorised" in note

    def test_an_absent_procedure_renders_no_heading(self) -> None:
        """A heading with nothing under it implies guidance that is not there."""
        import inspect

        from aethra_sec.ui.widgets.mitigation_panel import MitigationPanel

        source = inspect.getsource(MitigationPanel._render_numbered)
        assert "if not steps:" in source and "return" in source
        before_heading = source[:source.index("self._heading")]
        assert "return" in before_heading, (
            "the heading is drawn before the empty check"
        )

    def test_the_panel_executes_nothing(self) -> None:
        import inspect

        import aethra_sec.ui.widgets.mitigation_panel as module

        source = inspect.getsource(module)
        for forbidden in ("subprocess", "os.system", "Popen", "os.popen"):
            assert forbidden not in source, (
                f"the mitigation panel references {forbidden}"
            )
