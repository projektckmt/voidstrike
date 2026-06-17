"""Subagent spec construction tests.

These are the structural regressions that bit us in the field:
  - response_format was a bare pydantic schema → defaulted to ProviderStrategy →
    subagent returned empty placeholders without calling tools.
  - tool allowlists kept letting in too many MCP tools → Anthropic compiled-
    grammar limit.
  - model field was passed as the whole ModelChoice dict instead of the string.

We test the *shape* of every subagent spec. We monkey-patch
`tool_response_format` so we don't need langchain installed at test time, but
we assert the wrapped value is what each subagent passes (= no bare schemas).
"""

from __future__ import annotations

import pytest

from tests.unit._fake_tools import all_fake_tools


@pytest.fixture(autouse=True)
def stub_tool_response_format(monkeypatch):
    """Replace tool_response_format with a sentinel so we can assert it was
    called for every subagent, without needing langchain installed."""

    def sentinel(schema):
        return ("WRAPPED_AS_ToolStrategy", schema)

    monkeypatch.setattr("src.agent.models.tool_response_format", sentinel)
    # Also patch the per-subagent module rebinds (Python evaluates imports
    # once; the subagent module has its own ref to the original fn).
    for mod in [
        "src.agent.subagents.surface",
        "src.agent.subagents.exploit",
        "src.agent.subagents.postex",
        "src.agent.subagents.analyst",
        "src.agent.subagents.researcher",
        "src.agent.subagents.ad",
    ]:
        monkeypatch.setattr(f"{mod}.tool_response_format", sentinel)


# ---------------------------------------------------------------------------
# Common shape checks
# ---------------------------------------------------------------------------

REQUIRED_KEYS = {"name", "description", "system_prompt", "tools",
                 "skills", "model", "response_format", "required_tools"}


def _common_assertions(spec: dict, expected_name: str) -> None:
    assert spec["name"] == expected_name
    assert REQUIRED_KEYS.issubset(spec.keys()), \
        f"missing keys: {REQUIRED_KEYS - set(spec.keys())}"

    # `model` must be a provider:model STRING — passing a dict or instance
    # historically broke profile lookup (or made deepagents call .count on a
    # dict, etc.).
    assert isinstance(spec["model"], str), \
        f"expected model to be a `provider:model` string, got {type(spec['model'])}"
    assert ":" in spec["model"], \
        f"model should be in `provider:model` form, got {spec['model']!r}"

    # response_format MUST be wrapped — a bare class indicates we'd silently
    # opt into Anthropic's ProviderStrategy which short-circuits the tool loop.
    rf = spec["response_format"]
    assert isinstance(rf, tuple) and rf[0] == "WRAPPED_AS_ToolStrategy", (
        f"response_format must be wrapped via tool_response_format(...) so "
        f"the subagent runs tools before satisfying the schema. Got {rf!r}"
    )

    # Tools list must be non-empty AND must not include random unrelated tools.
    assert isinstance(spec["tools"], list)
    assert len(spec["tools"]) > 0, f"{expected_name} produced an empty tool list"

    # Skills directories
    assert isinstance(spec["skills"], list)
    assert all(s.startswith("skills/") for s in spec["skills"])

    # required_tools — every subagent must declare at least one tool that
    # MUST be bound. This is what `_assert_required_tools` checks at startup,
    # turning the "no execution backend" silent failure into a loud error.
    required = spec["required_tools"]
    assert isinstance(required, (set, frozenset))
    assert required, f"{expected_name} declares no required_tools — startup " \
                      "would silently produce an inert subagent if its MCP " \
                      "server was unreachable"
    # All required tool names must actually be in the bound list when the
    # fake catalogue is complete.
    bound = {t.name for t in spec["tools"]}
    assert required.issubset(bound), (
        f"{expected_name}.required_tools={required!r} but bound tools are "
        f"{bound!r}. Either the allowlist drifted or required_tools is wrong."
    )


# ---------------------------------------------------------------------------
# Per-subagent tests
# ---------------------------------------------------------------------------

class TestSurfaceSpec:
    def test_shape(self) -> None:
        from src.agent.subagents.surface import surface_spec
        spec = surface_spec("eco", all_fake_tools())
        _common_assertions(spec, "surface")

    def test_only_allowlisted_tools(self) -> None:
        from src.agent.subagents.surface import surface_spec
        spec = surface_spec("eco", all_fake_tools())
        names = {t.name for t in spec["tools"]}
        # No exploit/postex tools — surface characterizes, it does not exploit.
        assert not any(n.startswith(("exploit__", "postex__")) for n in names), names
        # Browser is allowed, but ONLY the read-only RECON tools. The
        # EXPLOIT-classed form-interaction tools (fill_form/submit/click) belong
        # to exploit — surface inspects, it doesn't drive forms.
        assert not ({"browser__fill_form", "browser__submit", "browser__click"} & names), names
        # Shell access is limited to the tmux command tools (ad-hoc recon /
        # long scans on the Kali sandbox). NOT listener/exploit shell tools.
        assert not any(
            n.startswith("shell__") and "tmux" not in n for n in names
        ), names
        assert "surface__curl" in names
        assert "surface__web_intake" in names
        assert "surface__service_triage" in names
        assert "surface__nmap_quick" in names


class TestExploitSpec:
    def test_shape(self) -> None:
        from src.agent.subagents.exploit import exploit_spec
        spec = exploit_spec("eco", all_fake_tools())
        _common_assertions(spec, "exploit")

    def test_has_listener_and_staging_tools(self) -> None:
        from src.agent.subagents.exploit import exploit_spec
        spec = exploit_spec("eco", all_fake_tools())
        names = {t.name for t in spec["tools"]}
        # `exploit__generate_payload` / `exploit__deliver_via_*` /
        # `exploit__searchsploit_lookup` are temporarily disabled. The
        # subagent drives delivery via tmux + the shell-mcp container's
        # real disk — pin the staging primitives it relies on.
        assert "exploit__generate_payload" not in names
        assert "exploit__deliver_via_web" not in names
        assert "exploit__deliver_via_ftp" not in names
        assert "exploit__searchsploit_lookup" not in names
        assert "shell__start_listener" in names
        assert "shell__stabilize_shell" in names
        assert "shell__tmux_new_session" in names
        assert "shell__tmux_send" in names
        assert "shell__tmux_read" in names
        assert "shell__start_callback_server" in names
        assert "shell__wait_callback" in names
        assert "shell__callback_events" in names
        assert "shell__http_json_request" in names


class TestPostExSpec:
    def test_shape(self) -> None:
        from src.agent.subagents.postex import postex_spec
        spec = postex_spec("eco", all_fake_tools())
        _common_assertions(spec, "postex")

    def test_has_enum_and_session_tools(self) -> None:
        from src.agent.subagents.postex import postex_spec
        spec = postex_spec("eco", all_fake_tools())
        names = {t.name for t in spec["tools"]}
        assert "postex__linux_basic_enum" in names
        assert "shell__tmux_send" in names

    def test_local_web_forwarding_guidance_and_schema(self) -> None:
        from src.agent.subagents.postex import POSTEX_PROMPT, PostExResult

        assert "skills/postex/local-web-port-forward/SKILL.md" in POSTEX_PROMPT
        assert "forwarded_services" in POSTEX_PROMPT
        assert "forwarded_services" in PostExResult.model_fields


class TestAnalystSpec:
    def test_shape(self) -> None:
        from src.agent.subagents.analyst import analyst_spec
        spec = analyst_spec("eco", all_fake_tools())
        _common_assertions(spec, "analyst")

    def test_has_findings_reader_and_report_renderer(self) -> None:
        from src.agent.subagents.analyst import analyst_spec
        spec = analyst_spec("eco", all_fake_tools())
        names = {t.name for t in spec["tools"]}
        # Analyst reads findings to produce the report
        assert "episodes__list_findings" in names
        # And calls the in-process render_report tool
        assert "render_report" in names


class TestResearcherSpec:
    def test_shape(self) -> None:
        from src.agent.subagents.researcher import researcher_spec
        spec = researcher_spec("eco", all_fake_tools())
        _common_assertions(spec, "researcher")

    def test_has_browser_and_searchsploit(self) -> None:
        from src.agent.subagents.researcher import researcher_spec
        spec = researcher_spec("eco", all_fake_tools())
        names = {t.name for t in spec["tools"]}
        assert "browser__goto" in names
        assert "research__cve_lookup" in names
        assert "research__vendor_advisory_search" in names
        assert "research__epss_lookup" in names
        assert "research__cisa_kev_lookup" in names
        assert "research__github_poc_search" in names
        assert "research__exploitdb_fetch" in names
        assert "research__fetch_poc" in names
        assert "research__poc_static_review" in names
        assert "research__affected_version_check" in names
        assert "exploit__searchsploit_lookup" in names

    def test_eco_uses_mid_tier_model(self) -> None:
        from src.agent.subagents.researcher import researcher_spec
        spec = researcher_spec("eco", all_fake_tools())
        assert spec["model"] == "anthropic:claude-sonnet-4-6"


class TestAdSpec:
    def test_shape(self) -> None:
        from src.agent.subagents.ad import ad_spec
        spec = ad_spec("eco", all_fake_tools())
        _common_assertions(spec, "ad")

    def test_has_bloodhound_and_kerberoast(self) -> None:
        from src.agent.subagents.ad import ad_spec
        spec = ad_spec("eco", all_fake_tools())
        names = {t.name for t in spec["tools"]}
        assert "ad__bloodhound_collect" in names
        assert "ad__kerberoast" in names


# ---------------------------------------------------------------------------
# Cross-cutting: tool-count budget per subagent
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec_fn,name,max_tools", [
    ("src.agent.subagents.surface.surface_spec", "surface", 18),  # +browser (recon) +tmux
    ("src.agent.subagents.exploit.exploit_spec", "exploit", 17),  # +tmux_list_sessions (session recovery)
    ("src.agent.subagents.postex.postex_spec",   "postex",  11),  # +tmux_list_sessions (session recovery)
    ("src.agent.subagents.researcher.researcher_spec", "researcher", 17),
    ("src.agent.subagents.analyst.analyst_spec", "analyst", 6),
])
def test_subagent_under_tool_budget(spec_fn, name, max_tools):
    """Each subagent's MCP toolset stays under a budget. This is mostly about
    keeping each subagent focused (and its context lean) — the original driver,
    Anthropic's "compiled grammar is too large" error, turns out to have lots of
    headroom now that the HarnessProfile excludes the 6 heavy filesystem tools:
    a live grammar-compile test (forced `tool_choice="any"`) against the real
    exploit model compiled cleanly at 15, 30, and even the full 44-tool catalog.
    So these caps are a focus/context guard, not a hard grammar ceiling — bump
    deliberately, but they're not the cliff they once were."""
    import importlib
    module_path, attr = spec_fn.rsplit(".", 1)
    fn = getattr(importlib.import_module(module_path), attr)
    spec = fn("eco", all_fake_tools())
    assert len(spec["tools"]) <= max_tools, (
        f"{name} now has {len(spec['tools'])} MCP tools (budget {max_tools}). "
        "Adding tools risks tripping the Anthropic grammar compiler again."
    )
