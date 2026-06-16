"""Tests for assumed-breach / provided credentials.

`spec.credentials` is surfaced into the orchestrator + offensive-subagent system
prompts (durable, unlike the kickoff message) so the agent uses what it already
holds instead of trying to discover/crack it. These pin the rendering and that an
empty list produces no block.
"""

from __future__ import annotations

from src.schemas.engagement import EngagementSpec, ProvidedCredential


def _spec(creds) -> EngagementSpec:
    return EngagementSpec(name="t", mode="ctf", targets=["10.0.0.1"], credentials=creds)


def test_no_block_when_no_credentials():
    assert _spec([]).credentials_block() == ""


def test_block_lists_each_credential_and_instructs_use():
    spec = _spec([
        ProvidedCredential(username="alex.turner", secret="Checkpoint2024!",
                           service="smb", notes="domain account"),
        ProvidedCredential(username="svc_backup", secret="aad3b...:31d6c...",
                           kind="hash", host="dc01"),
    ])
    block = spec.credentials_block()
    assert block.startswith("## Provided credentials")
    # uses them rather than re-discovering
    assert "USE them" in block
    assert "task brief" in block  # told to relay to subagents
    # both credentials rendered with their qualifiers
    assert "alex.turner : Checkpoint2024!  (password; service: smb) — domain account" in block
    assert "svc_backup : aad3b...:31d6c...  (hash; host: dc01)" in block


def test_one_line_handles_missing_secret():
    line = ProvidedCredential(username="guest").one_line()
    assert line == "guest : (no secret provided)  (password)"


def test_credentials_parse_from_yaml(tmp_path):
    spec_file = tmp_path / "e.yaml"
    spec_file.write_text(
        "name: t\nmode: ctf\ntargets: [10.0.0.1]\n"
        "credentials:\n"
        "  - username: alex.turner\n"
        "    secret: 'Checkpoint2024!'\n"
        "    service: smb\n"
    )
    spec = EngagementSpec.from_yaml(spec_file)
    assert len(spec.credentials) == 1
    assert spec.credentials[0].username == "alex.turner"
    assert spec.credentials[0].secret == "Checkpoint2024!"
    assert "Checkpoint2024!" in spec.credentials_block()
