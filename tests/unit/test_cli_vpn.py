"""CLI VPN-path resolution + project-root discovery.

`voidstrike engage` resolves the .ovpn from (in order) the --vpn flag, the
VPN_FILE env var, or the spec's `vpn_config:` field; relative paths in the
spec are anchored to the spec file's directory. These tests pin that
precedence — silently picking the wrong .ovpn would tunnel an engagement
through the wrong network and is the kind of bug nobody notices until packets
go to the wrong place.
"""

from __future__ import annotations

from pathlib import Path

import pytest


SPEC_TEMPLATE = """\
name: t
mode: ctf
targets: ["10.10.10.5"]
vpn_config: {vpn}
"""


def _write_spec(tmp_path: Path, vpn: str | None) -> Path:
    spec_path = tmp_path / "spec.yaml"
    if vpn is None:
        spec_path.write_text("name: t\nmode: ctf\ntargets: ['10.10.10.5']\n")
    else:
        spec_path.write_text(SPEC_TEMPLATE.format(vpn=vpn))
    return spec_path


class TestResolveVpnPath:
    def test_flag_wins_over_env_and_spec(self, tmp_path, monkeypatch) -> None:
        from src.cli.main import _resolve_vpn_path

        spec = _write_spec(tmp_path, "spec.ovpn")
        (tmp_path / "spec.ovpn").write_text("")
        flag = tmp_path / "flag.ovpn"
        flag.write_text("")
        monkeypatch.setenv("VPN_FILE", str(tmp_path / "env.ovpn"))

        resolved = _resolve_vpn_path(spec, flag)
        assert resolved == flag.resolve()

    def test_env_wins_over_spec(self, tmp_path, monkeypatch) -> None:
        from src.cli.main import _resolve_vpn_path

        spec = _write_spec(tmp_path, "spec.ovpn")
        (tmp_path / "spec.ovpn").write_text("")
        env_target = tmp_path / "env.ovpn"
        env_target.write_text("")
        monkeypatch.setenv("VPN_FILE", str(env_target))

        resolved = _resolve_vpn_path(spec, None)
        assert resolved == env_target.resolve()

    def test_spec_relative_resolved_against_spec_parent(
        self, tmp_path, monkeypatch
    ) -> None:
        from src.cli.main import _resolve_vpn_path

        monkeypatch.delenv("VPN_FILE", raising=False)
        nested = tmp_path / "engagements"
        nested.mkdir()
        spec = nested / "spec.yaml"
        spec.write_text(SPEC_TEMPLATE.format(vpn="./mybox.ovpn"))
        ovpn = nested / "mybox.ovpn"
        ovpn.write_text("")

        # Run from a different CWD to make sure resolution is anchored to the
        # spec's parent, not the shell's pwd.
        monkeypatch.chdir(tmp_path)
        resolved = _resolve_vpn_path(spec, None)
        assert resolved == ovpn.resolve()

    def test_spec_absolute_kept_as_is(self, tmp_path, monkeypatch) -> None:
        from src.cli.main import _resolve_vpn_path

        monkeypatch.delenv("VPN_FILE", raising=False)
        ovpn = tmp_path / "somewhere" / "abs.ovpn"
        ovpn.parent.mkdir()
        ovpn.write_text("")
        spec = _write_spec(tmp_path, str(ovpn))

        resolved = _resolve_vpn_path(spec, None)
        assert resolved == ovpn.resolve()

    def test_none_when_nothing_set(self, tmp_path, monkeypatch) -> None:
        from src.cli.main import _resolve_vpn_path

        monkeypatch.delenv("VPN_FILE", raising=False)
        spec = _write_spec(tmp_path, vpn=None)

        assert _resolve_vpn_path(spec, None) is None


class TestFindProjectRoot:
    def test_walks_up_from_spec(self, tmp_path) -> None:
        from src.cli.main import _find_project_root

        root = tmp_path / "repo"
        (root / "infra").mkdir(parents=True)
        (root / "infra" / "docker-compose.yml").write_text("")
        spec = root / "docs" / "examples" / "spec.yaml"
        spec.parent.mkdir(parents=True)
        spec.write_text("")

        assert _find_project_root(spec) == root.resolve()

    def test_falls_back_to_cwd(self, tmp_path, monkeypatch) -> None:
        from src.cli.main import _find_project_root

        root = tmp_path / "repo"
        (root / "infra").mkdir(parents=True)
        (root / "infra" / "docker-compose.yml").write_text("")
        # Spec lives outside the repo (~/engagements style).
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        spec = outside / "spec.yaml"
        spec.write_text("")

        monkeypatch.chdir(root)
        assert _find_project_root(spec) == root.resolve()

    def test_none_when_no_match(self, tmp_path, monkeypatch) -> None:
        from src.cli.main import _find_project_root

        monkeypatch.chdir(tmp_path)
        spec = tmp_path / "spec.yaml"
        spec.write_text("")

        assert _find_project_root(spec) is None
