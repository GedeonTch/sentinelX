"""Help/examples contract only: no real scans, monitoring or user databases."""
import shlex
import socket
import sqlite3
from unittest.mock import Mock

import pytest
from rich.console import Console
from typer.main import get_command
from typer.testing import CliRunner

import cli
import core.database as db
import core.logger as logger
import sentinel.sentinel_manager as manager


@pytest.fixture(autouse=True)
def isolated_help(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.setattr(db, "_real_user_home", lambda: home)
    monkeypatch.setattr(logger, "_console", Console(width=140, color_system=None))

    def forbidden(*args, **kwargs):
        pytest.fail("Help/example must not reach network, SQLite or real business logic")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "sendto", forbidden)
    monkeypatch.setattr(cli, "_run_pipeline", forbidden)
    monkeypatch.setattr(db, "get_findings", forbidden)
    for name in ("start", "display_status", "stop"):
        monkeypatch.setattr(manager, name, forbidden)
    yield
    assert not (home / ".netlab").exists()


HELP_CASES = [
    ([], ("Exemples d’utilisation", "scan", "findings", "sentinel")),
    (["scan"], ("--target", "--profile", "--session", "--yes", "normal", "stealth", "aggressive")),
    (["findings", "list"], ("--session", "SESSION_ID", "machine")),
    (["sentinel", "start"], ("--target", "--session", "--relearn", "processus courant", "second terminal")),
    (["sentinel", "status"], ("--network", "un seul réseau")),
    (["sentinel", "stop"], ("--network", "--session", "--timeout", "exactement un sélecteur", "0.01", "30", "contrôles déjà engagés")),
]


def compact(text):
    # Rich wraps option descriptions between table borders; borders are not text.
    return " ".join(text.replace("│", " ").split())


@pytest.mark.parametrize("args,tokens", HELP_CASES)
def test_general_help_contract_without_side_effects(args, tokens):
    result = CliRunner().invoke(cli.app, [*args, "--help"],
                                prog_name="netlab", terminal_width=140, color=False)
    assert result.exit_code == 0, result.output
    output = compact(result.output)
    assert "Usage: netlab" in output
    assert "python cli.py" not in output
    assert "python -m sentinel.command" not in output
    assert "netlab " in output
    for token in tokens:
        assert token in compact(result.output)


@pytest.mark.parametrize("args", [[], ["start"], ["status"], ["stop"]])
def test_sentinel_group_documents_autonomous_interface(args):
    # The shared group remains usable by the existing autonomous entry point.
    # This ticket must also work without its uncommitted packaging files.
    result = CliRunner().invoke(cli.sentinel_app, [*args, "--help"], prog_name="sentinel")
    assert result.exit_code == 0
    output = compact(result.output)
    assert "netlab sentinel" not in output
    assert "Usage: sentinel" in output
    assert "sentinel start" in output if not args else f"sentinel {args[0]}" in output
    assert "python cli.py" not in output
    assert "python -m sentinel.command" not in output


@pytest.mark.parametrize("app,args,program,path", [
    (cli.app, ["sentinel"], "netlab", "netlab sentinel"),
    (cli.sentinel_app, [], "sentinel", "sentinel"),
    (cli.app, ["findings"], "netlab", "netlab findings"),
])
def test_group_usage_uses_actual_path_and_registered_commands(app, args, program, path):
    result = CliRunner().invoke(app, args, prog_name=program, terminal_width=140)
    assert result.exit_code == 0
    output = compact(result.output)
    assert f"Usage: {path} [" in output
    assert "python cli.py" not in output
    assert "python -m sentinel.command" not in output
    group = get_command(app)
    for arg in args:
        group = group.commands[arg]
    for name in group.commands:
        assert name in output
    assert "--help" in output


@pytest.mark.parametrize("width", [48, 80])
@pytest.mark.parametrize("app,args", [(cli.app, []), (cli.app, ["sentinel", "stop"]),
                                     (cli.sentinel_app, [])])
def test_help_at_narrow_width(app, args, width, monkeypatch):
    monkeypatch.setenv("COLUMNS", str(width))
    result = CliRunner().invoke(app, [*args, "--help"], terminal_width=width, color=False)
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "\x1b[" not in result.output


# Read the commands from the very text passed to Typer. No parallel example list.
def documented_commands():
    def walk(command, path, app, program):
        if command.epilog:
            for line in command.epilog.splitlines():
                if line.startswith("netlab "):
                    if app is cli.sentinel_app:
                        line = line.replace("netlab sentinel", "sentinel", 1)
                    yield app, program, path, line
        for name, child in getattr(command, "commands", {}).items():
            yield from walk(child, [*path, name], app, program)
    yield from walk(get_command(cli.app), [], cli.app, "netlab")
    yield from walk(get_command(cli.sentinel_app), [], cli.sentinel_app, "sentinel")


@pytest.mark.parametrize("app,program,help_path,line", list(documented_commands()))
def test_documented_examples_parse_and_dispatch(app, program, help_path, line, monkeypatch):
    shown = CliRunner().invoke(app, [*help_path, "--help"],
                               prog_name=program, terminal_width=180, color=False)
    assert compact(line) in compact(shown.output)
    words = shlex.split(line)
    assert words[0] == program
    args = words[1:]
    args = [{"SESSION_ID": "help-scan", "NETWORK_ID": "help-network"}.get(a, a)
            for a in args]
    calls = {name: Mock(return_value=None) for name in ("start", "display_status", "stop")}
    for name, mock in calls.items():
        monkeypatch.setattr(manager, name, mock)
    pipeline = Mock(return_value=[])
    findings = Mock(return_value=[])
    monkeypatch.setattr(cli, "_run_pipeline", pipeline)
    monkeypatch.setattr(cli, "_render_scan_summary", Mock())
    monkeypatch.setattr(db, "get_findings", findings)
    result = CliRunner().invoke(app, args, input="y\n", terminal_width=180)
    assert result.exit_code == 0, result.output
    business_args = args[1:] if args[:1] == ["sentinel"] else args
    if "--help" in args:
        assert not any(m.called for m in [pipeline, findings, *calls.values()])
    elif business_args[0] == "scan":
        assert pipeline.call_count == 1
        assert pipeline.call_args.args[:4] == (args[args.index("--target") + 1], "normal", None, False)
    elif business_args[:2] == ["findings", "list"]:
        findings.assert_called_once_with("help-scan")
    elif business_args[0] == "start":
        calls["start"].assert_called_once_with(
            target_network=business_args[business_args.index("--target") + 1],
            session_id=None, force_relearn=False)
    elif business_args[0] == "status":
        calls["display_status"].assert_called_once_with("help-network")
    else:
        assert business_args[0] == "stop"
        calls["stop"].assert_called_once_with(None, network_id="help-network", timeout=30.0)


# Missing selector and legacy --session dispatch already have tests in test_cli.py.
@pytest.mark.parametrize("options", [
    ["--network", "network", "--session", "session"],
    ["--network", "network", "--timeout", "0"],
    ["--network", "network", "--timeout", "-1"],
])
def test_stop_rejects_conflict_and_invalid_timeout_before_manager(options):
    result = CliRunner().invoke(cli.app, ["sentinel", "stop", *options])
    assert result.exit_code == 2


def test_stop_accepts_minimum_timeout_and_network_alias(monkeypatch):
    stop = Mock()
    monkeypatch.setattr(manager, "stop", stop)
    result = CliRunner().invoke(cli.app, ["sentinel", "stop", "-n", "network", "--timeout", "0.01"])
    assert result.exit_code == 0
    stop.assert_called_once_with(None, network_id="network", timeout=0.01)


def test_status_does_not_accept_session():
    result = CliRunner().invoke(cli.app, ["sentinel", "status", "--session", "session"])
    assert result.exit_code == 2


def test_examples_exist_for_every_target_command():
    paths = {tuple(path) for app, program, path, line in documented_commands() if app is cli.app}
    for path, tokens in HELP_CASES:
        assert tuple(path) in paths


def test_help_for_every_registered_command_and_group():
    def walk(command, path):
        yield path
        for name, child in getattr(command, "commands", {}).items():
            yield from walk(child, [*path, name])
    for path in walk(get_command(cli.app), []):
        result = CliRunner().invoke(cli.app, [*path, "--help"], prog_name="netlab")
        assert result.exit_code == 0, (path, result.output)
        output = compact(result.output)
        assert "Usage: netlab" in output
        assert "python cli.py" not in output
        assert "python -m sentinel.command" not in output


@pytest.mark.parametrize("order", [("netlab", "sentinel", "netlab"),
                                  ("sentinel", "netlab", "sentinel")])
def test_help_context_does_not_mutate_shared_commands(order, capsys):
    def render(command, context):
        capsys.readouterr()
        text = command.get_help(context)
        # Typer/Rich prints its help rather than returning it on some versions.
        return text + capsys.readouterr().out

    root = get_command(cli.app)
    nested = root.commands["sentinel"]
    standalone = get_command(cli.sentinel_app)
    before = [(cmd, cmd.epilog) for cmd in [nested, standalone,
              *nested.commands.values(), *standalone.commands.values()]]
    for program in order:
        if program == "netlab":
            parent = root.make_context("netlab", [], resilient_parsing=True)
            group = nested
            context = group.make_context("sentinel", [], parent=parent, resilient_parsing=True)
            prefix = "netlab sentinel"
        else:
            group = standalone
            context = group.make_context("sentinel", [], resilient_parsing=True)
            prefix = "sentinel"
        rendered = [render(group, context)]
        for name in ("start", "status", "stop"):
            cmd = group.commands[name]
            ctx = cmd.make_context(name, [], parent=context, resilient_parsing=True)
            text = render(cmd, ctx)
            assert f"{prefix} {name}" in compact(text)
            rendered.append(text)
        for text in rendered:
            if program == "sentinel":
                assert "netlab sentinel" not in text
            else:
                assert "netlab sentinel" in compact(text)
        assert all(cmd.epilog == epilog for cmd, epilog in before)
    assert cli.sentinel_app.info.epilog == cli.SENTINEL_EXAMPLES


@pytest.mark.parametrize("name", ["start", "status", "stop"])
def test_sentinel_options_and_callbacks_identical_in_both_interfaces(name):
    nested = get_command(cli.app).commands["sentinel"].commands[name]
    standalone = get_command(cli.sentinel_app).commands[name]
    def options(cmd):
        return [(p.name, p.opts, p.secondary_opts, p.required, p.default,
                 type(p.type), getattr(p.type, "min", None), getattr(p.type, "max", None),
                 p.help) for p in cmd.params]
    assert options(nested) == options(standalone)
    assert nested.callback.__wrapped__ is standalone.callback.__wrapped__


@pytest.mark.parametrize("app,prefix", [(cli.app, ["sentinel"]), (cli.sentinel_app, [])])
@pytest.mark.parametrize("options", [[], ["--network", "net", "--session", "run"],
                                     ["--network", "net", "--timeout", "0"]])
def test_stop_constraints_identical_for_both_entries(app, prefix, options):
    result = CliRunner().invoke(app, [*prefix, "stop", *options])
    assert result.exit_code == 2
