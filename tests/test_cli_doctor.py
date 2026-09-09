"""
tests/test_cli_doctor.py — CLI tests for netlab doctor

Business logic is mocked. These tests only check orchestration, display
tokens, and exit codes.
"""

from unittest.mock import patch

from typer.testing import CliRunner

from cli import app
from core.dependencies import DependencyCheck

runner = CliRunner()


def _ready_checks() -> list[DependencyCheck]:
    return [
        DependencyCheck(name="python", present=True, version="3.12.3"),
        DependencyCheck(name="nmap", present=True, version="7.94"),
        DependencyCheck(name="enum4linux", present=True, version="0.8.9"),
        DependencyCheck(name=".netlab", present=True, version="/tmp/home/.netlab"),
    ]


def test_doctor_exits_zero_when_environment_ready():
    with patch("cli.check_environment", return_value=_ready_checks()):
        result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Environment is ready." in result.stdout
    assert "nmap" in result.stdout


def test_doctor_exits_one_when_tool_missing():
    checks = [
        DependencyCheck(name="python", present=True, version="3.12.3"),
        DependencyCheck(name="nmap", present=False, version=None),
        DependencyCheck(name="enum4linux", present=True, version="0.8.9"),
        DependencyCheck(name=".netlab", present=True, version="/tmp/home/.netlab"),
    ]
    with patch("cli.check_environment", return_value=checks):
        result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "Environment is not ready." in result.stdout
    assert "nmap" in result.stdout


def test_doctor_exits_one_when_netlab_dir_not_writable():
    checks = [
        DependencyCheck(name="python", present=True, version="3.12.3"),
        DependencyCheck(name="nmap", present=True, version="7.94"),
        DependencyCheck(name="enum4linux", present=True, version="0.8.9"),
        DependencyCheck(
            name=".netlab",
            present=False,
            version="/tmp/home/.netlab is not writable: Permission denied",
        ),
    ]
    with patch("cli.check_environment", return_value=checks):
        result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "Environment is not ready." in result.stdout
    assert ".netlab" in result.stdout
    assert "not writable" in result.stdout
