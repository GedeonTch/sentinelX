"""
tests/test_dependencies.py — Unit tests for core/dependencies.py

Covers:
- Nominal: python + nmap + enum4linux all usable
- Edge: one external tool missing
- Error: version detection fails (OSError / timeout) without crashing
- Python below 3.10 is not ready
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

from core.dependencies import (
    DependencyCheck,
    check_environment,
    check_external_tool,
    check_netlab_dir,
    check_python,
    check_status,
    environment_ready,
    python_version_ok,
)


def _nmap_ok() -> DependencyCheck:
    return DependencyCheck(name="nmap", present=True, version="7.94")


def _enum_ok() -> DependencyCheck:
    return DependencyCheck(name="enum4linux", present=True, version="0.8.9")


def _python_ok() -> DependencyCheck:
    return DependencyCheck(name="python", present=True, version="3.12.3")


def _netlab_ok() -> DependencyCheck:
    return DependencyCheck(name=".netlab", present=True, version="/tmp/home/.netlab")


# ---------------------------------------------------------------------------
# Nominal
# ---------------------------------------------------------------------------

class TestNominalEnvironment:
    def test_check_python_reports_running_interpreter(self):
        check = check_python()
        assert check.name == "python"
        assert check.present is True
        assert check.version is not None
        assert python_version_ok(check.version) is True

    @patch("core.dependencies.check_netlab_dir")
    @patch("core.dependencies.check_external_tool")
    @patch("core.dependencies.check_python")
    def test_check_environment_returns_one_entry_per_tool(
        self,
        mock_python: MagicMock,
        mock_external: MagicMock,
        mock_netlab: MagicMock,
    ):
        mock_python.return_value = _python_ok()
        mock_external.side_effect = [_nmap_ok(), _enum_ok()]
        mock_netlab.return_value = _netlab_ok()
        checks = check_environment()
        assert [c.name for c in checks] == ["python", "nmap", "enum4linux", ".netlab"]
        assert all(isinstance(c, DependencyCheck) for c in checks)
        assert environment_ready(checks) is True

    def test_environment_ready_is_not_the_primary_result_shape(self):
        checks = [_python_ok(), _nmap_ok(), _enum_ok(), _netlab_ok()]
        assert isinstance(checks, list)
        assert environment_ready(checks) is True


# ---------------------------------------------------------------------------
# Edge — one tool missing
# ---------------------------------------------------------------------------

class TestMissingTool:
    @patch("core.dependencies.shutil.which", return_value=None)
    def test_missing_nmap_does_not_raise(self, _mock_which: MagicMock):
        check = check_external_tool("nmap")
        assert check.name == "nmap"
        assert check.present is False
        assert check.version is None
        assert check_status(check) == "missing"

    def test_environment_not_ready_when_enum4linux_missing(self):
        checks = [
            _python_ok(),
            _nmap_ok(),
            DependencyCheck(name="enum4linux", present=False, version=None),
        ]
        assert environment_ready(checks) is False

    @patch("core.dependencies.check_netlab_dir", return_value=_netlab_ok())
    @patch("core.dependencies.check_external_tool")
    @patch("core.dependencies.check_python", return_value=_python_ok())
    def test_check_environment_survives_one_missing_tool(
        self,
        _mock_python: MagicMock,
        mock_external: MagicMock,
        _mock_netlab: MagicMock,
    ):
        mock_external.side_effect = [
            DependencyCheck(name="nmap", present=False, version=None),
            _enum_ok(),
        ]
        checks = check_environment()
        assert checks[1].present is False
        assert environment_ready(checks) is False


# ---------------------------------------------------------------------------
# Error — version probe fails, must not crash
# ---------------------------------------------------------------------------

class TestVersionDetectionErrors:
    @patch("core.dependencies.subprocess.run", side_effect=OSError("broken pipe"))
    @patch("core.dependencies.shutil.which", return_value="/usr/bin/nmap")
    def test_oserror_on_version_keeps_present_true(
        self,
        _mock_which: MagicMock,
        _mock_run: MagicMock,
    ):
        check = check_external_tool("nmap")
        assert check.present is True
        assert check.version is None

    @patch(
        "core.dependencies.subprocess.run",
        side_effect=__import__("subprocess").TimeoutExpired(cmd="nmap", timeout=5),
    )
    @patch("core.dependencies.shutil.which", return_value="/usr/bin/nmap")
    def test_timeout_on_version_keeps_present_true(
        self,
        _mock_which: MagicMock,
        _mock_run: MagicMock,
    ):
        check = check_external_tool("nmap")
        assert check.present is True
        assert check.version is None

    @patch("core.dependencies.shutil.which", return_value="/usr/bin/nmap")
    def test_nmap_banner_extracts_dotted_version(self, _mock_which: MagicMock):
        completed = MagicMock()
        completed.stdout = "Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64\n"
        completed.stderr = ""
        with patch("core.dependencies.subprocess.run", return_value=completed):
            check = check_external_tool("nmap")
        assert check.present is True
        assert check.version == "7.94"

    @patch("core.dependencies.shutil.which", return_value="/usr/bin/nmap")
    def test_unparseable_version_output(self, _mock_which: MagicMock):
        completed = MagicMock()
        completed.stdout = "not a version banner\n"
        completed.stderr = ""
        with patch("core.dependencies.subprocess.run", return_value=completed):
            check = check_external_tool("nmap")
        assert check.present is True
        assert check.version == "not a version banner"


class TestPythonVersionGate:
    def test_python_3_9_is_not_ok(self):
        assert python_version_ok("3.9.18") is False
        check = DependencyCheck(name="python", present=True, version="3.9.18")
        assert check_status(check) == "python_too_old"
        assert environment_ready([check, _nmap_ok(), _enum_ok(), _netlab_ok()]) is False

    def test_python_3_10_is_ok(self):
        assert python_version_ok("3.10.0") is True

    def test_none_version_is_not_ok(self):
        assert python_version_ok(None) is False

    def test_garbage_version_is_not_ok(self):
        assert python_version_ok("abc") is False

    def test_incomplete_check_list_is_not_ready(self):
        assert environment_ready([_python_ok(), _nmap_ok()]) is False

    def test_missing_netlab_dir_is_not_ready(self):
        checks = [
            _python_ok(),
            _nmap_ok(),
            _enum_ok(),
            DependencyCheck(
                name=".netlab",
                present=False,
                version="/tmp/home/.netlab is not writable: Permission denied",
            ),
        ]
        assert environment_ready(checks) is False
        assert check_status(checks[-1]) == "failed"


# ---------------------------------------------------------------------------
# ~/.netlab/ — ticket #003b
# ---------------------------------------------------------------------------

class TestNetlabDir:
    def test_existing_writable_directory_is_ok(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr("core.dependencies.Path.home", lambda: tmp_path)
        netlab = tmp_path / ".netlab"
        netlab.mkdir()
        check = check_netlab_dir()
        assert check.name == ".netlab"
        assert check.present is True
        assert check.version == str(netlab)
        assert not (netlab / "sessions").exists()
        assert not (netlab / ".doctor_write_probe").exists()

    def test_missing_directory_is_created_when_possible(
        self, tmp_path: Path, monkeypatch
    ):
        monkeypatch.setattr("core.dependencies.Path.home", lambda: tmp_path)
        netlab = tmp_path / ".netlab"
        assert not netlab.exists()
        check = check_netlab_dir()
        assert check.present is True
        assert netlab.is_dir()
        assert check.version == str(netlab)
        assert not (netlab / "sessions").exists()

    def test_create_failure_is_explicit_not_a_crash(
        self, tmp_path: Path, monkeypatch
    ):
        monkeypatch.setattr("core.dependencies.Path.home", lambda: tmp_path)

        original_mkdir = Path.mkdir

        def fake_mkdir(self: Path, *args: object, **kwargs: object) -> None:
            if self == tmp_path / ".netlab":
                raise PermissionError("denied")
            original_mkdir(self, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", fake_mkdir)
        check = check_netlab_dir()
        assert check.present is False
        assert check.version is not None
        assert "cannot create" in check.version
        assert not (tmp_path / ".netlab").exists()

    def test_existing_unwritable_directory_is_explicit_failure(
        self, tmp_path: Path, monkeypatch
    ):
        monkeypatch.setattr("core.dependencies.Path.home", lambda: tmp_path)
        netlab = tmp_path / ".netlab"
        netlab.mkdir()

        original_write = Path.write_text

        def fake_write_text(self: Path, *args: object, **kwargs: object) -> int:
            if self.name == ".doctor_write_probe":
                raise PermissionError("denied")
            return original_write(self, *args, **kwargs)

        monkeypatch.setattr(Path, "write_text", fake_write_text)
        check = check_netlab_dir()
        assert check.present is False
        assert check.version is not None
        assert "is not writable" in check.version
        assert netlab.is_dir()

