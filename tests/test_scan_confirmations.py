"""T25 — confirmations groupées du scan multi-hôtes.

Le chemin réel de `netlab scan` est exécuté, y compris le lecteur de saisie de
Click (`typer._click.termui.visible_prompt_func`) : un Ctrl+C est donc simulé à
l'endroit où Click le reçoit. Aucun réseau : nmap, la découverte et les
scanners sont remplacés ; la base SQLite est temporaire.
"""

import contextlib
import io
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import typer

import cli
import core.database as db
import recon.device_fingerprint as discovery
from core.finding import Confidence, Evidence, Finding, Severity

SID = "t25-confirmations"
TARGET = "192.0.2.0/24"
DISCOVERED = ["192.0.2.30", "192.0.2.9", "192.0.2.10"]  # ordre volontairement non trié
SORTED = ["192.0.2.9", "192.0.2.10", "192.0.2.30"]      # 9 avant 10 : tri numérique


def _host(ip, session_id):
    return Finding(
        session_id=session_id, module="device_fingerprint", target_ip=ip,
        severity=Severity.INFO, confidence=Confidence.CONFIRMED,
        evidence=Evidence(raw="simulated", command="test"),
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "get_db_path", lambda sid: tmp_path / f"{sid}.db")
    state = SimpleNamespace(hosts=list(DISCOVERED), db_file=tmp_path / f"{SID}.db")

    # Discovery runs for real; only the nmap boundary is replaced.
    ping = Mock(return_value="<nmaprun/>")
    monkeypatch.setattr(discovery, "_run_nmap_ping", ping)
    monkeypatch.setattr(discovery, "_parse_active_hosts", lambda xml: list(state.hosts))
    monkeypatch.setattr(discovery, "_run_nmap_os", lambda ip: None)
    monkeypatch.setattr(
        discovery, "_parse_host",
        lambda ip, ping_xml, os_xml, session_id: [_host(ip, session_id)],
    )
    tcp = Mock(return_value=[])
    udp = Mock(return_value=[])
    monkeypatch.setattr("detect.tcp_scan.tcp_scan", tcp)
    monkeypatch.setattr("detect.udp_scan.udp_scan", udp)
    state.ping, state.tcp, state.udp = ping, tcp, udp
    return state


def run_scan(monkeypatch, answers, extra_args=()):
    """Run the real `netlab scan`; each prompt consumes the next answer.

    A `True`/`False` answer is typed as y/n. An exception instance is raised
    from the reader, which is where Click receives a Ctrl+C.
    """
    replies = iter(answers)

    def read_reply(text=""):
        try:
            reply = next(replies)
        except StopIteration:
            raise AssertionError("unexpected extra prompt") from None
        if isinstance(reply, BaseException):
            raise reply
        return "y" if reply else "n"

    spy = Mock(side_effect=typer.confirm)
    out = io.StringIO()
    argv = ["netlab", "scan", "--target", TARGET, "--session", SID, *extra_args]
    code = None
    with patch("typer._click.termui.visible_prompt_func", side_effect=read_reply), \
         patch("typer.confirm", spy), \
         contextlib.redirect_stdout(out), \
         patch.object(sys, "argv", argv):
        try:
            cli.app()
            code = 0
        except SystemExit as exc:
            code = exc.code
    return SimpleNamespace(code=code, prompts=[c.args[0] for c in spy.call_args_list],
                           output=out.getvalue())


def module_prompts(run, module):
    return [p for p in run.prompts if p.startswith(f"[{module}]")]


def outcomes(module):
    return {row["target_ip"]: row["outcome"]
            for row in db.get_scan_outcomes(SID) or [] if row["module"] == module}


def session_status():
    return db.get_session(SID)["status"]


class TestBatchConsent:
    def test_three_hosts_accepted_asks_global_tcp_and_udp_only(self, env, monkeypatch):
        run = run_scan(monkeypatch, [True, True, True])

        assert run.code == 0
        assert len(run.prompts) == 3
        assert run.prompts[0] == f"Start full scan on {TARGET} with profile 'normal'?"
        assert len(module_prompts(run, "tcp_scan")) == 1
        assert len(module_prompts(run, "udp_scan")) == 1
        assert not any("discovery" in p.lower() for p in run.prompts)

    def test_batch_prompt_lists_every_host_in_numeric_order(self, env, monkeypatch):
        run = run_scan(monkeypatch, [True, True, True])

        assert ", ".join(SORTED) in run.output
        assert [c.args[0] for c in env.tcp.call_args_list] == SORTED
        assert [c.args[0] for c in env.udp.call_args_list] == SORTED

    def test_accepted_batches_run_each_host_without_inner_prompt(self, env, monkeypatch):
        run = run_scan(monkeypatch, [True, True, True])

        assert run.code == 0
        assert all(c.kwargs["auto_confirm"] is True for c in env.tcp.call_args_list)
        assert all(c.kwargs["auto_confirm"] is True for c in env.udp.call_args_list)
        assert session_status() == "completed"

    def test_no_active_host_means_no_module_prompt(self, env, monkeypatch):
        env.hosts = []
        run = run_scan(monkeypatch, [True])

        assert run.code == 0
        assert run.prompts == [f"Start full scan on {TARGET} with profile 'normal'?"]
        env.tcp.assert_not_called()
        env.udp.assert_not_called()

    def test_single_host_keeps_the_same_flow(self, env, monkeypatch):
        env.hosts = ["192.0.2.10"]
        run = run_scan(monkeypatch, [True, True, True])

        assert run.code == 0
        assert len(run.prompts) == 3
        env.tcp.assert_called_once()
        env.udp.assert_called_once()
        assert session_status() == "completed"


class TestRefusal:
    def test_global_refusal_exits_zero_without_session_or_traffic(self, env, monkeypatch):
        run = run_scan(monkeypatch, [False])

        assert run.code == 0
        assert "Scan cancelled." in run.output
        assert not env.db_file.exists()
        env.ping.assert_not_called()
        env.tcp.assert_not_called()
        env.udp.assert_not_called()

    def test_tcp_refusal_cancels_every_host_and_still_offers_udp(self, env, monkeypatch):
        run = run_scan(monkeypatch, [True, False, True])

        assert run.code == 0
        assert len(module_prompts(run, "udp_scan")) == 1
        env.tcp.assert_not_called()
        assert outcomes("tcp_scan") == {ip: "cancelled" for ip in SORTED}
        assert [c.args[0] for c in env.udp.call_args_list] == SORTED
        assert session_status() == "partial"

    def test_udp_refusal_cancels_every_host_without_udp_probe(self, env, monkeypatch):
        run = run_scan(monkeypatch, [True, True, False])

        assert run.code == 0
        assert [c.args[0] for c in env.tcp.call_args_list] == SORTED
        env.udp.assert_not_called()
        assert outcomes("tcp_scan") == {ip: "completed" for ip in SORTED}
        assert outcomes("udp_scan") == {ip: "cancelled" for ip in SORTED}
        assert session_status() == "partial"


class TestCtrlC:
    def test_ctrl_c_at_global_prompt_exits_130_without_session(self, env, monkeypatch):
        run = run_scan(monkeypatch, [KeyboardInterrupt()])

        assert run.code == 130
        assert not env.db_file.exists()
        env.ping.assert_not_called()
        env.tcp.assert_not_called()
        env.udp.assert_not_called()

    def test_ctrl_c_at_tcp_prompt_exits_130_and_finalises_partial(self, env, monkeypatch):
        run = run_scan(monkeypatch, [True, KeyboardInterrupt()])

        assert run.code == 130
        assert len(run.prompts) == 2
        env.tcp.assert_not_called()
        env.udp.assert_not_called()
        # Neither module ran: both are recorded as cancelled, none as completed.
        assert outcomes("tcp_scan") == {ip: "cancelled" for ip in SORTED}
        assert outcomes("udp_scan") == {ip: "cancelled" for ip in SORTED}
        assert session_status() == "partial"
        assert "RÉSULTAT : PARTIAL" in run.output

    def test_ctrl_c_at_udp_prompt_keeps_tcp_results_and_finalises_partial(self, env, monkeypatch):
        run = run_scan(monkeypatch, [True, True, KeyboardInterrupt()])

        assert run.code == 130
        assert len(run.prompts) == 3
        assert [c.args[0] for c in env.tcp.call_args_list] == SORTED
        env.udp.assert_not_called()
        assert outcomes("tcp_scan") == {ip: "completed" for ip in SORTED}
        assert outcomes("udp_scan") == {ip: "cancelled" for ip in SORTED}
        assert session_status() == "partial"
        assert "RÉSULTAT : PARTIAL" in run.output


class TestYes:
    def test_yes_asks_nothing_and_passes_auto_confirm_to_each_module(self, env, monkeypatch):
        run = run_scan(monkeypatch, [], extra_args=("--yes",))

        assert run.code == 0
        assert run.prompts == []
        assert all(c.kwargs["auto_confirm"] is True for c in env.tcp.call_args_list)
        assert all(c.kwargs["auto_confirm"] is True for c in env.udp.call_args_list)
        assert [c.args[0] for c in env.udp.call_args_list] == SORTED


class TestHostOrder:
    def test_host_sort_key_is_numeric_not_lexicographic(self):
        assert sorted(["10.0.0.10", "10.0.0.9", "10.0.0.100"], key=cli._host_sort_key) == [
            "10.0.0.9", "10.0.0.10", "10.0.0.100",
        ]

    def test_host_sort_key_keeps_non_ip_values_after_ip_addresses(self):
        assert sorted(["host.lan", "10.0.0.9"], key=cli._host_sort_key) == ["10.0.0.9", "host.lan"]
