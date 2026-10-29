"""Baseline reliability (ticket « Fiabiliser la baseline Sentinel », B1–B7, C1).

Rule under test: a TCP scan that completed with zero open ports is a valid
result; a failed, partial, invalid or incomplete scan is an UNKNOWN state and
never zero ports.

No real network and no real nmap/arp/ip: every external command is stubbed,
the SQLite databases are temporary, and HOME is isolated.
"""

import sqlite3
import subprocess
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

import core.database as db
import sentinel.baseline as baseline_mod
from sentinel.baseline import (
    NetworkIdentity,
    _get_arp_mac,
    baseline_exists,
    get_baseline,
    learn_baseline,
)
from sentinel.monitor import _get_open_ports

# Real implementation, captured before the autouse fixture neutralises it.
REAL_GET_ARP_MAC = _get_arp_mac

SESSION = "session-baseline-reliability"
NET = "192.168.1.0/24"
IDENTITY = NetworkIdentity(NET, "192.168.1.1", "aa:aa:aa:aa:aa:aa")
PLANNED = 1030  # 1-1024 plus the 6 extra Sentinel ports


# ---------------------------------------------------------------------------
# Fixtures and XML builders
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Temporary HOME-like paths, temporary SQLite, and no real command at all."""
    def sentinel_path(network_id: str):
        d = tmp_path / ".netlab" / "sentinel"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{network_id}.db"

    monkeypatch.setattr(db, "get_sentinel_db_path", sentinel_path)
    monkeypatch.setattr(db, "get_db_path", lambda sid: tmp_path / f"{sid}.db")
    db.init_sentinel_db(SESSION)

    def forbidden(cmd, *args, **kwargs):
        raise AssertionError(f"unexpected real command in test: {cmd!r}")

    monkeypatch.setattr(subprocess, "run", forbidden)
    # Default: MAC unknown. C1 tests call REAL_GET_ARP_MAC explicitly.
    monkeypatch.setattr(baseline_mod, "_get_arp_mac", lambda ip: "")
    yield


def nmap_tcp_xml(ip="192.168.1.10", open_ports=(), planned=PLANNED, *,
                 finished="success", host_state="up", timedout=False,
                 omit_extraports=False, extra_host_ip=None, duplicate_port=None,
                 port_id_override=None, omit_runstats=False, omit_ports=False):
    """A nmap TCP XML run; complete by default (zero open ports is valid)."""
    open_ports = sorted(open_ports)
    port_xml = "".join(
        f'<port protocol="tcp" portid="{p if port_id_override is None else port_id_override}">'
        f'<state state="open" reason="syn-ack"/><service name="svc{p}" method="table"/></port>'
        for p in open_ports
    )
    if duplicate_port is not None:
        port_xml += (f'<port protocol="tcp" portid="{duplicate_port}">'
                     '<state state="open" reason="syn-ack"/></port>')
    closed = planned - len(open_ports)
    extra = "" if omit_extraports or closed <= 0 else f'<extraports state="closed" count="{closed}"/>'
    timed = ' timedout="true"' if timedout else ""
    host = (f'<host{timed}><status state="{host_state}" reason="echo-reply"/>'
            f'<address addr="{ip}" addrtype="ipv4"/>'
            + ("" if omit_ports else f"<ports>{port_xml}{extra}</ports>")
            + "</host>")
    if extra_host_ip:
        host += (f'<host><status state="up"/><address addr="{extra_host_ip}" addrtype="ipv4"/>'
                 '<ports></ports></host>')
    runstats = "" if omit_runstats else f'<runstats><finished exit="{finished}"/></runstats>'
    return ('<?xml version="1.0"?>\n<nmaprun>'
            f'<scaninfo type="connect" protocol="tcp" numservices="{planned}" services="1-1024"/>'
            f'{host}{runstats}</nmaprun>')


def ping_xml(*ips):
    hosts = "".join(
        f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/></host>' for ip in ips
    )
    return f'<?xml version="1.0"?><nmaprun>{hosts}<runstats><finished exit="success"/></runstats></nmaprun>'


def learn(scans, *, force=False, ping=None):
    """Run learn_baseline with stubbed ping and per-IP TCP results (None = unknown)."""
    ips = list(scans)
    ping_result = ping if ping is not None else ping_xml(*ips)
    with patch("sentinel.baseline._run_nmap_ping", return_value=ping_result), \
         patch("sentinel.baseline._run_nmap_tcp",
               side_effect=lambda ip, profile, ports: scans[ip]):
        return learn_baseline(NET, SESSION, IDENTITY, force_relearn=force)


def stored_ports():
    return {ip: entry.ports for ip, entry in get_baseline(SESSION, IDENTITY).items()}


def raw(sql, params=()):
    conn = sqlite3.connect(str(db.get_sentinel_db_path(SESSION)))
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def baseline_snapshot():
    return raw("SELECT id, asset_id, ports, mac, last_scan FROM baseline ORDER BY id")


def assets_snapshot():
    return raw("SELECT id, ip, mac FROM assets ORDER BY id")


def inject_trigger(sql):
    conn = sqlite3.connect(str(db.get_sentinel_db_path(SESSION)))
    try:
        conn.execute(sql)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# B1 — a failed scan is never an empty baseline
# ---------------------------------------------------------------------------

class TestB1FailedScanIsNotEmptyBaseline:
    def test_complete_run_with_zero_open_ports_is_a_valid_baseline(self):
        assert learn({"192.168.1.10": nmap_tcp_xml()}) is True
        assert stored_ports() == {"192.168.1.10": []}

    def test_complete_run_with_open_ports_is_stored(self):
        assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[22, 80])}) is True
        assert stored_ports() == {"192.168.1.10": [22, 80]}

    def test_no_output_is_unknown_not_empty(self, capsys):
        assert learn({"192.168.1.10": None}) is False
        assert not baseline_exists(SESSION, IDENTITY)
        assert "Baseline stored" not in capsys.readouterr().out

    def test_real_nmap_timeout_is_unknown(self):
        with patch("detect.tcp_scan.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("nmap", 300)):
            ping = ping_xml("192.168.1.10")
            with patch("sentinel.baseline._run_nmap_ping", return_value=ping):
                assert learn_baseline(NET, SESSION, IDENTITY) is False
        assert not baseline_exists(SESSION, IDENTITY)

    def test_real_nonzero_exit_with_complete_xml_is_unknown(self):
        completed = CompletedProcess(["nmap"], 2, stdout=nmap_tcp_xml(open_ports=[22]), stderr="")
        with patch("detect.tcp_scan.subprocess.run", return_value=completed), \
             patch("sentinel.baseline._run_nmap_ping", return_value=ping_xml("192.168.1.10")):
            assert learn_baseline(NET, SESSION, IDENTITY) is False
        assert not baseline_exists(SESSION, IDENTITY)

    @pytest.mark.parametrize("xml", [
        nmap_tcp_xml(open_ports=[22], omit_extraports=True),       # partial table
        nmap_tcp_xml(open_ports=[22], omit_runstats=True),         # run not proven finished
        nmap_tcp_xml(open_ports=[22], finished="error"),           # run not successful
        nmap_tcp_xml(open_ports=[22], host_state="down"),          # host not up
        nmap_tcp_xml(open_ports=[22], timedout=True),              # nmap host timeout
        nmap_tcp_xml(open_ports=[22], omit_ports=True),            # no port table
        "not xml <<<",                                             # malformed
        "<nmaprun></nmaprun>",                                     # no host
    ], ids=["partial", "no-runstats", "finished-error", "host-down",
            "timedout", "no-ports", "malformed", "no-host"])
    def test_invalid_or_incomplete_tcp_xml_is_unknown(self, xml):
        assert learn({"192.168.1.10": xml}) is False
        assert not baseline_exists(SESSION, IDENTITY)

    def test_one_unknown_host_aborts_the_whole_learning(self):
        scans = {
            "192.168.1.10": nmap_tcp_xml(open_ports=[22]),
            "192.168.1.11": None,
        }
        assert learn(scans) is False
        assert not baseline_exists(SESSION, IDENTITY)
        assert raw("SELECT COUNT(*) FROM baseline")[0][0] == 0
        assert raw("SELECT COUNT(*) FROM assets")[0][0] == 0

    def test_partial_extra_host_in_xml_is_unknown(self):
        scans = {"192.168.1.10": nmap_tcp_xml(open_ports=[22], extra_host_ip="192.168.1.99")}
        assert learn(scans) is False
        assert not baseline_exists(SESSION, IDENTITY)


# ---------------------------------------------------------------------------
# B2 / B5 — relearn never replaces a reliable baseline with an unknown one
# ---------------------------------------------------------------------------

class TestB2B5RelearnIsAllOrNothing:
    def _reliable_baseline(self):
        assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[22, 80])}) is True
        return baseline_snapshot(), assets_snapshot()

    def test_relearn_with_unknown_host_keeps_previous_baseline(self, capsys):
        before_rows, before_assets = self._reliable_baseline()
        assert learn({"192.168.1.10": None}, force=True) is False
        assert baseline_snapshot() == before_rows
        assert assets_snapshot() == before_assets
        assert stored_ports() == {"192.168.1.10": [22, 80]}
        assert "Replaced" not in capsys.readouterr().out

    def test_relearn_with_unknown_second_host_keeps_previous_baseline(self):
        before_rows, _ = self._reliable_baseline()
        scans = {"192.168.1.10": nmap_tcp_xml(open_ports=[443]), "192.168.1.11": "not xml <<<"}
        assert learn(scans, force=True) is False
        assert baseline_snapshot() == before_rows

    def test_relearn_with_malformed_ping_keeps_previous_baseline(self):
        before_rows, _ = self._reliable_baseline()
        assert learn({}, force=True, ping="not xml <<<") is False
        assert baseline_snapshot() == before_rows

    def test_relearn_with_successful_complete_scan_replaces(self, capsys):
        self._reliable_baseline()
        assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[443])}, force=True) is True
        assert stored_ports() == {"192.168.1.10": [443]}
        assert "Replaced 1 old baseline entry(ies)." in capsys.readouterr().out

    def test_failing_insert_rolls_back_the_delete(self):
        """B5: the old rows are deleted in the same transaction; a failed 2nd insert undoes all."""
        self._reliable_baseline()
        before_rows, before_assets = baseline_snapshot(), assets_snapshot()
        inject_trigger(
            "CREATE TRIGGER fail_second_insert BEFORE INSERT ON baseline "
            "WHEN NEW.ports = '[80]' BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
        )
        scans = {
            "192.168.1.10": nmap_tcp_xml(open_ports=[22]),
            "192.168.1.11": nmap_tcp_xml(ip="192.168.1.11", open_ports=[80]),
        }
        with patch("sentinel.baseline._run_nmap_ping", return_value=ping_xml("192.168.1.10", "192.168.1.11")), \
             patch("sentinel.baseline._run_nmap_tcp", side_effect=lambda ip, p, ports: scans[ip]), \
             patch("sentinel.baseline.display") as shown:
            assert learn_baseline(NET, SESSION, IDENTITY, force_relearn=True) is False
        # The trigger must really have fired, otherwise the test proves nothing.
        assert any("code SQLite 1811" in str(c.args[0]) for c in shown.call_args_list)
        assert baseline_snapshot() == before_rows
        assert assets_snapshot() == before_assets

    def test_failing_delete_keeps_the_old_baseline(self):
        self._reliable_baseline()
        before_rows = baseline_snapshot()
        inject_trigger(
            "CREATE TRIGGER fail_delete BEFORE DELETE ON baseline "
            "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
        )
        assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[443])}, force=True) is False
        assert baseline_snapshot() == before_rows

    def test_storage_error_is_reported_without_sqlite_text(self, capsys):
        self._reliable_baseline()
        inject_trigger(
            "CREATE TRIGGER fail_delete BEFORE DELETE ON baseline "
            "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
        )
        assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[443])}, force=True) is False
        out = " ".join(capsys.readouterr().out.split())  # rich wraps long lines
        assert "baseline non modifiée" in out
        assert "injected failure" not in out


# ---------------------------------------------------------------------------
# B6 — assets are not duplicated per IP and orphans are pruned
# ---------------------------------------------------------------------------

class TestB6AssetsNotDuplicated:
    def test_relearn_reuses_the_same_asset_for_the_same_ip(self):
        assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[22])}) is True
        first = raw("SELECT asset_id FROM baseline")[0][0]
        assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[22, 80])}, force=True) is True
        assert raw("SELECT asset_id FROM baseline") == [(first,)]
        assert raw("SELECT COUNT(*) FROM assets WHERE ip='192.168.1.10'")[0][0] == 1

    def test_repeated_relearns_do_not_grow_the_asset_table(self):
        for _ in range(3):
            assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[22])}, force=True) is True
        assert raw("SELECT COUNT(*) FROM assets")[0][0] == 1

    def test_host_that_disappeared_is_pruned_when_unreferenced(self):
        assert learn({
            "192.168.1.10": nmap_tcp_xml(open_ports=[22]),
            "192.168.1.11": nmap_tcp_xml(ip="192.168.1.11", open_ports=[80]),
        }) is True
        assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[22])}, force=True) is True
        assert raw("SELECT ip FROM assets") == [("192.168.1.10",)]
        assert stored_ports() == {"192.168.1.10": [22]}

    def test_asset_referenced_by_an_event_survives_relearn(self):
        assert learn({
            "192.168.1.10": nmap_tcp_xml(open_ports=[22]),
            "192.168.1.11": nmap_tcp_xml(ip="192.168.1.11", open_ports=[80]),
        }) is True
        gone_asset = raw("SELECT asset_id FROM baseline b JOIN assets a ON a.id=b.asset_id "
                         "WHERE a.ip='192.168.1.11'")[0][0]
        db.sentinel_save_event(SESSION, "evt-keep", "new_port", "2026-10-29T00:00:00+00:00",
                               gone_asset, {}, False)
        assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[22])}, force=True) is True
        assert raw("SELECT id FROM assets WHERE id=?", (gone_asset,)) == [(gone_asset,)]
        assert raw("SELECT asset_id FROM events WHERE id='evt-keep'") == [(gone_asset,)]

    def test_historic_duplicate_asset_is_pruned(self):
        assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[22])}) is True
        db.sentinel_save_asset(SESSION, "dup-old", "192.168.1.10", "2026-01-01T00:00:00+00:00")
        assert learn({"192.168.1.10": nmap_tcp_xml(open_ports=[22])}, force=True) is True
        assert raw("SELECT COUNT(*) FROM assets WHERE ip='192.168.1.10'")[0][0] == 1
        assert raw("SELECT COUNT(*) FROM assets WHERE id='dup-old'")[0][0] == 0


# ---------------------------------------------------------------------------
# B7 — ping discovery failures are handled, not raised
# ---------------------------------------------------------------------------

class TestB7PingFailures:
    def _run_real_ping(self, side_effect=None, stdout="", returncode=0):
        if side_effect is not None:
            run = patch("recon.device_fingerprint.subprocess.run", side_effect=side_effect)
        else:
            run = patch("recon.device_fingerprint.subprocess.run",
                        return_value=CompletedProcess(["nmap"], returncode, stdout=stdout, stderr=""))
        with run:
            return learn_baseline(NET, SESSION, IDENTITY)

    def test_malformed_ping_xml_is_handled(self):
        assert self._run_real_ping(stdout="not xml <<<") is False
        assert not baseline_exists(SESSION, IDENTITY)

    def test_missing_nmap_is_handled(self):
        assert self._run_real_ping(side_effect=FileNotFoundError("nmap")) is False
        assert not baseline_exists(SESSION, IDENTITY)

    def test_unexpected_programming_error_is_not_masked(self):
        with pytest.raises(RuntimeError):
            self._run_real_ping(side_effect=RuntimeError("bug"))


# ---------------------------------------------------------------------------
# C1 — ip neigh fallback on the baseline path, no probe, no silent absence
# ---------------------------------------------------------------------------

def neigh_run(outcomes):
    """Stub subprocess.run: outcomes maps the tool name to an exception or (rc, stdout)."""
    calls = []

    def run(cmd, *args, **kwargs):
        calls.append(cmd[0])
        outcome = outcomes.get(cmd[0])
        if outcome is None:
            raise AssertionError(f"unexpected command: {cmd!r}")
        if isinstance(outcome, BaseException):
            raise outcome
        rc, stdout = outcome
        return CompletedProcess(cmd, rc, stdout=stdout, stderr="")

    return run, calls


class TestC1ArpFallback:
    IP = "192.168.1.1"

    def _mac(self, outcomes):
        run, calls = neigh_run(outcomes)
        with patch("sentinel.baseline.subprocess.run", side_effect=run):
            mac = REAL_GET_ARP_MAC(self.IP)
        return mac, calls

    def test_arp_entry_is_used_and_ip_neigh_not_consulted(self):
        mac, calls = self._mac({"arp": (0, f"{self.IP} ether AA:BB:CC:DD:EE:01 C eth0\n")})
        assert mac == "aa:bb:cc:dd:ee:01"
        assert calls == ["arp"]

    def test_missing_arp_falls_back_to_ip_neigh(self):
        mac, calls = self._mac({
            "arp": FileNotFoundError("arp"),
            "ip": (0, f"{self.IP} dev eth0 lladdr aa:bb:cc:dd:ee:02 REACHABLE\n"),
        })
        assert mac == "aa:bb:cc:dd:ee:02"
        assert calls == ["arp", "ip"]

    def test_ip_neigh_entry_for_another_ip_is_ignored(self):
        mac, _ = self._mac({
            "arp": FileNotFoundError("arp"),
            "ip": (0, "192.168.1.7 dev eth0 lladdr aa:bb:cc:dd:ee:03 STALE\n"),
        })
        assert mac == ""

    def test_ip_neigh_failed_or_incomplete_entries_are_unknown(self):
        mac, _ = self._mac({
            "arp": FileNotFoundError("arp"),
            "ip": (0, f"{self.IP} dev eth0  FAILED\n{self.IP} dev eth0  INCOMPLETE\n"),
        })
        assert mac == ""

    def test_no_arp_and_no_ip_is_unknown_with_message(self, capsys):
        mac, _ = self._mac({
            "arp": FileNotFoundError("arp"),
            "ip": FileNotFoundError("ip"),
        })
        assert mac == ""
        assert "No usable ARP tool" in capsys.readouterr().out

    def test_ip_neigh_error_is_unknown(self):
        mac, _ = self._mac({"arp": FileNotFoundError("arp"), "ip": (1, "")})
        assert mac == ""

    def test_arp_without_entry_does_not_fall_back(self):
        mac, calls = self._mac({"arp": (1, f"{self.IP} (192.168.1.1) -- no entry\n")})
        assert mac == ""
        assert calls == ["arp"]

    def test_conflicting_arp_entries_are_unknown(self):
        mac, _ = self._mac({"arp": (0, (
            f"{self.IP} ether aa:bb:cc:dd:ee:01 C eth0\n"
            f"{self.IP} ether aa:bb:cc:dd:ee:09 C wlan0\n"
        ))})
        assert mac == ""

    def test_learn_stores_the_fallback_mac(self):
        run, _ = neigh_run({
            "arp": FileNotFoundError("arp"),
            "ip": (0, "192.168.1.10 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n"),
        })
        with patch("sentinel.baseline.subprocess.run", side_effect=run), \
             patch("sentinel.baseline._get_arp_mac", side_effect=REAL_GET_ARP_MAC):
            ok = learn({"192.168.1.10": nmap_tcp_xml(open_ports=[22])})
        assert ok is True
        entry = get_baseline(SESSION, IDENTITY)["192.168.1.10"]
        assert entry.mac == "11:22:33:44:55:66"


# ---------------------------------------------------------------------------
# Sentinel scan contract used by the monitor (B3, B4)
# ---------------------------------------------------------------------------

def monitor_open_ports(completed=None, side_effect=None, ip="192.168.1.10"):
    run = (patch("detect.tcp_scan.subprocess.run", side_effect=side_effect) if side_effect
           else patch("detect.tcp_scan.subprocess.run", return_value=completed))
    with run:
        return _get_open_ports(ip)


def _done(stdout, rc=0):
    return CompletedProcess(["nmap"], rc, stdout=stdout, stderr="")


class TestSentinelScanContract:
    def test_monitor_zero_open_ports_is_a_valid_empty_result(self):
        assert monitor_open_ports(_done(nmap_tcp_xml())) == []

    def test_monitor_open_ports_are_returned(self):
        assert monitor_open_ports(_done(nmap_tcp_xml(open_ports=[443, 22]))) == [22, 443]

    @pytest.mark.parametrize("rc", [1, 2])
    def test_monitor_non_zero_exit_is_unknown_even_with_complete_xml(self, rc):
        assert monitor_open_ports(_done(nmap_tcp_xml(open_ports=[22]), rc=rc)) is None

    def test_monitor_malformed_xml_with_exit_zero_is_unknown(self):
        """B3: previously malformed XML with exit 0 became [] and advanced the check."""
        assert monitor_open_ports(_done("not xml <<<")) is None

    def test_monitor_partial_xml_is_unknown(self):
        """B4: a truncated table must not be read as 'only port 22 is open'."""
        assert monitor_open_ports(_done(nmap_tcp_xml(open_ports=[22], omit_extraports=True))) is None

    def test_monitor_timeout_and_missing_nmap_are_unknown(self):
        assert monitor_open_ports(side_effect=subprocess.TimeoutExpired("nmap", 300)) is None
        assert monitor_open_ports(side_effect=FileNotFoundError("nmap")) is None

    def test_monitor_other_host_in_xml_is_unknown(self):
        xml = nmap_tcp_xml(open_ports=[22], extra_host_ip="192.168.1.99")
        assert monitor_open_ports(_done(xml)) is None

    def test_monitor_xml_for_another_address_is_unknown(self):
        assert monitor_open_ports(_done(nmap_tcp_xml(ip="192.168.1.50", open_ports=[22]))) is None

    def test_monitor_repeated_port_is_unknown(self):
        assert monitor_open_ports(_done(nmap_tcp_xml(open_ports=[22], duplicate_port=22))) is None

    def test_monitor_non_numeric_port_id_is_unknown(self):
        assert monitor_open_ports(_done(nmap_tcp_xml(open_ports=[22], port_id_override="abc"))) is None
