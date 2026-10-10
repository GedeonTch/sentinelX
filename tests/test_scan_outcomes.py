"""Per-machine scan outcomes (T20): storage contract and real pipeline runs.

Two levels are covered:
- storage: core/database.py on a temporary SQLite database;
- pipeline: the real `_run_pipeline` on a temporary SQLite database.

In the pipeline tests the only controlled boundary is the nmap subprocess
(`FakeNmap`). Scanner parsers, the pipeline, Findings and persistence run for
real.

IMPORTANT: every XML and exit code used here is SIMULATED. nmap is not installed
in the test sandbox, so none of these results validates real Nmap behaviour.
Lab validation of XML and exit codes is still required.
"""

from pathlib import Path
from subprocess import CompletedProcess

import pytest
import typer

import core.database as db
from cli import PipelineResult, _run_pipeline


SESSION = "t20-storage"
OTHER_SESSION = "t20-storage-other"


@pytest.fixture(autouse=True)
def temp_session_db(tmp_path: Path, monkeypatch):
    """Redirect every session database to a temporary directory."""
    monkeypatch.setattr(
        db, "get_db_path", lambda session_id: tmp_path / f"{session_id}.db"
    )


def _drop_scan_outcomes(session_id: str) -> None:
    """Simulate a session database created before T20 (no scan_outcomes table)."""
    conn = db.get_connection(session_id)
    try:
        conn.execute("DROP TABLE scan_outcomes")
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Storage contract
# ---------------------------------------------------------------------------

class TestScanOutcomeStorage:

    def test_init_creates_an_empty_table(self):
        db.init_db(SESSION)
        assert db.get_scan_outcomes(SESSION) == []

    def test_schema_matches_the_imposed_definition(self):
        db.init_db(SESSION)
        conn = db.get_connection(SESSION)
        try:
            columns = {
                row["name"]: row
                for row in conn.execute("PRAGMA table_info(scan_outcomes)").fetchall()
            }
        finally:
            conn.close()

        assert list(columns) == ["target_ip", "module", "outcome", "open_ports"]
        assert columns["target_ip"]["type"] == "TEXT"
        assert columns["module"]["type"] == "TEXT"
        assert columns["outcome"]["type"] == "TEXT"
        assert columns["open_ports"]["type"] == "INTEGER"
        assert columns["open_ports"]["notnull"] == 1
        assert columns["open_ports"]["dflt_value"] == "0"
        assert {name for name, col in columns.items() if col["pk"]} == {
            "target_ip", "module",
        }

    def test_init_is_idempotent_and_keeps_existing_rows(self):
        db.init_db(SESSION)
        db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", "completed", open_ports=2)
        db.init_db(SESSION)
        db.init_db(SESSION)
        assert db.get_scan_outcomes(SESSION) == [
            {"target_ip": "192.0.2.10", "module": "tcp_scan",
             "outcome": "completed", "open_ports": 2},
        ]

    @pytest.mark.parametrize("outcome", ["completed", "failed", "cancelled"])
    def test_each_outcome_is_stored(self, outcome):
        db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", outcome)
        assert db.get_scan_outcomes(SESSION) == [
            {"target_ip": "192.0.2.10", "module": "tcp_scan",
             "outcome": outcome, "open_ports": 0},
        ]

    def test_completed_with_zero_open_ports_is_a_real_row(self):
        db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", "completed", open_ports=0)
        assert db.get_scan_outcomes(SESSION) == [
            {"target_ip": "192.0.2.10", "module": "tcp_scan",
             "outcome": "completed", "open_ports": 0},
        ]

    def test_retry_replaces_the_previous_outcome_in_the_session(self):
        db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", "failed")
        db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", "completed", open_ports=3)
        assert db.get_scan_outcomes(SESSION) == [
            {"target_ip": "192.0.2.10", "module": "tcp_scan",
             "outcome": "completed", "open_ports": 3},
        ]

    def test_failed_retry_replaces_a_completed_row_and_drops_its_ports(self):
        db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", "completed", open_ports=3)
        db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", "failed")
        assert db.get_scan_outcomes(SESSION) == [
            {"target_ip": "192.0.2.10", "module": "tcp_scan",
             "outcome": "failed", "open_ports": 0},
        ]

    def test_modules_are_kept_apart_for_the_same_machine(self):
        db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", "completed", open_ports=1)
        db.save_scan_outcome(SESSION, "192.0.2.10", "udp_scan", "failed")
        assert [(row["module"], row["outcome"]) for row in db.get_scan_outcomes(SESSION)] == [
            ("tcp_scan", "completed"),
            ("udp_scan", "failed"),
        ]

    @pytest.mark.parametrize("outcome", ["failed", "cancelled"])
    def test_open_ports_are_only_kept_for_completed_scans(self, outcome):
        db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", outcome, open_ports=3)
        assert db.get_scan_outcomes(SESSION)[0]["open_ports"] == 0

    def test_outcomes_are_isolated_per_session(self):
        db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", "completed")
        db.init_db(OTHER_SESSION)
        assert db.get_scan_outcomes(OTHER_SESSION) == []

    @pytest.mark.parametrize("outcome", ["ok", "COMPLETED", "", "partial"])
    def test_unknown_outcome_is_rejected_and_not_written(self, outcome):
        db.init_db(SESSION)
        with pytest.raises(ValueError):
            db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", outcome)
        assert db.get_scan_outcomes(SESSION) == []

    @pytest.mark.parametrize("target_ip, module", [("", "tcp_scan"), ("192.0.2.10", "")])
    def test_empty_identity_is_rejected(self, target_ip, module):
        db.init_db(SESSION)
        with pytest.raises(ValueError):
            db.save_scan_outcome(SESSION, target_ip, module, "completed")
        assert db.get_scan_outcomes(SESSION) == []

    def test_negative_open_ports_is_rejected(self):
        db.init_db(SESSION)
        with pytest.raises(ValueError):
            db.save_scan_outcome(SESSION, "192.0.2.10", "tcp_scan", "completed", open_ports=-1)
        assert db.get_scan_outcomes(SESSION) == []

    def test_session_without_the_table_reports_none_not_an_empty_scan(self):
        db.init_db(SESSION)
        _drop_scan_outcomes(SESSION)
        assert db.get_scan_outcomes(SESSION) is None

    def test_init_adds_the_table_to_an_older_session_without_losing_data(self):
        db.init_db(SESSION)
        db.save_session(SESSION, "192.0.2.0/29", "normal", status="completed")
        _drop_scan_outcomes(SESSION)  # database created before T20

        db.init_db(SESSION)

        assert db.get_scan_outcomes(SESSION) == []
        assert db.get_session(SESSION)["status"] == "completed"


# ---------------------------------------------------------------------------
# Pipeline: real _run_pipeline, simulated nmap subprocess boundary
# ---------------------------------------------------------------------------

RUN_OK = (
    '<runstats><finished time="1700000000" exit="success" elapsed="1.00"/>'
    '<hosts up="1" down="0" total="1"/></runstats>'
)
CLOSED_ONLY_PORTS = (
    '<extraports state="closed" count="1">'
    '<extrareasons reason="conn-refused" count="1" proto="tcp" ports="80"/>'
    "</extraports>"
)
OS_XML = (
    '<?xml version="1.0"?><nmaprun><host>'
    '<os><osmatch name="Linux 5.x" accuracy="95"/></os>'
    "</host></nmaprun>"
)
UDP_NO_HOST = f'<?xml version="1.0"?><nmaprun>{RUN_OK}</nmaprun>'


def ping_xml(ips) -> str:
    hosts = "".join(
        '<host><status state="up" reason="arp-response"/>'
        f'<address addr="{ip}" addrtype="ipv4"/></host>'
        for ip in ips
    )
    return f'<?xml version="1.0"?><nmaprun>{hosts}{RUN_OK}</nmaprun>'


def tcp_open_port_xml(ip: str, port: int = 23) -> str:
    return (
        '<?xml version="1.0"?><nmaprun>'
        f'<scaninfo type="connect" protocol="tcp" numservices="1" services="{port}"/>'
        '<host><status state="up" reason="syn-ack"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>'
        "<ports>"
        f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/>'
        '<service name="telnet" product="Linux telnetd" version="1.0"/></port>'
        "</ports></host>"
        f"{RUN_OK}</nmaprun>"
    )


def tcp_no_open_port_xml(ip: str) -> str:
    return (
        '<?xml version="1.0"?><nmaprun>'
        '<scaninfo type="connect" protocol="tcp" numservices="1" services="80"/>'
        '<host><status state="up" reason="echo-reply"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>'
        f"<ports>{CLOSED_ONLY_PORTS}</ports></host>"
        f"{RUN_OK}</nmaprun>"
    )


def tcp_down_xml(ip: str) -> str:
    return (
        '<?xml version="1.0"?><nmaprun>'
        '<scaninfo type="connect" protocol="tcp" numservices="1" services="80"/>'
        '<host><status state="down" reason="no-response"/>'
        f'<address addr="{ip}" addrtype="ipv4"/></host>'
        '<runstats><finished time="1700000000" exit="success" elapsed="1.00"/>'
        '<hosts up="0" down="1" total="1"/></runstats>'
        "</nmaprun>"
    )


def udp_open_port_xml(ip: str, port: int = 161) -> str:
    return (
        '<?xml version="1.0"?><nmaprun><host>'
        '<status state="up" reason="echo-reply"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>'
        "<ports>"
        f'<port protocol="udp" portid="{port}"><state state="open" reason="udp-response"/>'
        '<service name="snmp" product="net-snmp" version="5.7"/></port>'
        "</ports></host>"
        f"{RUN_OK}</nmaprun>"
    )


def _done(stdout: str, returncode: int = 0) -> CompletedProcess:
    return CompletedProcess(args=["nmap"], returncode=returncode, stdout=stdout, stderr="")


class FakeNmap:
    """Simulated nmap subprocess: the only controlled boundary of these tests.

    The command line selects the scan: "-sn" is the discovery ping, "-O" the
    OS pass, "-sU" the UDP scan, anything else the TCP scan. Behaviour per
    target is an XML string (exit 0), a CompletedProcess (exit code and output
    as given), or an exception raised by the call.

    The order in which the pipeline visits machines is not guaranteed (it
    comes from a set), so `tcp_sequence` applies to the first TCP calls in
    call order, whatever the machine: each item is a behaviour or a function
    of the target IP. Later TCP calls use the per-target mapping `tcp`.
    """

    def __init__(self, ping_hosts=(), tcp=None, udp=None, ping=None,
                 tcp_sequence=(), udp_sequence=()):
        self.ping_hosts = list(ping_hosts)
        self.tcp = dict(tcp or {})
        self.udp = dict(udp or {})
        self.ping = ping
        self.tcp_sequence = list(tcp_sequence)
        self.udp_sequence = list(udp_sequence)
        self.calls = []

    def __call__(self, cmd, *args, **kwargs):
        if "-sn" in cmd:
            self.calls.append(("ping", None))
            if self.ping is not None:
                return self.ping
            return _done(ping_xml(self.ping_hosts))
        if "-O" in cmd:
            self.calls.append(("os", cmd[-1]))
            return _done(OS_XML)

        target = cmd[-1]
        if "-sU" in cmd:
            self.calls.append(("udp", target))
            if self.udp_sequence:
                item = self.udp_sequence.pop(0)
                behaviour = item(target) if callable(item) else item
            else:
                behaviour = self.udp.get(target, UDP_NO_HOST)
        else:
            self.calls.append(("tcp", target))
            if self.tcp_sequence:
                item = self.tcp_sequence.pop(0)
                behaviour = item(target) if callable(item) else item
            else:
                behaviour = self.tcp.get(target, tcp_no_open_port_xml(target))

        if isinstance(behaviour, BaseException):
            raise behaviour
        if isinstance(behaviour, CompletedProcess):
            return behaviour
        return _done(behaviour)


@pytest.fixture
def run_real_pipeline(monkeypatch):
    """Run the production pipeline with the simulated nmap boundary."""

    def run(session: str, fake: FakeNmap):
        for module in ("recon.device_fingerprint", "detect.tcp_scan", "detect.udp_scan"):
            monkeypatch.setattr(f"{module}.subprocess.run", fake)
        result = PipelineResult()
        findings = _run_pipeline(
            target="192.0.2.0/29",
            profile="normal",
            session=session,
            auto_confirm=True,
            result=result,
        )
        return findings, result

    return run


def _scanned_tcp_targets(fake: FakeNmap) -> list:
    """TCP targets in the order the pipeline actually visited them."""
    return [target for kind, target in fake.calls if kind == "tcp"]


def _tcp_rows(session: str) -> dict:
    return {
        row["target_ip"]: (row["outcome"], row["open_ports"])
        for row in db.get_scan_outcomes(session)
        if row["module"] == "tcp_scan"
    }


def _udp_rows(session: str) -> dict:
    return {
        row["target_ip"]: (row["outcome"], row["open_ports"])
        for row in db.get_scan_outcomes(session)
        if row["module"] == "udp_scan"
    }


MATRIX_HOSTS = ["192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.40", "192.0.2.50"]


def _matrix_fake() -> FakeNmap:
    return FakeNmap(
        ping_hosts=MATRIX_HOSTS,
        tcp={
            "192.0.2.10": tcp_open_port_xml("192.0.2.10"),
            "192.0.2.20": tcp_no_open_port_xml("192.0.2.20"),
            "192.0.2.30": tcp_down_xml("192.0.2.30"),
            "192.0.2.40": _done(tcp_no_open_port_xml("192.0.2.40"), returncode=2),
            "192.0.2.50": "<nmaprun><host>",
        },
    )


class TestPipelineScanOutcomes:

    def test_each_machine_gets_the_outcome_its_scan_proved(self, run_real_pipeline):
        session = "t20-matrix"
        findings, _ = run_real_pipeline(session, _matrix_fake())

        assert _tcp_rows(session) == {
            "192.0.2.10": ("completed", 1),  # open port, scan completed
            "192.0.2.20": ("completed", 0),  # zero open ports is still completed
            "192.0.2.30": ("failed", 0),     # host reported DOWN
            "192.0.2.40": ("failed", 0),     # nmap exit code 2 is rejected
            "192.0.2.50": ("failed", 0),     # invalid XML
        }

        stored = db.get_findings(session)
        tcp_findings = [f for f in stored if f.module == "tcp_scan"]
        assert [f.target_ip for f in tcp_findings] == ["192.0.2.10"]
        # Every machine is observed (device_fingerprint), whatever its TCP outcome.
        assert {f.target_ip for f in stored if f.module == "device_fingerprint"} == set(
            MATRIX_HOSTS
        )

    def test_completed_open_ports_equal_the_persisted_tcp_findings(self, run_real_pipeline):
        session = "t20-open-ports"
        tcp = {
            "192.0.2.10": tcp_open_port_xml("192.0.2.10", port=23),
        }
        run_real_pipeline(session, FakeNmap(ping_hosts=["192.0.2.10"], tcp=tcp))

        stored = [f for f in db.get_findings(session) if f.module == "tcp_scan"]
        assert len(stored) == 1
        assert _tcp_rows(session) == {"192.0.2.10": ("completed", 1)}

    def test_udp_rows_follow_the_same_per_machine_rules(self, run_real_pipeline):
        session = "t20-udp"
        fake = FakeNmap(
            ping_hosts=["192.0.2.10", "192.0.2.20"],
            udp={"192.0.2.20": _done("", returncode=1)},  # UDP exit code != 0
        )
        run_real_pipeline(session, fake)

        assert _udp_rows(session) == {
            "192.0.2.10": ("completed", 0),
            "192.0.2.20": ("failed", 0),
        }

    def test_udp_down_host_stays_completed_t13_limitation(self, run_real_pipeline):
        """T13 policy unchanged: a DOWN host with no UDP output is 'completed'.

        This pins a documented limitation, not a validated Nmap behaviour.
        """
        session = "t20-udp-down"
        fake = FakeNmap(
            ping_hosts=["192.0.2.10"],
            tcp={"192.0.2.10": tcp_down_xml("192.0.2.10")},
        )
        run_real_pipeline(session, fake)

        assert _tcp_rows(session) == {"192.0.2.10": ("failed", 0)}
        assert _udp_rows(session) == {"192.0.2.10": ("completed", 0)}

    def test_empty_discovery_records_no_machine(self, run_real_pipeline):
        session = "t20-empty"
        findings, _ = run_real_pipeline(session, FakeNmap(ping_hosts=[]))

        assert findings == []
        assert db.get_session(session)["discover_status"] == "EMPTY"
        assert db.get_scan_outcomes(session) == []  # no artificial 'completed' row

    def test_failed_discovery_records_no_machine(self, run_real_pipeline):
        session = "t20-discover-failed"
        run_real_pipeline(session, FakeNmap(ping=_done("", returncode=1)))

        assert db.get_session(session)["discover_status"] == "FAILED"
        assert db.get_scan_outcomes(session) == []

    @pytest.mark.parametrize("interrupt", [KeyboardInterrupt, typer.Abort])
    def test_interruption_records_cancelled_for_the_host_in_progress(
        self, run_real_pipeline, interrupt
    ):
        session = f"t20-interrupt-{interrupt.__name__}"
        fake = FakeNmap(
            ping_hosts=MATRIX_HOSTS[:3],
            tcp_sequence=[tcp_open_port_xml, lambda ip: interrupt()],
        )
        with pytest.raises(interrupt):
            run_real_pipeline(session, fake)

        first, interrupted = _scanned_tcp_targets(fake)
        assert _tcp_rows(session) == {
            first: ("completed", 1),
            interrupted: ("cancelled", 0),
        }
        # The third machine was never reached: no row at all.
        assert len(_scanned_tcp_targets(fake)) == 2

    def test_tcp_ports_of_a_completed_host_are_stored_before_a_later_interruption(
        self, run_real_pipeline
    ):
        """A completed row's open_ports must match the findings actually stored."""
        session = "t20-persist-tcp"
        fake = FakeNmap(
            ping_hosts=MATRIX_HOSTS[:3],
            tcp_sequence=[tcp_open_port_xml, lambda ip: KeyboardInterrupt()],
        )
        with pytest.raises(KeyboardInterrupt):
            run_real_pipeline(session, fake)

        first, _ = _scanned_tcp_targets(fake)
        stored = [f for f in db.get_findings(session) if f.module == "tcp_scan"]
        assert _tcp_rows(session)[first] == ("completed", 1)
        assert [f.target_ip for f in stored] == [first]

    def test_udp_ports_of_a_completed_host_are_stored_before_a_later_interruption(
        self, run_real_pipeline
    ):
        # The UDP runner keeps its T13 policy and turns ordinary exceptions into
        # a failed UDP scan, so the interruption used here is KeyboardInterrupt.
        session = "t20-persist-udp"
        fake = FakeNmap(
            ping_hosts=MATRIX_HOSTS[:3],
            udp_sequence=[udp_open_port_xml, lambda ip: KeyboardInterrupt()],
        )
        with pytest.raises(KeyboardInterrupt):
            run_real_pipeline(session, fake)

        first, interrupted = [t for kind, t in fake.calls if kind == "udp"]
        assert _udp_rows(session) == {
            first: ("completed", 1),
            interrupted: ("cancelled", 0),
        }
        stored = [f for f in db.get_findings(session) if f.module == "udp_scan"]
        assert [f.target_ip for f in stored] == [first]

    def test_unexpected_exception_records_failed_then_propagates(self, run_real_pipeline):
        session = "t20-unexpected"
        fake = FakeNmap(
            ping_hosts=MATRIX_HOSTS[:3],
            tcp_sequence=[
                tcp_no_open_port_xml,
                lambda ip: RuntimeError("programming error"),
            ],
        )
        with pytest.raises(RuntimeError, match="programming error"):
            run_real_pipeline(session, fake)

        first, failed = _scanned_tcp_targets(fake)
        assert _tcp_rows(session) == {
            first: ("completed", 0),
            failed: ("failed", 0),
        }
        # The third machine was never reached: no row at all.
        assert len(_scanned_tcp_targets(fake)) == 2
