"""Real A4 pipeline integration tests.

Only the external nmap subprocess boundary is controlled.  The pipeline,
Finding transformations, local enrichment, scoring, SQLite persistence, and
session lifecycle all execute for real.
"""

from pathlib import Path
from subprocess import CompletedProcess

import pytest

import core.database as db
from cli import PipelineResult, _run_pipeline


PING_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <hostnames><hostname name="lab-host"/></hostnames>
  </host>
</nmaprun>
"""

OS_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <os><osmatch name="Linux 5.x" accuracy="95"/></os>
  </host>
</nmaprun>
"""

TCP_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <scaninfo type="connect" protocol="tcp" numservices="1" services="23"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet" product="Linux telnetd" version="1.0"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1700000000" exit="success" elapsed="1.00"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""

UDP_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open"/>
        <service name="snmp" product="net-snmp" version="5.7"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def real_pipeline_db(tmp_path: Path, monkeypatch):
    def db_path(session_id: str) -> Path:
        return tmp_path / f"{session_id}.db"

    monkeypatch.setattr(db, "get_db_path", db_path)


def test_a4_pipeline_persists_real_findings_and_closes_session(
    real_pipeline_db, monkeypatch
):
    """Run the production pipeline against a real temporary SQLite database."""
    nmap_outputs = iter([PING_XML, OS_XML, TCP_XML, UDP_XML])

    def fake_nmap(*args, **kwargs):
        return CompletedProcess(
            args=args,
            returncode=0,
            stdout=next(nmap_outputs),
            stderr="",
        )

    # This is the external boundary only: all scanner parsers remain real.
    monkeypatch.setattr("recon.device_fingerprint.subprocess.run", fake_nmap)
    monkeypatch.setattr("detect.tcp_scan.subprocess.run", fake_nmap)
    monkeypatch.setattr("detect.udp_scan.subprocess.run", fake_nmap)

    result = PipelineResult()
    findings = _run_pipeline(
        target="192.0.2.0/24",
        profile="normal",
        session="integration-a4-success",
        auto_confirm=True,
        result=result,
    )

    session = db.get_session("integration-a4-success")
    stored_findings = db.get_findings("integration-a4-success")

    assert findings
    assert result.overall_status == "SUCCESS"
    assert session is not None
    assert session["status"] == "completed"
    assert session["discover_status"] == "OK"
    assert session["end_time"] is not None

    assert stored_findings
    assert {finding.target_ip for finding in stored_findings} == {"192.0.2.10"}
    assert {finding.module for finding in stored_findings} >= {
        "device_fingerprint",
        "tcp_scan",
        "udp_scan",
        "misconfig_detection.telnet_exposed",
        "misconfig_detection.snmp_exposed",
    }
    scored_findings = [
        finding for finding in stored_findings
        if finding.module != "device_fingerprint"
    ]
    assert scored_findings
    assert all(finding.risk_score is not None for finding in scored_findings)
    assert len({finding.id for finding in stored_findings}) == len(stored_findings)

    assert any(step.name == "cve_enrichment" for step in result.steps)
    assert any(step.name == "misconfig_detection" for step in result.steps)
    assert any(step.name == "explanation" for step in result.steps)
    assert any(step.name == "risk_scoring" for step in result.steps)
    assert any(step.name == "persist" for step in result.steps)
