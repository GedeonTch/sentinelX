"""
tests/test_t24_recon_cli.py — CLI tests for whois, passive-recon and doctor (T24).

The real rendering code runs. Every external source is replaced: DNS resolver,
RDAP fetch, WHOIS function, subprocess (avahi-browse / arp / ip). No network,
no real /etc/hosts, no real avahi.
"""

import json
import socket
import subprocess
from unittest.mock import MagicMock, patch

import dns.resolver
import dns.reversename
import pytest
import typer
from typer.testing import CliRunner

from cli import app
from core.dependencies import OPTIONAL_TOOL_EFFECTS, DependencyCheck, environment_ready
from recon.rdap import BOOTSTRAP_URL, FetchResult

runner = CliRunner()

IP = "192.0.2.10"
PTR_NAME = str(dns.reversename.from_address(IP))


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class Answer:
    def __init__(self, values, aa=True):
        import dns.flags
        from types import SimpleNamespace

        self._values = list(values)
        self.response = SimpleNamespace(flags=dns.flags.AA if aa else 0)

    def __iter__(self):
        return iter(self._values)


class FakeResolver:
    def __init__(self, table):
        self.table = table

    def resolve(self, name, rtype, raise_on_no_answer=True):
        value = self.table.get((name, rtype))
        if value is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(value, BaseException):
            raise value
        return value


def resolver_factory(table):
    resolver = FakeResolver(table)
    return lambda: resolver


def fake_rdap_fetch(domain_object):
    bootstrap = {"services": [[["com"], ["https://rdap.example-com/"]]]}

    def fetch(url):
        if url == BOOTSTRAP_URL:
            return FetchResult(200, {}, json.dumps(bootstrap).encode())
        return FetchResult(200, {}, json.dumps(domain_object).encode())

    return fetch


DOMAIN_OBJECT = {
    "objectClassName": "domain",
    "ldhName": "example.com",
    "status": ["client transfer prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
    "nameservers": [{"ldhName": "ns1.example.net"}],
    "entities": [
        {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Reg Inc"]]]},
    ],
    "redacted": [{
        "name": {"description": "Registrant Name"},
        "prePath": "$.entities[?(@.roles[0]=='registrant')]",
        "method": "removal",
    }],
}


def flat(text):
    """Collapse whitespace: Rich may wrap long cells across lines."""
    return " ".join(text.split())


def fake_run(outputs):
    def run(cmd, **kwargs):
        name = cmd[0]
        if name not in outputs:
            raise FileNotFoundError(name)
        value = outputs[name]
        if isinstance(value, BaseException):
            raise value
        return subprocess.CompletedProcess(cmd, 0, stdout=value, stderr="")
    return run


AVAHI_OUT = (
    "=;eth0;IPv4;My\\032Printer;_ipp._tcp;local;printer.local;192.168.1.50;631;\n"
)
ARP_OUT = "192.168.1.1 ether aa:bb:cc:dd:ee:01 C eth0\n"


# ---------------------------------------------------------------------------
# whois
# ---------------------------------------------------------------------------

class TestWhoisCommand:
    def test_ip_target_shows_ptr_and_no_registration(self):
        table = {(PTR_NAME, "PTR"): Answer(["host.example.net."])}
        with patch("recon.dns_enum._make_resolver", resolver_factory(table)), \
             patch("recon.dns_enum._forward_confirm", return_value=MagicMock()), \
             patch("recon.registration.query_whois") as whois_query:
            result = runner.invoke(app, ["whois", IP])
        assert result.exit_code == 0, result.output
        assert IP in result.output
        assert "host.example.net" in result.output
        whois_query.assert_not_called()

    def test_domain_renders_dns_rdap_and_whois_statuses(self):
        table = {
            ("example.com", "A"): Answer([IP]),
            ("example.com", "MX"): Answer(["10 mx.example.com."], aa=True),
            (PTR_NAME, "PTR"): Answer(["host.example.net."]),
        }
        with patch("recon.dns_enum._make_resolver", resolver_factory(table)), \
             patch("recon.rdap._default_fetch", side_effect=fake_rdap_fetch(DOMAIN_OBJECT)), \
             patch("recon.registration._default_whois", side_effect=socket.timeout()):
            result = runner.invoke(app, ["whois", "example.com"])
        out = flat(result.output)
        assert result.exit_code == 0, result.output
        assert "example.com" in out
        assert "autoritative (AA)" in out
        assert "RDAP : OK" in out
        assert "WHOIS : timeout" in out
        assert "Reg Inc" in out
        assert "Masqué par le registre" in out
        assert "Non communiqué" in out  # RDAP answered: missing fields are not 'timeout'
        # raw data is never printed
        assert "objectClassName" not in out
        assert "{" not in out

    def test_domain_with_no_source_says_absence_is_not_proof(self):
        with patch("recon.dns_enum._make_resolver", resolver_factory({})), \
             patch("recon.rdap._default_fetch", side_effect=RuntimeError("no network")), \
             patch("recon.registration._default_whois", side_effect=OSError("no network")):
            result = runner.invoke(app, ["whois", "example.com"])
        assert result.exit_code == 0, result.output
        assert "ne prouve pas que le domaine" in flat(result.output)

    def test_invalid_target_is_rejected(self):
        result = runner.invoke(app, ["whois", "http://example.com/"])
        assert result.exit_code == 2

    def test_ipv6_target_is_rejected(self):
        result = runner.invoke(app, ["whois", "2001:db8::1"])
        assert result.exit_code == 2

    def test_help_lists_passive_recon(self):
        result = runner.invoke(app, ["--help"])
        assert "passive-recon" in result.output


# ---------------------------------------------------------------------------
# passive-recon
# ---------------------------------------------------------------------------

class TestPassiveReconCommand:
    def test_default_refuses_mdns_and_never_runs_avahi(self, tmp_path):
        run = MagicMock(side_effect=fake_run({"arp": ARP_OUT, "avahi-browse": AVAHI_OUT}))
        with patch("recon.passive_recon.subprocess.run", run), \
             patch("recon.passive_recon.HOSTS_PATH", tmp_path / "absent-hosts"):
            result = runner.invoke(app, ["passive-recon", "--network", "192.168.1.0/24"])
        assert result.exit_code == 0, result.output
        commands = [c.args[0][0] for c in run.call_args_list]
        assert "avahi-browse" not in commands
        assert "non lancé" in flat(result.output)
        assert "192.168.1.1" in result.output

    def test_consent_runs_avahi_and_shows_service(self, tmp_path):
        run = MagicMock(side_effect=fake_run({"arp": ARP_OUT, "avahi-browse": AVAHI_OUT}))
        with patch("recon.passive_recon.subprocess.run", run), \
             patch("recon.passive_recon.HOSTS_PATH", tmp_path / "absent-hosts"), \
             patch("cli._confirm_mdns", return_value=True):
            result = runner.invoke(app, ["passive-recon", "--network", "192.168.1"])
        assert result.exit_code == 0, result.output
        assert "printer.local" in result.output
        assert "_ipp._tcp" in result.output

    def test_missing_avahi_with_consent_is_explicit(self, tmp_path):
        run = MagicMock(side_effect=fake_run({"arp": ARP_OUT}))
        with patch("recon.passive_recon.subprocess.run", run), \
             patch("recon.passive_recon.HOSTS_PATH", tmp_path / "absent-hosts"), \
             patch("cli._confirm_mdns", return_value=True):
            result = runner.invoke(app, ["passive-recon"])
        assert result.exit_code == 0, result.output
        assert "avahi-browse absent" in flat(result.output)
        assert "indisponible" in flat(result.output)

    def test_invalid_network_is_rejected(self):
        result = runner.invoke(app, ["passive-recon", "--network", "192.168.1.5/24"])
        assert result.exit_code == 2

    def test_scan_pipeline_never_calls_passive_recon(self):
        import inspect
        import cli

        assert "passive_recon" not in inspect.getsource(cli.scan)
        assert "collect_passive" not in inspect.getsource(cli.scan)

    def test_confirm_without_terminal_refuses(self):
        with patch("sys.stdin", MagicMock(isatty=MagicMock(return_value=False))), \
             patch("typer.confirm") as confirm:
            from cli import _confirm_mdns
            assert _confirm_mdns() is False
        confirm.assert_not_called()

    def test_ctrl_c_at_prompt_exits_130(self):
        with patch("sys.stdin", MagicMock(isatty=MagicMock(return_value=True))), \
             patch("typer.confirm", side_effect=KeyboardInterrupt):
            from cli import _confirm_mdns
            with pytest.raises(typer.Exit) as exc:
                _confirm_mdns()
        assert exc.value.exit_code == 130


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

def _ready_checks():
    return [
        DependencyCheck(name="python", present=True, version="3.12.3"),
        DependencyCheck(name="nmap", present=True, version="7.94"),
        DependencyCheck(name="enum4linux-ng", present=True, version="0.8.9"),
        DependencyCheck(name=".netlab", present=True, version="/tmp/.netlab"),
    ]


class TestDoctorOptionalTools:
    def test_missing_optional_tools_are_shown_without_failing(self):
        optional = [
            (DependencyCheck(name="arp", present=False), "voisinage ARP"),
            (DependencyCheck(name="ip", present=True, version="6.1"), "repli ARP"),
            (DependencyCheck(name="avahi-browse", present=False), "mDNS indisponible"),
        ]
        with patch("cli.check_environment", return_value=_ready_checks()), \
             patch("cli.check_optional_tools", return_value=optional):
            result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0, result.output
        assert "avahi-browse" in result.output
        assert "mDNS indisponible" in result.output
        assert "Environment is ready." in result.output

    def test_optional_tools_are_declared_with_their_effect(self):
        names = [name for name, _ in OPTIONAL_TOOL_EFFECTS]
        assert names == ["arp", "ip", "avahi-browse"]
        assert all(effect for _, effect in OPTIONAL_TOOL_EFFECTS)

    def test_environment_readiness_ignores_optional_tools(self):
        assert environment_ready(_ready_checks()) is True
