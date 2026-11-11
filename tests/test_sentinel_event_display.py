"""Presentation of Sentinel events: colour of the Type value and the 'Port N closed' label.

Presentation only. The persisted event type and detail are not changed: the
detail stored by the manager stays 'port N not open'.
"""
import io

import pytest
from rich.console import Console
from rich.text import Text

import core.database as db
from sentinel import alerting
from sentinel.alerting import AlertCounter, EventStamp, process_changes
from sentinel.monitor import NetworkChange
from sentinel.monitor_view import EVENT_TYPE_STYLES, MonitorView, presentation_detail
from sentinel.whitelist import Whitelist
from tests.test_sentinel_notifications import store, NET, HOST, RUN  # noqa: F401  (store fixture)


SPECIFIED_STYLES = {
    'new_host': 'yellow',
    'new_port': 'red',
    'mac_change': 'red',
    'port_not_open': 'cyan',
    'host_not_observed': 'magenta',
    'host_recovered': 'green',
    'scan_degraded': 'bold magenta',
}


def _notification_output(kind):
    """Render one notification with colours enabled, as a terminal would."""
    view = MonitorView(NET, 60, None, console=Console(file=io.StringIO(), width=100), session_id=RUN)
    row = ('12:00:00', HOST, kind, 'detail text', 'identity-1', 'LOW', 'UUID du Finding')
    out = io.StringIO()
    Console(file=out, force_terminal=True, color_system='standard', width=100).print(view.notification(row))
    return out.getvalue()


def _style_codes(style):
    """Escape sequences Rich emits around a Text of this style: (opening, closing)."""
    probe = Console(file=io.StringIO(), force_terminal=True, color_system='standard')
    with probe.capture() as captured:
        probe.print(Text('MARK', style=style))
    rendered = captured.get().rstrip('\n')
    opening, rest = rendered.split('MARK', 1)
    return opening, rest


def _type_line(output):
    """The table line of the Type row. Rich pads the value to the column width, so the
    reset code comes after the padding: the check is on the line, not on adjacent text."""
    return next(line for line in output.splitlines() if '│ Type' in line)


class TestTypeColours:
    def test_mapping_matches_the_specification(self):
        assert EVENT_TYPE_STYLES == SPECIFIED_STYLES

    @pytest.mark.parametrize('kind,style', sorted(SPECIFIED_STYLES.items()))
    def test_type_value_is_coloured(self, kind, style):
        opening, closing = _style_codes(style)
        line = _type_line(_notification_output(kind))
        value_at = line.index(kind)
        assert opening in line, f'{kind}: no {style!r} code on the Type line'
        assert line.index(opening) < value_at, f'{kind}: colour must precede the value'
        assert closing in line[value_at:], f'{kind}: colour must be reset after the value'

    def test_unknown_type_is_shown_without_colour(self):
        line = _type_line(_notification_output('host_ports_initialized'))
        assert '\x1b[' not in line


class TestClosedPortLabel:
    def test_closed_port_is_labelled_closed(self):
        change = NetworkChange('port_not_open', HOST, 'port 80 not open', 'evidence', port=80)
        assert presentation_detail(change) == 'Port 80 closed'

    def test_label_is_derived_from_stored_detail_when_port_field_is_missing(self):
        change = NetworkChange('port_not_open', HOST, 'port 22 not open', 'evidence')
        assert presentation_detail(change) == 'Port 22 closed'

    def test_other_types_keep_their_detail(self):
        change = NetworkChange('new_port', HOST, 'port 8080 opened', 'evidence', port=8080)
        assert presentation_detail(change) == 'port 8080 opened'

    def test_stored_detail_is_not_modified(self):
        change = NetworkChange('port_not_open', HOST, 'port 80 not open', 'evidence', port=80)
        presentation_detail(change)
        assert change.detail == 'port 80 not open'

    def test_monitor_view_shows_closed_label_and_keeps_the_stored_detail(self, store):
        counter = AlertCounter(clock=store)
        counter.bind(NET)
        change = NetworkChange('port_not_open', HOST, 'port 80 not open', 'evidence', port=80)
        out = io.StringIO()
        with MonitorView(NET, 60, counter, Console(file=out, width=100), session_id=RUN) as view:
            view.emit('12:00:00', change, event_id='evt-1', session_id=RUN)
        assert 'Port 80 closed' in out.getvalue()
        assert 'not open' not in out.getvalue()
        assert view.rows[-1][3] == 'Port 80 closed'
        assert view.rows[-1][4] == 'evt-1'
        assert change.detail == 'port 80 not open'

    def test_standalone_fallback_uses_the_closed_label(self, monkeypatch):
        shown = []
        monkeypatch.setattr(alerting, 'display', lambda message: shown.append(message))
        change = NetworkChange('port_not_open', HOST, 'port 80 not open', 'evidence', port=80)
        alerting._display_observation(change)
        assert shown[-1].plain == f'[INFO] {HOST} — Port 80 closed'

    def test_standalone_fallback_keeps_other_observations(self, monkeypatch):
        shown = []
        monkeypatch.setattr(alerting, 'display', lambda message: shown.append(message))
        change = NetworkChange('host_not_observed', HOST, 'host not observed', 'evidence')
        alerting._display_observation(change)
        assert shown[-1].plain == f'[INFO] {HOST} — host not observed'


class TestTerminalAndPersistence:
    def test_tty_console_shows_closed_label(self, store):
        counter = AlertCounter(clock=store)
        counter.bind(NET)
        change = NetworkChange('port_not_open', HOST, 'port 80 not open', 'evidence', port=80)
        out = io.StringIO()
        view = MonitorView(NET, 60, counter, Console(file=out, force_terminal=True,
                                                    color_system='standard', width=100),
                           session_id=RUN)
        view.emit('12:00:00', change, event_id='evt-tty', session_id=RUN)  # no live frame here
        assert 'Port 80 closed' in out.getvalue()
        assert 'not open' not in out.getvalue()

    def test_unauthorised_closed_port_fallback_and_stored_detail(self, store, monkeypatch):
        shown = []
        monkeypatch.setattr(alerting, 'display', lambda message: shown.append(message))
        counter = AlertCounter(clock=store)
        change = NetworkChange('port_not_open', HOST, 'port 80 not open', 'evidence', port=80)
        process_changes([change], RUN, Whitelist(), counter, network_id=NET,
                        stamp=EventStamp(NET, clock=counter.clock))
        assert shown[-1].plain == f'[INFO] {HOST} — Port 80 closed'
        events = [e for e in db.sentinel_get_events(NET) if e['type'] == 'port_not_open']
        assert len(events) == 1
        assert events[0]['details']['detail'] == 'port 80 not open'
        assert events[0]['resolved'] == 0
        assert db.get_findings(RUN) == []

    def test_authorised_new_port_keeps_detail_label_and_resolution(self, store, monkeypatch):
        shown = []
        monkeypatch.setattr(alerting, 'display', lambda message: shown.append(message))
        counter = AlertCounter(clock=store)
        whitelist = Whitelist(allowed_port_changes=[{'host': HOST, 'ports': [4444]}])
        change = NetworkChange('new_port', HOST, 'port 4444 opened', 'evidence', port=4444)
        process_changes([change], RUN, whitelist, counter, network_id=NET,
                        stamp=EventStamp(NET, clock=counter.clock))
        assert shown[-1].plain == f'[INFO] {HOST} — port 4444 opened (changement autorisé / whitelisté)'
        events = [e for e in db.sentinel_get_events(NET) if e['type'] == 'new_port']
        assert len(events) == 1
        assert events[0]['details']['detail'] == 'port 4444 opened'
        assert events[0]['resolved'] == 1
        assert db.get_findings(RUN) == []

