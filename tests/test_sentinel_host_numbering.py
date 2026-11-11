"""Host table of the Sentinel monitor: a first 'N°' column (or 'N°' row in narrow mode).

Presentation only. Numbers are 1..n in the existing display order, computed on each
render. Notifications, Findings and persisted data are not numbered or changed.
"""
import copy
import io
import re

from rich.console import Console

from sentinel.monitor_view import MonitorView

NET = '192.0.2.0/24'
SESSION = 'session-numbering'

WIDE_ROW = re.compile(r'│\s*(\d+)\s*│\s*(\d{1,3}(?:\.\d{1,3}){3})\s*│')
NARROW_NUMBER = re.compile(r'│ N° +│ (\d+) +│')
NARROW_HOST = re.compile(r'│ Hôte +│ (\S+) +│')


class FakeWindow:
    """Stands in for the notification window: only summary() is used by the view."""

    def __init__(self, hosts=()):
        self.hosts = {}
        for host in hosts:
            self.add(host)

    def add(self, host, displayed=0, masked=0, reserved=0, unknown=0, state='actif'):
        self.hosts[host] = dict(displayed=displayed, masked=masked, reserved=reserved,
                                unknown=unknown, state=state)

    def remove(self, host):
        del self.hosts[host]

    def summary(self):
        return dict(self.hosts)


def _view(window, width=100):
    return MonitorView(NET, 60, window, console=Console(file=io.StringIO(), width=width),
                       session_id=SESSION)


def _render(renderable, width=100, height=None):
    out = io.StringIO()
    Console(file=out, width=width, height=height, color_system=None).print(renderable)
    return out.getvalue()


def _wide_pairs(text):
    return [(int(number), host) for number, host in WIDE_ROW.findall(text)]


def _narrow_pairs(text):
    pairs, number = [], None
    for line in text.splitlines():
        found = NARROW_NUMBER.search(line)
        if found:
            number = int(found.group(1))
        found = NARROW_HOST.search(line)
        if found:
            pairs.append((number, found.group(1)))
    return pairs


class TestSequentialNumbering:
    def test_wide_table_numbers_hosts_from_one_in_display_order(self):
        window = FakeWindow(['192.0.2.12', '192.0.2.10', '192.0.2.11'])
        pairs = _wide_pairs(_render(_view(window).hosts()))
        assert pairs == [(1, '192.0.2.10'), (2, '192.0.2.11'), (3, '192.0.2.12')]

    def test_numbering_follows_the_existing_display_order_not_numeric_order(self):
        # The monitor sorts host keys as text: '192.0.2.20' precedes '192.0.2.3'.
        window = FakeWindow(['192.0.2.3', '192.0.2.20'])
        pairs = _wide_pairs(_render(_view(window).hosts()))
        assert pairs == [(1, '192.0.2.20'), (2, '192.0.2.3')]

    def test_narrow_table_numbers_each_host_block(self):
        window = FakeWindow(['192.0.2.11', '192.0.2.10'])
        pairs = _narrow_pairs(_render(_view(window, width=50).hosts(), width=50))
        assert pairs == [(1, '192.0.2.10'), (2, '192.0.2.11')]

    def test_numbers_follow_the_list_when_it_changes(self):
        window = FakeWindow(['192.0.2.10', '192.0.2.11', '192.0.2.12'])
        view = _view(window)
        assert _wide_pairs(_render(view.hosts())) == [
            (1, '192.0.2.10'), (2, '192.0.2.11'), (3, '192.0.2.12')]

        window.add('192.0.2.1')  # sorts first: every later host moves down one number
        assert _wide_pairs(_render(view.hosts())) == [
            (1, '192.0.2.1'), (2, '192.0.2.10'), (3, '192.0.2.11'), (4, '192.0.2.12')]

        window.remove('192.0.2.10')
        assert _wide_pairs(_render(view.hosts())) == [
            (1, '192.0.2.1'), (2, '192.0.2.11'), (3, '192.0.2.12')]

    def test_numbers_are_not_stored_in_the_window_rows(self):
        window = FakeWindow(['192.0.2.10', '192.0.2.11'])
        before = copy.deepcopy(window.summary())
        _render(_view(window).hosts())
        assert window.summary() == before


class TestEmptyAndOtherTables:
    def test_empty_wide_table_has_no_numbered_row(self):
        text = _render(_view(FakeWindow()).hosts())
        assert _wide_pairs(text) == []
        assert 'N°' in text  # the header stays, as the table already had no host rows

    def test_empty_narrow_table_has_no_numbered_row(self):
        text = _render(_view(FakeWindow(), width=50).hosts(), width=50)
        assert _narrow_pairs(text) == []

    def test_notifications_are_not_numbered(self):
        view = _view(FakeWindow(['192.0.2.10']))
        row = ('12:00:00', '192.0.2.10', 'new_port', 'port 80 opened', 'id-1', 'LOW',
               'UUID du Finding')
        assert 'N°' not in _render(view.notification(row))


class TestTerminalModes:
    def test_non_tty_output_is_numbered(self):
        window = FakeWindow(['192.0.2.11', '192.0.2.10'])
        out = io.StringIO()
        with MonitorView(NET, 60, window, Console(file=out, width=100), session_id=SESSION):
            pass
        assert _wide_pairs(out.getvalue()) == [(1, '192.0.2.10'), (2, '192.0.2.11')]

    def test_tty_frame_is_numbered(self):
        window = FakeWindow(['192.0.2.11', '192.0.2.10'])
        out = io.StringIO()
        console = Console(file=out, force_terminal=True, color_system=None, width=100, height=40)
        console.print(_view(window))  # rendered as a live frame would be, without Live
        assert _wide_pairs(out.getvalue()) == [(1, '192.0.2.10'), (2, '192.0.2.11')]


class TestHeightLimit:
    def test_limited_frame_numbers_only_the_visible_hosts(self):
        hosts = [f'192.0.2.{i}' for i in range(1, 31)]
        window = FakeWindow(hosts)
        out = io.StringIO()
        console = Console(file=out, force_terminal=True, color_system=None, width=100, height=20)
        console.print(_view(window))
        text = out.getvalue()
        pairs = _wide_pairs(text)
        shown = len(pairs)
        assert 0 < shown < len(hosts), 'the frame must show some hosts and hide others'
        assert [number for number, _ in pairs] == list(range(1, shown + 1))
        assert [host for _, host in pairs] == sorted(hosts)[:shown]
        assert f'{len(hosts) - shown} hôte(s) non affiché(s)' in text
