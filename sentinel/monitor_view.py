"""Presentation only. Shared Rich console, bounded live frame, plain log mode."""
from collections import deque
from datetime import datetime
import re
import unicodedata
from typing import Optional
from rich.console import Group
from rich.live import Live
from rich.table import Table
from rich.text import Text
from core.finding import Finding
from core.logger import get_console
from sentinel.monitor import NetworkChange


def safe_text(value):
    # Neutralize terminal control sequences while leaving readable Unicode.
    return ''.join(c if not unicodedata.category(c).startswith('C') else ' ' for c in str(value))


# Plain-log mode: the section title is written once per execution, before the
# first notification. TTY notifications are printed above the live frame, which
# never contains them (no list, no UUID): see MonitorView.emit.
NON_TTY_ALERTS_TITLE = 'Alertes de cette exécution'
NO_NOTIFICATION_LINE = 'Aucune notification affichée pendant cette exécution.'
# T23-B (B2): observations have no Finding and no severity. Shown as a dash.
OBSERVATION_SEVERITY_LABEL = '—'
FINDING_IDENTITY_LABEL = 'UUID du Finding'
EVENT_IDENTITY_LABEL = "UUID de l'événement"
# A check that ended, by outcome. Only 'attente' with a finished timestamp is a success:
# 'dégradé' and 'erreur' ended without recording last_check_time, so they never say "terminé".
CHECK_OUTCOMES = {
    'attente': 'Contrôle terminé',
    'dégradé': 'Contrôle partiel, non enregistré comme réussi',
    'erreur': 'Contrôle en échec, non enregistré comme réussi',
}
# Colour of the Type value of a notification. Presentation only: the persisted
# event type and detail are unchanged. Other types are shown without colour.
EVENT_TYPE_STYLES = {
    'new_host': 'yellow',
    'new_port': 'red',
    'mac_change': 'red',
    'port_not_open': 'cyan',
    'host_not_observed': 'magenta',
    'host_recovered': 'green',
    'scan_degraded': 'bold magenta',
}
# The persisted detail of a closed port is 'port N not open'; it is shown as 'Port N closed'.
_PORT_NOT_OPEN_DETAIL = re.compile(r'port (\d+) not open')


def presentation_detail(change):
    """Detail text to display for a change. The stored change.detail is never modified."""
    if change.change_type == 'port_not_open':
        port = change.port
        if port is None:
            match = _PORT_NOT_OPEN_DETAIL.fullmatch(change.detail or '')
            port = int(match.group(1)) if match else None
        if port is not None:
            return f'Port {port} closed'
    return change.detail


class MonitorView:
    def __init__(self, network, interval, window, console=None, *, session_id):
        self.network, self.interval, self.window = network, interval, window
        self.session_id = session_id
        self.footer_written = False
        self.emitted = 0  # notifications actually written to the terminal, TTY or plain log
        self.cycle_emitted = 0  # notifications written during the current check cycle
        self.console = console or get_console()
        self.rows = deque(maxlen=20)
        self.phase = 'attente'
        self.last_finished = None
        self.live = None

    def header(self):
        active = ('SENTINEL ● FINALISATION' if self.phase in ('finalisation', 'interruption') else
                  'SENTINEL ● ERREUR' if self.phase == 'erreur' else 'SENTINEL ● SURVEILLANCE ACTIVE')
        header = Text(f"{active}\nRéseau : {safe_text(self.network)} | intervalle : {self.interval}s "
                    f"| phase : {self.phase}\nSession Sentinel : {safe_text(self.session_id)}\nDernier contrôle terminé : {self.last_finished or 'non disponible'}")
        header.append('\nCtrl+C pour arrêter. Baseline conservée à l’arrêt.', style='dim')
        return header

    def footer(self):
        return Group(
            Text('Pour consulter un Finding, copiez son UUID complet depuis la liste. '
                 'La session Sentinel est affichée au-dessus et déjà renseignée '
                 'dans la commande ci-dessous.', style='dim'),
            Text(f'sentinel findings show <UUID_COMPLET> -s {self.session_id}',
                 overflow='fold'),
        )

    def notification(self, row):
        """One notification block: no command, full UUID, severity. Never a title."""
        when, host, kind, detail, identity, severity, identity_label = row
        table = Table(show_header=False, expand=True)
        table.add_column(width=8)
        table.add_column(overflow='fold')
        cells = [('Heure', Text(safe_text(when))),
                 ('Hôte', Text(safe_text(host))),
                 ('Type', Text(safe_text(kind), style=EVENT_TYPE_STYLES.get(kind, ''))),
                 ('Détail', Text(safe_text(detail))),
                 ('Sévérité', Text(safe_text(severity)))]
        for key, cell in cells:
            table.add_row(key, cell)
        # No borders or ellipsis; narrow terminals wrap without losing characters.
        return Group(table, Text(f'{identity_label} :', style='dim'),
                     Text(identity, overflow='fold'))

    def hosts(self):
        return self._host_table(sorted(self.window.summary().items()))

    def _host_table(self, items):
        if self.console.width < 60:
            table = Table(title='Hôtes — 60 min', show_header=False, expand=True)
            table.add_column(width=8)
            table.add_column(overflow='fold')
            for host, row in items:
                for key, value in [('Hôte', host), ('Affichées', row['displayed']),
                                   ('Masquées', row['masked']), ('Réserves', row['reserved']),
                                   ('État', row['state'])]:
                    table.add_row(key, Text(safe_text(value)))
            return table
        table = Table(title='État des hôtes — fenêtre glissante de 60 min', expand=True)
        for column in ('Hôte', 'Affichées (60 min)', 'Masquées (60 min)', 'État'):
            table.add_column(column, overflow='fold')
        for host, row in items:
            state = row['state']
            if row['reserved']:
                state += f" · {row['reserved']} réserve(s), dont {row['unknown']} inconnue(s)"
            table.add_row(Text(safe_text(host)), str(row['displayed']), str(row['masked']), Text(state))
        return table

    def _frame(self, hosts, hidden):
        parts = [self.header(),
                 Text(f'Notifications affichées cette exécution : {self.emitted}'),
                 self._host_table(hosts)]
        if hidden:
            parts.append(Text(f'{hidden} hôte(s) non affiché(s) dans ce cadre : hauteur du terminal insuffisante.',
                              style='dim'))
        parts.append(self.footer())
        return Group(*parts)

    def __rich_console__(self, console, options):
        # Re-evaluated on each refresh (expiry against the clock), no DB access.
        # The frame never exceeds the terminal height: the host table keeps as many
        # hosts as fit (binary search on the rendered height; height grows with hosts)
        # and the hidden ones are announced. Notifications are not part of the frame.
        hosts = sorted(self.window.summary().items())
        # One row stays free: Live.stop() ends with a newline, and a frame using the
        # full height would scroll its own header into the scrollback.
        budget = options.size.height - 1

        def frame(count):
            return self._frame(hosts[:count], len(hosts) - count)

        def height(count):
            return len(console.render_lines(frame(count), options, pad=False))

        low, high, best = 0, len(hosts), 0
        while low <= high:
            middle = (low + high) // 2
            if height(middle) <= budget:
                best, low = middle, middle + 1
            else:
                high = middle - 1
        yield frame(best)

    def __enter__(self):
        if self.console.is_terminal:
            self.live = Live(self, console=self.console, refresh_per_second=1,
                             redirect_stdout=False, redirect_stderr=False,
                             vertical_overflow='visible')
            try:
                self.live.start(refresh=True)
            except BaseException:
                try:
                    self.live.stop()
                except Exception:
                    pass
                raise
        else:
            self.console.print(self.header(), Text(NON_TTY_ALERTS_TITLE), self.hosts())
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.phase = 'finalisation'
        else:
            self.phase = 'erreur' if exc_type is not KeyboardInterrupt else 'interruption'
        try:
            if self.live is not None:
                self.live.stop()
            elif not self.footer_written:
                self.footer_written = True
                if self.emitted == 0:
                    self.console.print(Text(NO_NOTIFICATION_LINE))
                self.console.print(self.footer())
                self.console.file.flush()
        except BaseException:
            if exc_type is None:
                raise
        return False

    def set_phase(self, phase, finished=None):
        self.phase = phase
        if finished is not None:
            self.last_finished = finished
        if self.live is not None:
            self.live.refresh()
        if phase == 'contrôle':
            self.cycle_emitted = 0  # a new cycle starts; count only its own notifications
        elif finished is not None and phase in CHECK_OUTCOMES:
            # The check ended. TTY shows it in the frame; plain log gets exactly one line for it.
            if self.live is None:
                self._progress_line(phase, finished)
            self.cycle_emitted = 0

    def _progress_line(self, phase, finished):
        try:
            when = datetime.fromisoformat(finished).astimezone().strftime('%H:%M:%S')
        except (TypeError, ValueError):
            when = 'heure inconnue'
        count = self.cycle_emitted
        summary = (f'{count} notification(s) affichée(s) pendant ce contrôle' if count
                   else 'aucune notification affichée pendant ce contrôle')
        # soft_wrap: one check = one physical line, whatever the redirected terminal width.
        self.console.print(Text(f'[{when}] {CHECK_OUTCOMES[phase]} — {summary}.'), soft_wrap=True)
        self.console.file.flush()

    def emit(self, when, change: NetworkChange, finding: Optional[Finding] = None, *,
             event_id: Optional[str] = None, session_id: Optional[str] = None) -> None:
        """Display one notification.

        With a Finding: identity is the Finding UUID and the severity is its severity.
        Without a Finding (T23-B observation, B2): identity is the event UUID and the
        severity is the dash label. No Finding is invented.
        """
        if finding is not None:
            if finding.session_id != self.session_id:
                raise ValueError('Finding session differs from monitor session')
            identity, severity, label = finding.id, finding.severity.value.upper(), FINDING_IDENTITY_LABEL
        else:
            if not event_id:
                raise ValueError('An observation without Finding needs its event_id')
            if session_id is not None and session_id != self.session_id:
                raise ValueError('Event session differs from monitor session')
            identity, severity, label = event_id, OBSERVATION_SEVERITY_LABEL, EVENT_IDENTITY_LABEL
        row = (when, change.asset_ip, change.change_type, presentation_detail(change),
               identity, severity, label)
        self.rows.append(row)
        try:
            # Written once, at emission. In TTY, Rich prints it above the live frame and
            # redraws the frame below it; in plain log, this block alone is written.
            self.console.print(self.notification(row))
            self.emitted += 1
            self.cycle_emitted += 1
            if self.live is not None:
                self.live.refresh()  # updates the notification counter in the frame
            self.console.file.flush()
        except BaseException:
            self.rows.pop()
            raise
