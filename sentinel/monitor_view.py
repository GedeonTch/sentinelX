"""Presentation only. Shared Rich console, bounded live history, plain log mode."""
from collections import deque
import unicodedata
from rich.console import Group
from rich.live import Live
from rich.table import Table
from rich.text import Text
from core.finding import Finding
from core.logger import get_console


def safe_text(value):
    # Neutralize terminal control sequences while leaving readable Unicode.
    return ''.join(c if not unicodedata.category(c).startswith('C') else ' ' for c in str(value))


# Plain-log mode: the section title is written once per execution, before the
# first notification. TTY keeps its live list title unchanged.
NON_TTY_ALERTS_TITLE = 'Alertes de cette exécution'
TTY_ALERTS_TITLE = 'Alertes affichées — 20 dernières de cette exécution'
NO_NOTIFICATION_LINE = 'Aucune notification affichée pendant cette exécution.'


class MonitorView:
    def __init__(self, network, interval, window, console=None, *, session_id):
        self.network, self.interval, self.window = network, interval, window
        self.session_id = session_id
        self.footer_written = False
        self.emitted = 0  # plain-log notifications actually written to the terminal
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
        when, host, kind, detail, finding_id, severity = row
        table = Table(show_header=False, expand=True)
        table.add_column(width=8)
        table.add_column(overflow='fold')
        for key, value in [('Heure', when), ('Hôte', host), ('Type', kind),
                           ('Détail', detail), ('Sévérité', severity)]:
            table.add_row(key, Text(safe_text(value)))
        # No borders or ellipsis; narrow terminals wrap without losing characters.
        return Group(table, Text('UUID du Finding :', style='dim'),
                     Text(finding_id, overflow='fold'))

    def alerts(self, rows):
        items = [Text(TTY_ALERTS_TITLE)]
        if not rows:
            items.append(Text('Aucune notification affichée'))
        for row in rows:
            items.append(self.notification(row))
        return Group(*items)

    def hosts(self):
        if self.console.width < 60:
            table = Table(title='Hôtes — 60 min', show_header=False, expand=True)
            table.add_column(width=8)
            table.add_column(overflow='fold')
            for host, row in sorted(self.window.summary().items()):
                for key, value in [('Hôte', host), ('Affichées', row['displayed']),
                                   ('Masquées', row['masked']), ('Réserves', row['reserved']),
                                   ('État', row['state'])]:
                    table.add_row(key, Text(safe_text(value)))
            return table
        table = Table(title='État des hôtes — fenêtre glissante de 60 min', expand=True)
        for column in ('Hôte', 'Affichées (60 min)', 'Masquées (60 min)', 'État'):
            table.add_column(column, overflow='fold')
        for host, row in sorted(self.window.summary().items()):
            state = row['state']
            if row['reserved']:
                state += f" · {row['reserved']} réserve(s), dont {row['unknown']} inconnue(s)"
            table.add_row(Text(safe_text(host)), str(row['displayed']), str(row['masked']), Text(state))
        return table

    def __rich_console__(self, console, options):
        # Re-evaluate expiry against the clock on refresh, no DB access/threaded writes.
        yield Group(self.header(), self.alerts(list(self.rows)), self.hosts(), self.footer())

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
        else:
            self.console.print(self.header(), self.hosts())  # never replay old alerts

    def emit(self, when, change, finding: Finding):
        if finding.session_id != self.session_id:
            raise ValueError('Finding session differs from monitor session')
        row = (when, change.asset_ip, change.change_type, change.detail,
               finding.id, finding.severity.value.upper())
        self.rows.append(row)
        try:
            if self.live is not None:
                self.live.refresh()
            else:
                # Plain log: this notification block only; the title is already written.
                self.console.print(self.notification(row))
                self.emitted += 1
            self.console.file.flush()
        except BaseException:
            self.rows.pop()
            raise
