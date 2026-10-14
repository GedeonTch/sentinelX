"""Standalone read-only Sentinel network snapshot, not an audit Findings report."""
from __future__ import annotations
import base64
import uuid
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from core import database as db
from sentinel.notifications import utcnow, host_summary, notification_state

LABELS = {'confirmed': 'Notification affichée (émission confirmée)',
          'masked': 'Notification masquée par quota',
          'whitelisted': 'Whitelistée — INFO, hors quota',
          'preparing': 'Émission en préparation — issue inconnue',
          'uncertain': 'Émission incertaine — pas une confirmation',
          'unknown': 'Notification inconnue'}


def generate_sentinel_report(network_id, directory=None, clock=None):
    db.validate_sentinel_network_id(network_id)
    if network_id not in db.list_sentinel_network_ids():
        raise ValueError('Réseau Sentinel inconnu')
    data = db.sentinel_network_snapshot(network_id)
    now = (clock or utcnow)()
    events = []
    counts = {'confirmed': 0, 'masked': 0, 'whitelisted': 0, 'uncertain': 0, 'unknown': 0, 'preparing': 0}
    for event in reversed(data['events']):
        details = event['details']
        state = notification_state(event)
        if state not in LABELS:
            state = 'unknown'
        counts[state] += 1
        events.append({'when': event['timestamp'], 'host': details.get('ip', 'inconnu'),
                       'type': event['type'], 'detail': details.get('detail', ''),
                       'notification': LABELS[state],
                       'whitelisted': details.get('whitelisted') is True})
    white_count = sum(e['whitelisted'] for e in events)
    dates = sorted(str(r['last_scan']) for r in data['baseline'] if r.get('last_scan'))
    assets = data['assets']
    logo = Path(__file__).parent / 'assets' / 'SentinelleX.png'
    logo_uri = 'data:image/png;base64,' + base64.b64encode(logo.read_bytes()).decode('ascii')
    env = Environment(loader=FileSystemLoader(Path(__file__).parent / 'templates'),
                      autoescape=select_autoescape(['html']))
    html = env.get_template('sentinel_status.html').render(
        network=network_id, generated=now.isoformat(), state=data['state'],
        counts=counts, total=len(events), whitelisted=white_count,
        assets=len(assets), active=sum(bool(a.get('active')) for a in assets),
        reference=dates[-1] if dates else None,
        hosts=sorted(host_summary(data['events'], now).values(), key=lambda r: r['host']),
        groups=[events[i:i+25] for i in range(0, len(events), 25)], logo=logo_uri)
    directory = Path(directory) if directory is not None else Path.cwd()
    for _ in range(10):
        name = f"sentinel-status-{network_id}-{now.strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:8]}.html"
        path = directory / name
        try:
            with path.open('x', encoding='utf-8') as stream:
                stream.write(html)
            return path.resolve()
        except FileExistsError:
            continue
    raise RuntimeError('Impossible de réserver un nom de rapport unique')
