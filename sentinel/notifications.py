"""Durable per-network/IP notification window. No scanning and no SQL here."""
from __future__ import annotations
import datetime
import ipaddress
from core import database as db

WINDOW = datetime.timedelta(minutes=60)
LIMIT = 3
VERSION = 1


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def timestamp(value):
    try:
        result = datetime.datetime.fromisoformat(value)
        return result.astimezone(datetime.timezone.utc) if result.tzinfo else None
    except (TypeError, ValueError):
        return None


def host_key(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return str(value)


def metadata(event):
    data = event.get('details', {}).get('notification')
    return data if isinstance(data, dict) and data.get('version') == VERSION else {}


def notification_state(event):
    meta = metadata(event)
    state = meta.get('state', 'unknown')
    if state == 'confirmed' and timestamp(meta.get('emitted_at')) is None:
        return 'unknown'
    return state


def host_summary(events, now, exclude=None):
    """Counts confirmed emissions separately from conservative reservations.

    Boundary: an emission at exactly now-60min no longer occupies a slot.
    Future dates remain occupied after a clock rollback (fail conservative).
    """
    hosts = {}
    for event in events:
        if event['id'] == exclude:
            continue
        details = event.get('details', {})
        host = host_key(details.get('ip', 'inconnu'))
        row = hosts.setdefault(host, dict(host=host, displayed=0, masked=0,
                                         reserved=0, unknown=0))
        meta = metadata(event)
        state = meta.get('state', 'unknown')
        if state == 'whitelisted' or details.get('whitelisted') is True:
            continue
        if state == 'confirmed':
            date = timestamp(meta.get('emitted_at'))
            if date is None:
                row['reserved'] += 1
            elif date > now - WINDOW:
                row['displayed'] += 1
        elif state == 'masked':
            date = timestamp(meta.get('decided_at'))
            if date is not None and date > now - WINDOW:
                row['masked'] += 1
        elif state == 'preparing':
            row['reserved'] += 1  # live intention or crash not yet recovered
        elif state == 'uncertain':
            until = timestamp(meta.get('reserved_until'))
            if until is None or now < until:
                row['reserved'] += 1
        else:
            date = timestamp(event.get('timestamp'))
            if date is None or date > now - WINDOW:
                row['unknown'] += 1
                row['reserved'] += 1
    for row in hosts.values():
        row['available'] = max(0, LIMIT - row['displayed'] - row['reserved'])
        row['state'] = ('silence (quota/réserve)' if row['available'] == 0 else
                        'réserve prudente' if row['reserved'] else 'disponible')
    return hosts


class NotificationWindow:
    """One instance per owned execution; durable history survives new instances."""
    def __init__(self, clock=None, view=None):
        self.clock = clock or utcnow
        self.view = view
        self.network = None
        self.events = []

    def bind(self, network):
        if self.network == network:
            return
        if self.network is not None:
            raise ValueError('Notification window belongs to a different network')
        self.network = network
        # Called once under the lifecycle's stable exclusive network lock.
        self.refresh()
        for event in self.events:
            if notification_state(event) == 'preparing':
                self.uncertain(event['id'])
        self.refresh()

    def refresh(self):
        self.events = db.sentinel_network_snapshot(self.network)['events']

    def summary(self, exclude=None):
        return host_summary(self.events, self.clock(), exclude)

    def uncertain(self, event_id):
        now = self.clock()
        db.sentinel_set_notification(self.network, event_id, {
            'version': VERSION, 'state': 'uncertain', 'recovered_at': now.isoformat(),
            'reserved_until': (now + WINDOW).isoformat()}, expected='preparing')

    def emit(self, event_id, change, emit):
        self.refresh()
        host = host_key(change.asset_ip)
        row = self.summary(exclude=event_id).get(host)
        now = self.clock().isoformat()
        if row is not None and row['available'] == 0:
            db.sentinel_set_notification(self.network, event_id, {
                'version': VERSION, 'state': 'masked', 'decided_at': now})
            self.refresh()
            return False
        db.sentinel_set_notification(self.network, event_id, {
            'version': VERSION, 'state': 'preparing', 'decided_at': now})
        try:
            emit()  # synchronous terminal write/flush, NOT just enqueueing a row
            db.sentinel_set_notification(self.network, event_id, {
                'version': VERSION, 'state': 'confirmed', 'decided_at': now,
                'emitted_at': self.clock().isoformat()}, expected='preparing')
        except BaseException:
            try:
                self.uncertain(event_id)
            except Exception:
                # Leave the durable preparing marker for recovery. Never hide
                # the original display/confirmation failure or claim emission.
                pass
            raise
        self.refresh()
        return True

    def phase(self, phase, finished=False):
        if self.view is not None:
            self.view.set_phase(phase, self.clock().isoformat() if finished else None)
