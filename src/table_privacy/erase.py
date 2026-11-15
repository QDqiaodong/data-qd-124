"""Cross-database subject erasure for private data retention termination.

This module is *not* a new anonymization or disclosure analysis and it does not
promise to purge SQLite free pages, backups or external raw inputs.  It removes
a set of subjects from the two private stores already used by this package:

* the serial-release :mod:`~table_privacy.series` ledger (history rows plus a
  durable tombstone), and
* the :mod:`~table_privacy.linkage` audit database (whole runs that contain a
  target or cannot be proven unrelated).

Only SHA256 digests of the original id UTF-8 bytes are persisted as task and
tombstone records.  Digests are matching keys, not anonymization guarantees:
no plaintext id and no reversible encoding is ever written by this module, and
the documentation says so explicitly.

The series ledger owns the request state machine and therefore controls the
real commit boundary of the linkage store:

1. ``pending`` task + tombstones + history deletion commit on the ledger;
2. one atomic conservative purge on the audit database with its own resume
   marker;
3. the ledger task flips to ``done`` and both stores reopen to other writers.

Any process exit between these steps is continued with the same request id via
:func:`resume_erase`, which never needs the id file again.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path

from .common import ident
from .linkage import AuditStore
from .series import SeriesError, Store, id_digest

ERASE_ID_LIMIT = 10000


def _exit_point(name):
    """Test-only crash hooks; inert unless explicitly armed."""
    if os.environ.get('TABLE_PRIVACY_CRASH_HOOK') == name:
        os._exit(99)


def read_id_set(path):
    """Load the JSON id file as an order/duplicate-insensitive non-empty set.

    Every id must satisfy the same identifier contract as source rows.
    """
    raw = Path(path).read_bytes()
    if len(raw) > 8_000_000:
        raise ValueError('id file exceeds the 8 MB input limit')

    def reject_constant(value):
        raise ValueError('nonfinite JSON number: ' + value)

    data = json.loads(raw, parse_constant=reject_constant)
    if not isinstance(data, list) or not data:
        raise ValueError('ids must be a non-empty JSON array of strings')
    ids = set()
    for value in data:
        ids.add(ident(value))
    if not ids:
        raise ValueError('ids must be a non-empty set of nonblank strings')
    if len(ids) > ERASE_ID_LIMIT:
        raise ValueError('erase request exceeds the supported limit of %d ids'
                         % ERASE_ID_LIMIT)
    return ids


def id_set_fingerprint(ids):
    """Canonical digest of the whole id set, independent of order/duplicates."""
    hasher = hashlib.sha256()
    for digest in sorted(id_digest(rid) for rid in ids):
        hasher.update(digest.encode('ascii'))
        hasher.update(b'\n')
    return hasher.hexdigest()


def ensure_binding(ledger, audit):
    """Bind the two databases one-to-one on first use, or verify the pairing.

    A fresh pair receives a random 256-bit token stored in both ``meta``
    tables together with the role and the absolute partner path.  Already
    bound databases must be reopened with exactly their original partners;
    omitting either path or swapping in another database fails closed at the
    store constructors and again here.
    """
    if ledger.binding is None and audit.binding is None:
        token = secrets.token_hex(32)
        ledger_path = str(ledger.path.resolve())
        audit_path = str(audit.path.resolve())
        # Persist on the audit side first: a crash here leaves both stores
        # unbound, so no half-paired database can ever reject the legacy
        # entry points.
        audit.install_binding(token, ledger_path)
        _exit_point('after_binding_audit')
        ledger.install_binding(token, audit_path)
        _exit_point('after_binding_ledger')
        ledger.binding = ledger._load_binding()
        audit.binding = audit._load_binding()
        return token
    if ledger.binding is None or audit.binding is None:
        # Recover a half-finished first-time binding: the persisted side must
        # point back at exactly the partner being opened now, in which case
        # completing the pairing is just replaying the same token.  Any other
        # shape (peer points elsewhere) fails closed.
        ledger_path = str(ledger.path.resolve())
        audit_path = str(audit.path.resolve())
        if audit.binding is not None and ledger.binding is None:
            if audit.binding['peer_path'] != ledger_path:
                raise SeriesError(
                    'the audit database is already bound to a different ledger')
            ledger.install_binding(audit.binding['token'], audit_path)
            ledger.binding = ledger._load_binding()
            return ledger.binding['token']
        if ledger.binding is not None and audit.binding is None:
            if ledger.binding['peer_path'] != audit_path:
                raise SeriesError(
                    'the ledger is already bound to a different audit database')
            audit.install_binding(ledger.binding['token'], ledger_path)
            audit.binding = audit._load_binding()
            return audit.binding['token']
        raise SeriesError(
            'exactly one of the two databases is already bound; refusing to '
            'pair a bound database with an unbound one')
    if ledger.binding['token'] != audit.binding['token']:
        raise SeriesError(
            'the ledger and audit database belong to different bindings')
    if ledger.binding['peer_path'] != str(audit.path.resolve()):
        raise SeriesError(
            'ledger is bound to a different audit database path')
    if audit.binding['peer_path'] != str(ledger.path.resolve()):
        raise SeriesError(
            'audit database is bound to a different ledger path')
    return ledger.binding['token']


def _task_view(task):
    """Strip every internal field that could carry a plaintext id."""
    return {
        'request_id': task['request_id'],
        'state': task['state'],
        'id_count': task['id_count'],
        'id_set_fingerprint': task['id_fingerprint'],
        'series_history_deleted': task['history_deleted'],
        'audit_runs_deleted': task['audit_runs_deleted'],
        'audit_index_rows_deleted': task['audit_index_deleted'],
        'audit_rows_deleted': task['audit_rows_deleted'],
    }


def _resume_audit(ledger, audit, request_id):
    """Run or skip phase 2 using only persisted digests, then close phase 3."""
    task = ledger.get_erase_task(request_id)
    if task is None:
        raise SeriesError('unknown erase request id: ' + request_id)
    if task['state'] == 'done':
        # A completed task is a pure no-op: runs created afterwards are never
        # examined or deleted by a repeated resume.
        return ledger.get_erase_task(request_id)
    digests = ledger.task_digests(request_id)
    if not digests:
        raise SeriesError(
            'erase task has no tombstones; the ledger is internally inconsistent')
    progress = audit.erase_progress(request_id)
    if progress is None:
        _exit_point('erase_before_audit_purge')
        progress = audit.purge_for_erase(request_id, digests)
        _exit_point('erase_after_audit_purge')
        ledger.record_audit_progress(request_id, progress)
        _exit_point('erase_after_audit_progress')
    done = ledger.complete_erase(request_id)
    _exit_point('erase_after_done')
    return done


def run_erase(ledger_path, audit_path, request_id, ids, journal_mode=None):
    """Validate a fresh request and drive the three phases to completion."""
    with Store(ledger_path, audit_path=audit_path,
               journal_mode=journal_mode) as ledger, \
            AuditStore(audit_path, ledger_path=ledger_path,
                       journal_mode=journal_mode) as audit:
        ensure_binding(ledger, audit)
        # Finish any interrupted ordinary publication before entering the
        # pending state, so the eraser never has to share the ledger with a
        # half-committed batch.
        from .series import recover
        recover(ledger)
        fingerprint = id_set_fingerprint(ids)
        existing = ledger.get_erase_task(request_id)
        if existing is not None:
            if existing['id_fingerprint'] != fingerprint:
                raise SeriesError(
                    'request id is already registered with a different id set; '
                    'use --resume without changing the request')
            return _task_view(_resume_audit(ledger, audit, request_id))
        _exit_point('erase_before_series_phase')
        task = ledger.begin_erase(request_id, fingerprint, ids)
        _exit_point('erase_after_series_phase')
        return _task_view(_resume_audit(ledger, audit, request_id))


def resume_erase(ledger_path, audit_path, request_id, journal_mode=None):
    """Continue an interrupted request without the original id file."""
    with Store(ledger_path, audit_path=audit_path,
               journal_mode=journal_mode) as ledger, \
            AuditStore(audit_path, ledger_path=ledger_path,
                       journal_mode=journal_mode) as audit:
        ensure_binding(ledger, audit)
        return _task_view(_resume_audit(ledger, audit, request_id))


def request_status(ledger_path, audit_path, request_id, journal_mode=None):
    """Return the id-free task state; never opens the original id file."""
    with Store(ledger_path, audit_path=audit_path,
               journal_mode=journal_mode) as ledger, \
            AuditStore(audit_path, ledger_path=ledger_path,
                       journal_mode=journal_mode) as audit:
        ensure_binding(ledger, audit)
        task = ledger.get_erase_task(request_id)
        if task is None:
            raise SeriesError('unknown erase request id: ' + request_id)
        view = _task_view(task)
        progress = audit.erase_progress(request_id)
        view['audit_purge_recorded'] = progress is not None
        return view
