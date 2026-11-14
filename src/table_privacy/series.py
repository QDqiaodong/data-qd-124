"""Serial releases over one synthetic population.

The single-shot contract in :mod:`table_privacy.model` treats every input as
independent.  This module links the same private ``id`` across successive
releases of the same population and groups each round on the *full history* of
generalized bucket labels together with the current round's generalized bucket.

Threat model (deliberately narrow): an observer links the age/postal group
labels of the same identity across rounds.  Absence and suppression are both
recorded as one uniform empty label; a brand new id gets empty labels for every
past round.  ``category`` and external background knowledge are explicitly out
of scope.

A SQLite ledger (single writer) plus an atomic file-replacement publication
step form a durable protocol that can be recovered after an exit at any point.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from collections import Counter, defaultdict
from fractions import Fraction
from itertools import product
from pathlib import Path

from .generalize import bucket
from .model import parse_input

SCHEMA_VERSION = 2
LEDGER_SCHEMA_VERSION = 1
EMPTY = ''                       # uniform empty label for absence/suppression
LABEL_SEP = '|'                  # cannot occur inside a bucket label
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL UNIQUE,
    source_sha256 TEXT NOT NULL,
    k INTEGER NOT NULL,
    max_suppressed INTEGER NOT NULL,
    report_path TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('committed','published')),
    report_json TEXT NOT NULL,
    report_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS history (
    version INTEGER NOT NULL,
    id TEXT NOT NULL,
    label TEXT NOT NULL,
    PRIMARY KEY (version, id)
);
CREATE INDEX IF NOT EXISTS idx_history_id ON history (id);
"""


class SeriesError(Exception):
    """Conflict or protocol violation; the caller maps this to exit code 2."""


def encode_label(age_label, postal_label):
    """Serialize a current generalized bucket into one history label."""
    return age_label + LABEL_SEP + postal_label


def decode_label(label):
    if label == EMPTY:
        return None
    age_label, postal_label = label.split(LABEL_SEP, 1)
    return age_label, postal_label


def analyze_series(data, history):
    """Run the nine global recodings with cross-round history linkage.

    ``history`` maps id to the tuple of labels from previous rounds (oldest
    first).  For every candidate each current row is grouped by the pair
    (full history label sequence, current generalized bucket); a whole joint
    group smaller than the round's ``k`` is suppressed.  The nine candidates,
    budgets and ordering are identical to the single-shot contract.
    """
    k, budget, records = parse_input(data)
    round_count = max((len(seq) for seq in history.values()), default=0)
    padded = {}
    for r in records:
        seq = tuple(history.get(r['id'], ()))
        # New ids and shorter histories are backfilled with the uniform empty
        # label, indistinguishable from a suppressed or absent identity.
        padded[r['id']] = (EMPTY,) * (round_count - len(seq)) + seq

    candidates = []
    feasible = []
    for age_level, postal_level in product(range(3), repeat=2):
        joint = defaultdict(list)
        for r in records:
            current = encode_label(*bucket(r['age'], r['postal'], age_level, postal_level))
            joint[(padded[r['id']], current)].append(r)
        kept = {key: group for key, group in joint.items() if len(group) >= k}
        suppressed = sum(len(g) for key, g in joint.items() if key not in kept)
        loss = Fraction(age_level + postal_level, 4)
        admissible = bool(kept) and suppressed <= budget
        candidates.append({'age_level': age_level, 'postal_level': postal_level,
                           'suppressed': suppressed,
                           'ordinal_generalization_cost': str(loss),
                           'feasible': admissible})
        if admissible:
            feasible.append(((loss, suppressed, age_level, postal_level), kept))

    if not feasible:
        return {'feasible': False, 'input_rows': len(records), 'k': k,
                'candidates': candidates, 'released_rows': [],
                'equivalence_classes': []}, {}

    (loss, suppressed, age_level, postal_level), kept = min(feasible, key=lambda x: x[0])
    # The public release merges joint groups sharing the current bucket so the
    # output schema matches the single-shot contract; the hidden history split
    # never appears in any public artifact.
    merged = defaultdict(list)
    decisions = {}
    for (history_seq, current_label), members in sorted(kept.items()):
        age_label, postal_label = decode_label(current_label)
        merged[(age_label, postal_label)].extend(members)
        for r in members:
            decisions[r['id']] = current_label

    released = []
    classes = []
    for (age_label, postal_label), members in sorted(merged.items()):
        counts = Counter(r['category'] for r in members)
        classes.append({'age': age_label, 'postal': postal_label,
                        'size': len(members),
                        'distinct_categories': len(counts),
                        'category_counts': dict(sorted(counts.items()))})
        for category, count in sorted(counts.items()):
            released.extend({'age': age_label, 'postal': postal_label,
                             'category': category} for _ in range(count))

    result = {'feasible': True, 'input_rows': len(records), 'k': k,
              'selected': {'age_level': age_level, 'postal_level': postal_level,
                           'ordinal_generalization_cost': str(loss)},
              'suppressed_rows': suppressed,
              'released_count': len(released),
              'released_rows': released,
              'equivalence_classes': classes,
              'candidates': candidates,
              'privacy_scope': ('Serial k-anonymity on age/postal across the full '
                                'history of linked releases; an observer may still '
                                'combine category values or external information. '
                                'This is not a privacy guarantee.')}
    return result, decisions


def _canonical_report_bytes(report):
    return (json.dumps(report, sort_keys=True, ensure_ascii=False,
                       allow_nan=False, indent=2) + '\n').encode('utf-8')


class Store:
    """SQLite ledger for one population's serial releases (single writer)."""

    def __init__(self, path):
        self.path = Path(path)
        if self.path.is_symlink():
            raise SeriesError('ledger path cannot be a symlink')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), timeout=5)
        self.conn.execute('PRAGMA busy_timeout=5000')
        self.conn.executescript(SCHEMA_SQL)
        self.conn.execute('INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)',
                          ('ledger_schema_version', str(LEDGER_SCHEMA_VERSION)))
        self.conn.commit()

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def get_batch(self, batch_id):
        cur = self.conn.execute(
            'SELECT batch_id,version,source_sha256,k,max_suppressed,report_path,'
            'state,report_json,report_sha256 FROM batches WHERE batch_id=?',
            (batch_id,))
        row = cur.fetchone()
        if row is None:
            return None
        keys = ('batch_id', 'version', 'source_sha256', 'k', 'max_suppressed',
                'report_path', 'state', 'report_json', 'report_sha256')
        return dict(zip(keys, row))

    def latest_batch(self):
        cur = self.conn.execute(
            'SELECT batch_id,version,source_sha256,k,max_suppressed,report_path,'
            'state,report_json,report_sha256 FROM batches ORDER BY version DESC LIMIT 1')
        row = cur.fetchone()
        if row is None:
            return None
        keys = ('batch_id', 'version', 'source_sha256', 'k', 'max_suppressed',
                'report_path', 'state', 'report_json', 'report_sha256')
        return dict(zip(keys, row))

    def path_in_use(self, report_path):
        cur = self.conn.execute('SELECT 1 FROM batches WHERE report_path=? LIMIT 1',
                                (report_path,))
        return cur.fetchone() is not None

    def history(self):
        rows = self.conn.execute('SELECT version,id,label FROM history').fetchall()
        by_id = defaultdict(list)
        for version, rid, label in rows:
            by_id[rid].append((version, label))
        return {rid: tuple(label for _, label in sorted(pairs))
                for rid, pairs in by_id.items()}

    def next_version(self):
        cur = self.conn.execute('SELECT COALESCE(MAX(version),0)+1 FROM batches')
        return cur.fetchone()[0]

    def insert_committed(self, batch_id, version, digest, k, budget,
                         report_path, report_bytes, history_rows):
        """Append the batch and its history labels in one durable transaction."""
        report_text = report_bytes.decode('utf-8')
        report_sha = hashlib.sha256(report_bytes).hexdigest()
        try:
            self.conn.execute('BEGIN IMMEDIATE')
            self.conn.execute(
                'INSERT INTO batches(batch_id,version,source_sha256,k,'
                'max_suppressed,report_path,state,report_json,report_sha256) '
                "VALUES(?,?,?,?,?,?, 'committed', ?, ?)",
                (batch_id, version, digest, k, budget, report_path,
                 report_text, report_sha))
            self.conn.executemany(
                'INSERT INTO history(version,id,label) VALUES(?,?,?)',
                [(version, rid, label) for rid, label in history_rows])
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def mark_published(self, batch_id):
        try:
            self.conn.execute('BEGIN IMMEDIATE')
            self.conn.execute(
                "UPDATE batches SET state='published' WHERE batch_id=? AND state='committed'",
                (batch_id,))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise


def _atomic_write(path, payload):
    dest = Path(path)
    if dest.is_symlink():
        raise SeriesError('report path cannot be a symlink')
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', dir=dest.parent,
                                         delete=False) as stream:
            temp = stream.name
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, dest)
    finally:
        if temp and os.path.exists(temp):
            os.unlink(temp)


def _reconcile_file(batch):
    """Make the public file match the ledger; idempotent at any crash point."""
    payload = batch['report_json'].encode('utf-8')
    path = Path(batch['report_path'])
    if hashlib.sha256(payload).hexdigest() != batch['report_sha256']:
        raise SeriesError('ledger report digest is internally inconsistent')
    if path.is_symlink():
        raise SeriesError('report path cannot be a symlink: ' + str(path))
    current = path.read_bytes() if path.exists() else None
    if current != payload:
        _atomic_write(path, payload)
    if hashlib.sha256(path.read_bytes()).hexdigest() != batch['report_sha256']:
        raise SeriesError('public report does not reconcile with the ledger')


def _exit_point(name):
    """Test-only crash hooks; inert unless explicitly armed via the environment."""
    if os.environ.get('TABLE_PRIVACY_CRASH_HOOK') == name:
        # Hard exit bypasses finally blocks, simulating SIGKILL / power loss.
        os._exit(99)


def recover(store):
    """Complete any interrupted publication. Refuses to advance on failure."""
    latest = store.latest_batch()
    if latest is None:
        return None
    if latest['state'] == 'committed':
        # The ledger append is durable but the file replacement may not have
        # happened, or may have happened before the state update was committed.
        _reconcile_file(latest)
        store.mark_published(latest['batch_id'])
        latest = store.get_batch(latest['batch_id'])
    else:
        # Already published: still verify the on-disk content against the
        # ledger so a tampered or missing file is detected before a new batch.
        _reconcile_file(latest)
    return latest


def publish(store, batch_id, data, digest, report_path):
    """Run one serial release through the durable publication protocol.

    Returns ``(status, payload)`` where status is ``'published'`` (including a
    recovered/identical replay) or ``'infeasible'``.
    """
    k, budget, _ = parse_input(data)
    report_obj = Path(report_path)
    # Check the path as supplied: resolve() would dereference a symlink and
    # hide it. Single-writer assumption bounds the remaining TOCTOU window.
    if report_obj.is_symlink():
        raise SeriesError('report path cannot be a symlink')
    report_path = str(report_obj.resolve())

    existing = store.get_batch(batch_id)
    if existing is not None:
        # Replay/conflict path: recovery must finish before anything else.
        recovered = recover(store)
        if recovered is not None and recovered['batch_id'] == batch_id:
            existing = store.get_batch(batch_id)
        same = (existing['source_sha256'] == digest and existing['k'] == k
                and existing['max_suppressed'] == budget
                and existing['report_path'] == report_path)
        if not same:
            raise SeriesError(
                'batch id %r already exists with different source SHA256, '
                'parameters or report path' % batch_id)
        if existing['state'] != 'published':
            raise SeriesError('batch %r is not recoverable to a published state' % batch_id)
        # Reconcile this batch's own public file (recovery above only touches
        # the latest batch), so a tampered older report is restored to ledger.
        _reconcile_file(existing)
        return 'published', existing['report_json'].encode('utf-8')

    # A new batch is refused until any interrupted publication is recovered.
    recovered = recover(store)
    if recovered is not None and recovered['state'] != 'published':
        raise SeriesError('interrupted publication must be recovered before the next batch')
    if store.path_in_use(report_path):
        raise SeriesError('report path already belongs to a published batch')
    if Path(report_path).exists():
        raise SeriesError('refusing to overwrite an existing file: ' + report_path)

    history = store.history()
    result, decisions = analyze_series(data, history)
    if not result['feasible']:
        # Infeasibility never advances the ledger and never touches the file.
        report = {'schema_version': SCHEMA_VERSION, 'batch_id': batch_id,
                  'source_sha256': digest,
                  'version': None, 'result': result}
        return 'infeasible', _canonical_report_bytes(report)

    version = store.next_version()
    history_rows = []
    for r in data['records']:
        rid = r['id']
        label = decisions.get(rid, EMPTY)      # suppressed this round -> empty
        history_rows.append((rid, label))
    # Every identity known from past rounds but absent this round gets the
    # uniform empty label; new ids are inserted with this round only and their
    # past is implicitly empty via backfill in analyze_series.
    present = {r['id'] for r in data['records']}
    for rid in set(history) - present:
        history_rows.append((rid, EMPTY))

    report = {'schema_version': SCHEMA_VERSION, 'batch_id': batch_id,
              'source_sha256': digest,
              'version': version, 'result': result}
    payload = _canonical_report_bytes(report)

    store.insert_committed(batch_id, version, digest, k, budget,
                           report_path, payload, history_rows)
    _exit_point('after_db_commit')
    _reconcile_file(store.get_batch(batch_id))
    _exit_point('after_file_replace')
    store.mark_published(batch_id)
    return 'published', payload
