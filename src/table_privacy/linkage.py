"""Linkage-risk audit against one public release and a helper-identity array.

The audit imports exactly two *external* artifacts:

1. a single public schema-1 table-privacy report (the JSON envelope written by
   the single-shot ``table-privacy`` entry point), and
2. a JSON array of synthetic helper identities with ``id``, ``age_min``,
   ``age_max`` and ``postal_prefix`` fields.

It never opens the private source contract input and never reads the serial
release SQLite ledger (``series``).  The helper table is assumed to contain
exactly the released identities, with unique ids; a helper count that differs
from the released row count is therefore an invalid invocation, not a Hall
failure.

The public (age, postal, category) counts are treated as *capacity slots*: one
slot per distinct triple with its multiplicity as capacity.  A helper identity
is adjacent to a slot only when its age interval intersects the bucket's age
label and its postal prefix intersects the bucket's postal label (category is
not part of adjacency).  A full matching assigns every identity to exactly one
slot while filling every slot capacity exactly.

Conclusions are purely combinatorial, never probabilistic:

* a category that an identity takes in *every* full matching is a forced
  exposure (the identity has exactly one possible category);
* a compatibility edge that belongs to no full matching is recorded as
  unusable;
* when no full matching exists the run is ``inconsistent`` and a Hall witness
  (identity set, its neighbour slots, their joint capacity, the deficit) is
  stored.

The solver runs one Dinic max flow plus one iterative Kosaraju SCC pass; slot
copies are never expanded and full matchings are never enumerated.
"""
from __future__ import annotations

import re
import sqlite3
import sys
from collections import Counter, deque
from pathlib import Path

from urllib.parse import quote

from .common import gate_wait, ident

# Keep recursive Dinic DFS safely below the limit for the supported graph size
# (at most 2000 identities + 2000 slots + source/sink).
sys.setrecursionlimit(50000)

AUDIT_SCHEMA_VERSION = 1
MAX_IDENTITIES = 2000
MAX_EDGES = 20000

BINDING_ROLE = 'linkage_audit'
_BINDING_TOKEN_KEY = 'privacy_binding_token'
_BINDING_ROLE_KEY = 'privacy_binding_role'
_BINDING_PEER_KEY = 'privacy_binding_peer_path'
_SCHEMA_VERSION_KEY = 'audit_schema_version'
_SQL_VAR_CHUNK = 300

_EXACT_AGE_RE = re.compile(r'\d{1,3}$')
_AGE_RANGE_RE = re.compile(r'(\d{1,3})-(\d{1,3})$')
_POSTAL_FULL_RE = re.compile(r'\d{5}$')
_POSTAL_STEM_RE = re.compile(r'(\d{3})\*\*$')
_PREFIX_RE = re.compile(r'\d{0,5}$')
_SHA256_RE = re.compile(r'[0-9a-f]{64}$')

_FEASIBLE_KEYS = {'candidates', 'equivalence_classes', 'feasible', 'input_rows',
                  'k', 'privacy_scope', 'released_count', 'released_rows',
                  'selected', 'suppressed_rows'}
_INFEASIBLE_KEYS = {'candidates', 'equivalence_classes', 'feasible',
                    'input_rows', 'k', 'released_rows'}
_RELEASED_ROW_KEYS = {'age', 'category', 'postal'}
_CLASS_KEYS = {'age', 'category_counts', 'distinct_categories', 'postal', 'size'}
_HELPER_KEYS = {'age_max', 'age_min', 'id', 'postal_prefix'}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_sha256 TEXT NOT NULL,
    helpers_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('consistent','inconsistent')),
    identity_count INTEGER NOT NULL,
    slot_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL,
    total_capacity INTEGER NOT NULL,
    maxflow INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS slots (
    run_id INTEGER NOT NULL,
    slot_index INTEGER NOT NULL,
    age_label TEXT NOT NULL,
    postal_label TEXT NOT NULL,
    category TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    PRIMARY KEY (run_id, slot_index)
);
CREATE TABLE IF NOT EXISTS edges (
    run_id INTEGER NOT NULL,
    identity_index INTEGER NOT NULL,
    slot_index INTEGER NOT NULL,
    matched INTEGER NOT NULL CHECK (matched IN (0,1)),
    usable INTEGER CHECK (usable IS NULL OR usable IN (0,1)),
    PRIMARY KEY (run_id, identity_index, slot_index)
);
CREATE TABLE IF NOT EXISTS identity_outcomes (
    run_id INTEGER NOT NULL,
    identity_index INTEGER NOT NULL,
    id TEXT NOT NULL,
    age_min INTEGER NOT NULL,
    age_max INTEGER NOT NULL,
    postal_prefix TEXT NOT NULL,
    forced_exposure INTEGER NOT NULL CHECK (forced_exposure IN (0,1)),
    forced_category TEXT,
    PRIMARY KEY (run_id, identity_index)
);
CREATE TABLE IF NOT EXISTS identity_possible_categories (
    run_id INTEGER NOT NULL,
    identity_index INTEGER NOT NULL,
    category TEXT NOT NULL,
    PRIMARY KEY (run_id, identity_index, category)
);
CREATE TABLE IF NOT EXISTS hall_witnesses (
    run_id INTEGER PRIMARY KEY,
    witness_set_size INTEGER NOT NULL,
    neighbor_slot_count INTEGER NOT NULL,
    neighbor_capacity INTEGER NOT NULL,
    deficit INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS hall_witness_identities (
    run_id INTEGER NOT NULL,
    identity_index INTEGER NOT NULL,
    id TEXT NOT NULL,
    PRIMARY KEY (run_id, identity_index)
);
CREATE TABLE IF NOT EXISTS hall_witness_slots (
    run_id INTEGER NOT NULL,
    slot_index INTEGER NOT NULL,
    capacity INTEGER NOT NULL,
    PRIMARY KEY (run_id, slot_index)
);
-- Digest-only subject index of every input identity, written atomically with
-- the run itself.  It lets an erase request prove that a run is unrelated
-- without ever storing a reversible encoding of an id.  Runs created before
-- binding have no rows here and are therefore treated conservatively as
-- "cannot be proven unrelated" by the first erase.
CREATE TABLE IF NOT EXISTS run_identity_index (
    run_id INTEGER NOT NULL,
    identity_index INTEGER NOT NULL,
    id_digest TEXT NOT NULL,
    PRIMARY KEY (run_id, identity_index)
);
CREATE INDEX IF NOT EXISTS idx_run_identity_digest
    ON run_identity_index (id_digest);
-- One row per completed erase phase for this audit database; its presence is
-- the durable resume marker.  No plaintext id is stored, only the ledger
-- request id and aggregate deletion counts.
CREATE TABLE IF NOT EXISTS erase_progress (
    request_id TEXT PRIMARY KEY,
    runs_deleted INTEGER NOT NULL,
    index_deleted INTEGER NOT NULL,
    rows_deleted INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
"""


def id_digest(rid):
    """SHA256 over the exact UTF-8 bytes of the original id."""
    import hashlib
    return hashlib.sha256(rid.encode('utf-8')).hexdigest()


def _chunks(seq, size):
    for start in range(0, len(seq), size):
        yield seq[start:start + size]


class LinkageError(Exception):
    """Invalid input or audit-store conflict; the caller maps this to exit 2."""


# --------------------------------------------------------------------------- #
# Label parsing and intersection
# --------------------------------------------------------------------------- #

def parse_age_label(text):
    """Parse a public age bucket label into ``(kind, interval)``.

    ``kind`` 0 is an exact age ``"37"`` (interval ``(37, 37)``), kind 1 a
    canonical ten-year band such as ``"20-29"`` or the age-120 singleton
    ``"120-120"`` (interval ``(lo, hi)``), and kind 2 the wildcard ``"*"``
    (interval ``None``).  Anything else is rejected.
    """
    if not isinstance(text, str):
        raise LinkageError('age label must be a string')
    if text == '*':
        return 2, None
    if _EXACT_AGE_RE.match(text):
        value = int(text)
        if text != str(value) or not 0 <= value <= 120:
            raise LinkageError('age label out of range or not canonical: ' + text)
        return 0, (value, value)
    match = _AGE_RANGE_RE.match(text)
    if match:
        lo_text, hi_text = match.groups()
        lo, hi = int(lo_text), int(hi_text)
        # Only the ten-year bands emitted by generalize.bucket are accepted.
        if (lo_text != str(lo) or hi_text != str(hi) or lo > 120
                or lo % 10 != 0 or hi != min(120, lo + 9) or lo > hi):
            raise LinkageError('age band label is not a canonical ten-year band: ' + text)
        return 1, (lo, hi)
    raise LinkageError('unrecognized age label: ' + text)


def parse_postal_label(text):
    """Parse a public postal bucket label into ``(kind, value)``.

    kind 0 = full five-digit label (value is the five digits, leading zeros
    preserved), kind 1 = three-digit stem plus ``"**"`` (value is the stem),
    kind 2 = wildcard ``"*"`` (value is ``""``).
    """
    if not isinstance(text, str):
        raise LinkageError('postal label must be a string')
    if text == '*':
        return 2, ''
    if _POSTAL_FULL_RE.match(text):
        return 0, text
    match = _POSTAL_STEM_RE.match(text)
    if match:
        return 1, match.group(1)
    raise LinkageError('unrecognized postal label: ' + text)


def age_intersects(age_min, age_max, age_label):
    """True when helper interval [age_min, age_max] meets the age label."""
    parsed = parse_age_label(age_label) if isinstance(age_label, str) else age_label
    _kind, interval = parsed
    if interval is None:
        return True
    lo, hi = interval
    return age_min <= hi and lo <= age_max


def postal_intersects(prefix, postal_label):
    """True when a 0..5 digit prefix meets the postal label.

    Two fixed digit strings intersect exactly when one is a prefix of the
    other (their common prefix is non-empty); the empty prefix and the ``*``
    label intersect everything.  Leading zeros are ordinary digits here.
    """
    parsed = parse_postal_label(postal_label) if isinstance(postal_label, str) \
        else postal_label
    kind, value = parsed
    if kind == 2:
        return True
    if kind == 0:
        return value.startswith(prefix)
    return prefix.startswith(value) or value.startswith(prefix)


# --------------------------------------------------------------------------- #
# Strict input validation
# --------------------------------------------------------------------------- #

def _require_object(obj, keys, what):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise LinkageError('expected object fields for %s: %s' % (what, ' '.join(sorted(keys))))


def _strict_int(value, lo, hi, what):
    if type(value) is not int or not lo <= value <= hi:
        raise LinkageError(what + ' must be an integer in %d..%d' % (lo, hi))
    return value


def parse_report(data):
    """Validate a schema-1 feasible report and return normalized slot records.

    Cross-checks every count between ``released_rows`` and
    ``equivalence_classes`` (the two views must agree bucket by bucket),
    including released/input/suppressed totals.  Returns
    ``(slots, source_sha256)`` where each slot is a dict with the bucket
    labels, category and aggregated capacity.
    """
    _require_object(data, ('result', 'schema_version', 'source_sha256'), 'report envelope')
    if type(data['schema_version']) is not int or data['schema_version'] != 1:
        raise LinkageError('only schema_version 1 reports are supported')
    digest = data['source_sha256']
    if not isinstance(digest, str) or not _SHA256_RE.match(digest):
        raise LinkageError('report source_sha256 must be a 64-character lowercase hex string')
    result = data['result']
    if not isinstance(result, dict):
        raise LinkageError('report result must be an object')
    if not result.get('feasible'):
        raise LinkageError('linkage audit requires a feasible report with released rows')
    if set(result) != _FEASIBLE_KEYS:
        raise LinkageError('unexpected or missing result fields in feasible report')
    _strict_int(result['input_rows'], 1, 10 ** 9, 'input_rows')
    _strict_int(result['released_count'], 1, 10 ** 9, 'released_count')
    _strict_int(result['suppressed_rows'], 0, 10 ** 9, 'suppressed_rows')
    if result['input_rows'] != result['released_count'] + result['suppressed_rows']:
        raise LinkageError('input_rows must equal released_count plus suppressed_rows')

    released = result['released_rows']
    classes = result['equivalence_classes']
    if not isinstance(released, list) or not isinstance(classes, list) or not released:
        raise LinkageError('released_rows and equivalence_classes must be non-empty arrays')

    row_counts = Counter()
    for row in released:
        _require_object(row, _RELEASED_ROW_KEYS, 'released_row')
        ident(row['category'])
        parse_age_label(row['age'])
        parse_postal_label(row['postal'])
        row_counts[(row['age'], row['postal'], row['category'])] += 1
    if len(released) != result['released_count']:
        raise LinkageError('released_count does not match the released_rows array length')

    class_views = {}
    for cls in classes:
        _require_object(cls, _CLASS_KEYS, 'equivalence_class')
        parse_age_label(cls['age'])
        parse_postal_label(cls['postal'])
        key = (cls['age'], cls['postal'])
        if key in class_views:
            raise LinkageError('duplicate equivalence class for bucket %s/%s' % key)
        counts = cls['category_counts']
        if not isinstance(counts, dict) or not counts:
            raise LinkageError('category_counts must be a non-empty object')
        normalized = {}
        for category, count in counts.items():
            ident(category)
            _strict_int(count, 1, 10 ** 9, 'category count')
            normalized[category] = count
        _strict_int(cls['size'], 1, 10 ** 9, 'equivalence class size')
        _strict_int(cls['distinct_categories'], 1, 10 ** 9, 'distinct_categories')
        if cls['size'] != sum(normalized.values()):
            raise LinkageError('equivalence class size differs from its category counts')
        if cls['distinct_categories'] != len(normalized):
            raise LinkageError('distinct_categories differs from its category_counts keys')
        class_views[key] = normalized

    bucket_keys = {(age, postal) for age, postal, _cat in row_counts}
    if bucket_keys != set(class_views):
        raise LinkageError('released_rows and equivalence_classes bucket labels do not match')
    for (age, postal), view_counts in class_views.items():
        actual = Counter({cat: n for (a, p, cat), n in row_counts.items()
                          if a == age and p == postal})
        if dict(sorted(actual.items())) != dict(sorted(view_counts.items())):
            raise LinkageError('released_rows and equivalence_classes counts disagree for '
                               'bucket %s/%s' % (age, postal))

    slots = []
    for index, ((age, postal, category), capacity) in enumerate(sorted(row_counts.items())):
        slots.append({'index': index, 'age_label': age, 'postal_label': postal,
                      'category': category, 'capacity': capacity})
    if sum(s['capacity'] for s in slots) != result['released_count']:
        raise LinkageError('slot capacities do not reconcile with released_count')
    return slots, digest


def parse_helpers(data):
    """Validate the helper-identity JSON array; returns normalized identities."""
    if not isinstance(data, list) or not data:
        raise LinkageError('helper input must be a non-empty JSON array')
    if len(data) > MAX_IDENTITIES:
        raise LinkageError('helper identity count exceeds the supported limit of %d'
                           % MAX_IDENTITIES)
    identities = []
    seen = set()
    for index, row in enumerate(data):
        _require_object(row, _HELPER_KEYS, 'helper identity')
        rid = ident(row['id'])
        if rid in seen:
            raise LinkageError('duplicate helper identity id: ' + rid)
        seen.add(rid)
        age_min = _strict_int(row['age_min'], 0, 120, 'age_min')
        age_max = _strict_int(row['age_max'], 0, 120, 'age_max')
        if age_min > age_max:
            raise LinkageError('age_min must not exceed age_max for id ' + rid)
        prefix = row['postal_prefix']
        if not isinstance(prefix, str) or not _PREFIX_RE.match(prefix):
            raise LinkageError('postal_prefix must be 0..5 ASCII digits for id ' + rid)
        identities.append({'index': index, 'id': rid, 'age_min': age_min,
                           'age_max': age_max, 'postal_prefix': prefix})
    return identities


# --------------------------------------------------------------------------- #
# Bipartite flow graph (Dinic), Hall witness and allowed-edge SCC analysis
# --------------------------------------------------------------------------- #

class _FlowEdge:
    __slots__ = ('to', 'rev', 'cap')

    def __init__(self, to, rev, cap):
        self.to = to
        self.rev = rev
        self.cap = cap


def _add_edge(graph, u, v, cap):
    forward = _FlowEdge(v, len(graph[v]), cap)
    backward = _FlowEdge(u, len(graph[u]), 0)
    graph[u].append(forward)
    graph[v].append(backward)
    return forward


def _dinic_maxflow(graph, source, sink):
    """Max flow with level graph and recursive blocking-flow DFS."""
    flow = 0

    def dfs(u, pushed):
        if u == sink:
            return pushed
        while ptr[u] < len(graph[u]):
            edge = graph[u][ptr[u]]
            if edge.cap > 0 and level[edge.to] == level[u] + 1:
                sent = dfs(edge.to, min(pushed, edge.cap))
                if sent:
                    edge.cap -= sent
                    graph[edge.to][edge.rev].cap += sent
                    return sent
            ptr[u] += 1
        return 0

    while True:
        level = [-1] * len(graph)
        level[source] = 0
        queue = deque([source])
        while queue:
            u = queue.popleft()
            for edge in graph[u]:
                if edge.cap > 0 and level[edge.to] < 0:
                    level[edge.to] = level[u] + 1
                    queue.append(edge.to)
        if level[sink] < 0:
            return flow
        ptr = [0] * len(graph)
        while True:
            pushed = dfs(source, 10 ** 18)
            if not pushed:
                break
            flow += pushed


def _kosaraju(node_count, adjacency):
    """Iterative Kosaraju SCC; returns a component id per node."""
    seen = [False] * node_count
    order = []
    for start in range(node_count):
        if seen[start]:
            continue
        seen[start] = True
        stack = [(start, 0)]
        while stack:
            node, cursor = stack[-1]
            if cursor < len(adjacency[node]):
                nxt = adjacency[node][cursor]
                stack[-1] = (node, cursor + 1)
                if not seen[nxt]:
                    seen[nxt] = True
                    stack.append((nxt, 0))
            else:
                order.append(node)
                stack.pop()

    reverse = [[] for _ in range(node_count)]
    for u, outs in enumerate(adjacency):
        for v in outs:
            reverse[v].append(u)

    component = [-1] * node_count
    comp_id = 0
    for start in reversed(order):
        if component[start] != -1:
            continue
        component[start] = comp_id
        stack = [start]
        while stack:
            node = stack.pop()
            for v in reverse[node]:
                if component[v] == -1:
                    component[v] = comp_id
                    stack.append(v)
        comp_id += 1
    return component


def analyze_linkage(report_data, helper_data, report_sha256, helpers_sha256):
    """Run the full combinatorial audit entirely in memory.

    Returns a plain dict describing slots, compatibility edges (with matched
    and usable flags), per-identity possible categories and, when applicable,
    the Hall witness.  No SQLite file is touched here, so invalid input can
    never disturb an existing audit database.
    """
    slots, report_digest = parse_report(report_data)
    identities = parse_helpers(helper_data)
    total_capacity = sum(slot['capacity'] for slot in slots)
    if len(identities) != total_capacity:
        raise LinkageError(
            'helper identity count (%d) must equal released row capacity (%d); '
            'the helper table is assumed to cover exactly the released identities'
            % (len(identities), total_capacity))

    n_id = len(identities)
    n_slot = len(slots)
    parsed_age = [parse_age_label(s['age_label']) for s in slots]
    parsed_postal = [parse_postal_label(s['postal_label']) for s in slots]

    # Compatibility edges: adjacency depends only on age/postal intersection,
    # never on category.  One record per (identity, slot); repeated released
    # rows live inside the slot capacity and are never expanded.
    edge_records = []
    edge_count = 0
    for identity in identities:
        i = identity['index']
        for slot in slots:
            j = slot['index']
            if (age_intersects(identity['age_min'], identity['age_max'], parsed_age[j])
                    and postal_intersects(identity['postal_prefix'], parsed_postal[j])):
                edge_count += 1
                if edge_count > MAX_EDGES:
                    raise LinkageError(
                        'compatibility edge count exceeds the supported limit of %d'
                        % MAX_EDGES)
                edge_records.append((i, j))

    source = n_id + n_slot
    sink = source + 1
    graph = [[] for _ in range(n_id + n_slot + 2)]
    forward_edges = {}
    for i in range(n_id):
        _add_edge(graph, source, i, 1)
    for slot in slots:
        _add_edge(graph, n_id + slot['index'], sink, slot['capacity'])
    for i, j in edge_records:
        forward_edges[(i, j)] = _add_edge(graph, i, n_id + j, 1)

    maxflow = _dinic_maxflow(graph, source, sink)
    matched = {(i, j): forward_edges[(i, j)].cap == 0 for i, j in edge_records}

    result = {
        'report_sha256': report_sha256,
        'helpers_sha256': helpers_sha256,
        'report_source_sha256': report_digest,
        'identities': identities,
        'slots': slots,
        'identity_count': n_id,
        'slot_count': n_slot,
        'edge_count': edge_count,
        'total_capacity': total_capacity,
        'maxflow': maxflow,
    }

    if maxflow < n_id:
        # Residual reachability from the source yields a Hall-deficient set:
        # every reached identity X can only reach the reached neighbour slots
        # N(X), whose saturated joint capacity is strictly smaller than |X|.
        reachable = [False] * len(graph)
        reachable[source] = True
        queue = deque([source])
        while queue:
            u = queue.popleft()
            for edge in graph[u]:
                if edge.cap > 0 and not reachable[edge.to]:
                    reachable[edge.to] = True
                    queue.append(edge.to)
        witness_identities = [i for i in range(n_id) if reachable[i]]
        neighbor_slots = sorted(j - n_id for j in range(n_id, n_id + n_slot)
                                if reachable[j])
        neighbor_capacity = sum(slots[j]['capacity'] for j in neighbor_slots)
        deficit = len(witness_identities) - neighbor_capacity
        if deficit <= 0 or not witness_identities:
            raise LinkageError('internal Hall witness construction failed')
        result.update(status='inconsistent', edges=[
            {'identity_index': i, 'slot_index': j,
             'matched': 1 if matched[(i, j)] else 0, 'usable': None}
            for i, j in edge_records],
            outcomes=[], hall={
                'witness_identities': witness_identities,
                'neighbor_slots': neighbor_slots,
                'neighbor_capacity': neighbor_capacity,
                'deficit': deficit})
        return result

    # A full matching exists.  Build the alternating residual digraph on
    # identity + slot nodes: unused compatibility arcs point identity -> slot,
    # matched arcs point slot -> identity.  An unused edge belongs to some full
    # matching exactly when its endpoints share an SCC; matched edges belong to
    # the current matching and are always allowed.
    digraph = [[] for _ in range(n_id + n_slot)]
    for i, j in edge_records:
        if matched[(i, j)]:
            digraph[n_id + j].append(i)
        else:
            digraph[i].append(n_id + j)
    components = _kosaraju(n_id + n_slot, digraph)

    edges_out = []
    possible = {i: set() for i in range(n_id)}
    for i, j in edge_records:
        is_matched = matched[(i, j)]
        usable = is_matched or components[i] == components[n_id + j]
        edges_out.append({'identity_index': i, 'slot_index': j,
                          'matched': 1 if is_matched else 0,
                          'usable': 1 if usable else 0})
        if usable:
            possible[i].add(slots[j]['category'])

    outcomes = []
    for identity in identities:
        i = identity['index']
        categories = sorted(possible[i])
        if not categories:
            raise LinkageError('internal allowed-edge analysis produced no category for id '
                               + identity['id'])
        forced = len(categories) == 1
        outcomes.append({'identity_index': i,
                         'forced_exposure': 1 if forced else 0,
                         'forced_category': categories[0] if forced else None,
                         'possible_categories': categories})
    result.update(status='consistent', edges=edges_out, outcomes=outcomes, hall=None)
    return result


# --------------------------------------------------------------------------- #
# Private SQLite audit store
# --------------------------------------------------------------------------- #

class AuditStore:
    """Private SQLite audit database.

    Once bound to a series ledger by :mod:`table_privacy.erase`, every writer
    entry point (CLI or this Python API) must supply the bound ledger path and
    passes a transaction-local admission check against the ledger's pending
    erase tasks and tombstones.  An audit database that has never been bound
    keeps the original single-writer behavior.
    """

    def __init__(self, path, ledger_path=None, journal_mode=None):
        self.path = Path(path)
        if self.path.is_symlink():
            raise LinkageError('audit database path cannot be a symlink')
        if self.path.exists() and not self.path.is_file():
            raise LinkageError('audit database path is not a regular file')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), timeout=5)
        self.conn.execute('PRAGMA busy_timeout=5000')
        if journal_mode:
            if journal_mode not in ('delete', 'wal'):
                raise LinkageError("journal_mode must be 'delete' or 'wal'")
            self.conn.execute('PRAGMA journal_mode=%s' % journal_mode)
        self.journal_mode = journal_mode or 'delete'
        existing = {row[0] for row in
                    self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if existing and 'runs' not in existing:
            raise LinkageError('database is not a linkage audit store: ' + str(self.path))
        self.conn.executescript(SCHEMA_SQL)
        self.conn.execute('INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)',
                          (_SCHEMA_VERSION_KEY, str(AUDIT_SCHEMA_VERSION)))
        self.conn.commit()
        self.binding = self._load_binding()
        self.ledger_path = Path(ledger_path).resolve() if ledger_path is not None else None
        self._verify_binding('audit database')

    def _load_binding(self):
        rows = dict(self.conn.execute(
            'SELECT key,value FROM meta WHERE key IN (?,?,?)',
            (_BINDING_TOKEN_KEY, _BINDING_ROLE_KEY, _BINDING_PEER_KEY)).fetchall())
        if not rows:
            return None
        if set(rows) != {_BINDING_TOKEN_KEY, _BINDING_ROLE_KEY,
                         _BINDING_PEER_KEY}:
            raise LinkageError('audit database binding metadata is incomplete')
        if rows[_BINDING_ROLE_KEY] != BINDING_ROLE:
            raise LinkageError('audit database binding role mismatch')
        return {'token': rows[_BINDING_TOKEN_KEY],
                'peer_path': rows[_BINDING_PEER_KEY]}

    def _verify_binding(self, what):
        if self.binding is None:
            return
        if self.ledger_path is None:
            raise LinkageError(
                'this %s is bound to a series ledger; --ledger is required '
                'for every writer' % what)
        if str(self.ledger_path) != self.binding['peer_path']:
            raise LinkageError(
                'bound audit database rejects a different ledger; expected %s'
                % self.binding['peer_path'])

    def binding_token(self):
        return None if self.binding is None else self.binding['token']

    def install_binding(self, token, ledger_path):
        if self.binding is not None:
            raise LinkageError('audit database is already bound to a series ledger')
        peer = str(Path(ledger_path).resolve())
        try:
            self.conn.execute('BEGIN IMMEDIATE')
            self.conn.executemany(
                'INSERT INTO meta(key,value) VALUES(?,?)',
                [(_BINDING_TOKEN_KEY, token),
                 (_BINDING_ROLE_KEY, BINDING_ROLE),
                 (_BINDING_PEER_KEY, peer)])
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        self.binding = {'token': token, 'peer_path': peer}

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------------ #
    # Cross-store admission, read from the bound ledger inside the write
    # transaction so the check and the commit share one serializable point.
    # ------------------------------------------------------------------ #

    def _open_ledger_gate(self):
        uri = 'file:%s?mode=ro' % quote(str(self.ledger_path))
        gate = sqlite3.connect(uri, uri=True, timeout=5)
        gate.execute('PRAGMA busy_timeout=5000')
        # In WAL mode a separate read connection sees the latest committed
        # snapshot; in rollback-journal mode the read is consistent while no
        # write transaction is active on the ledger.
        return gate

    def _txn_admission(self, gate, rid_digests):
        pending = gate.execute(
            "SELECT 1 FROM erase_tasks WHERE state='pending' LIMIT 1").fetchone()
        if pending is not None:
            raise LinkageError(
                'the bound ledger has a pending erase; new runs are rejected '
                'until the erase is resumed to done')
        for chunk in _chunks(sorted(set(rid_digests)), _SQL_VAR_CHUNK):
            placeholders = ','.join('?' for _ in chunk)
            hit = gate.execute(
                'SELECT 1 FROM tombstones WHERE id_digest IN (%s) LIMIT 1'
                % placeholders, chunk).fetchone()
            if hit is not None:
                raise LinkageError(
                    'run contains an identity erased by a previous request; '
                    'tombstoned identities are permanently rejected')

    def erase_progress(self, request_id):
        row = self.conn.execute(
            'SELECT request_id,runs_deleted,index_deleted,rows_deleted '
            'FROM erase_progress WHERE request_id=?', (request_id,)).fetchone()
        if row is None:
            return None
        return {'request_id': row[0], 'runs_deleted': row[1],
                'index_deleted': row[2], 'rows_deleted': row[3]}

    def persist(self, result):
        """Append one fully solved run and all its evidence in one transaction.

        For a bound audit store the ledger's pending/tombstone state is read
        after the write lock is taken, so an eraser that commits first makes
        this commit fail even when the solve ran against an older snapshot.
        The expensive solve happens entirely before this method runs, and the
        test barrier below is reached *before* ``BEGIN IMMEDIATE`` so waiting
        work never holds an exclusive lock (the writer and one eraser can
        therefore compete without a lock timeout deciding the outcome).
        """
        rid_digests = [id_digest(identity['id'])
                       for identity in result['identities']]
        self._verify_binding('audit database')
        # Pause after the full solve but before any lock is taken.
        gate_wait('linkage_pre_commit')
        gate = None
        try:
            self.conn.execute('BEGIN IMMEDIATE')
            if self.binding is not None:
                gate = self._open_ledger_gate()
                self._txn_admission(gate, rid_digests)
            cur = self.conn.execute(
                'INSERT INTO runs(report_sha256,helpers_sha256,status,identity_count,'
                'slot_count,edge_count,total_capacity,maxflow) VALUES(?,?,?,?,?,?,?,?)',
                (result['report_sha256'], result['helpers_sha256'], result['status'],
                 result['identity_count'], result['slot_count'], result['edge_count'],
                 result['total_capacity'], result['maxflow']))
            run_id = cur.lastrowid
            self.conn.executemany(
                'INSERT INTO slots(run_id,slot_index,age_label,postal_label,category,'
                'capacity) VALUES(?,?,?,?,?,?)',
                [(run_id, s['index'], s['age_label'], s['postal_label'],
                  s['category'], s['capacity']) for s in result['slots']])
            self.conn.executemany(
                'INSERT INTO edges(run_id,identity_index,slot_index,matched,usable) '
                'VALUES(?,?,?,?,?)',
                [(run_id, e['identity_index'], e['slot_index'], e['matched'],
                  e['usable']) for e in result['edges']])
            for outcome in result['outcomes']:
                identity = result['identities'][outcome['identity_index']]
                self.conn.execute(
                    'INSERT INTO identity_outcomes(run_id,identity_index,id,age_min,'
                    'age_max,postal_prefix,forced_exposure,forced_category) '
                    'VALUES(?,?,?,?,?,?,?,?)',
                    (run_id, identity['index'], identity['id'], identity['age_min'],
                     identity['age_max'], identity['postal_prefix'],
                     outcome['forced_exposure'], outcome['forced_category']))
                self.conn.executemany(
                    'INSERT INTO identity_possible_categories(run_id,identity_index,'
                    'category) VALUES(?,?,?)',
                    [(run_id, identity['index'], category)
                     for category in outcome['possible_categories']])
            hall = result['hall']
            if hall is not None:
                self.conn.execute(
                    'INSERT INTO hall_witnesses(run_id,witness_set_size,'
                    'neighbor_slot_count,neighbor_capacity,deficit) VALUES(?,?,?,?,?)',
                    (run_id, len(hall['witness_identities']),
                     len(hall['neighbor_slots']), hall['neighbor_capacity'],
                     hall['deficit']))
                self.conn.executemany(
                    'INSERT INTO hall_witness_identities(run_id,identity_index,id) '
                    'VALUES(?,?,?)',
                    [(run_id, i, result['identities'][i]['id'])
                     for i in hall['witness_identities']])
                self.conn.executemany(
                    'INSERT INTO hall_witness_slots(run_id,slot_index,capacity) '
                    'VALUES(?,?,?)',
                    [(run_id, j, result['slots'][j]['capacity'])
                     for j in hall['neighbor_slots']])
            # The full digest index of every input identity is part of the same
            # atomic transaction: a run is either fully indexed or absent.
            self.conn.executemany(
                'INSERT INTO run_identity_index(run_id,identity_index,id_digest) '
                'VALUES(?,?,?)',
                [(run_id, identity['index'], id_digest(identity['id']))
                 for identity in result['identities']])
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            if gate is not None:
                gate.close()
        return run_id

    # ------------------------------------------------------------------ #
    # Erase phase 2: conservative purge, one atomic transaction
    # ------------------------------------------------------------------ #

    def _delete_runs(self, run_ids):
        """Delete every table row belonging to the given runs; return counts."""
        if not run_ids:
            return 0, 0
        index_deleted = 0
        rows_deleted = 0
        child_tables = (
            'hall_witness_slots', 'hall_witness_identities', 'hall_witnesses',
            'identity_possible_categories', 'identity_outcomes', 'edges',
            'slots', 'run_identity_index')
        for chunk in _chunks(sorted(run_ids), _SQL_VAR_CHUNK):
            placeholders = ','.join('?' for _ in chunk)
            for table in child_tables:
                cur = self.conn.execute(
                    'DELETE FROM %s WHERE run_id IN (%s)' % (table, placeholders),
                    chunk)
                rows_deleted += cur.rowcount
                if table == 'run_identity_index':
                    index_deleted = cur.rowcount
            cur = self.conn.execute(
                'DELETE FROM runs WHERE run_id IN (%s)' % placeholders, chunk)
            rows_deleted += cur.rowcount
        return index_deleted, rows_deleted

    def purge_for_erase(self, request_id, target_digests):
        """Atomically remove every run that contains or cannot exclude a target.

        * pre-binding runs without a complete identity index cannot be proven
          unrelated, so they are conservatively deleted on the first erase;
        * indexed runs whose digest index hits any target are deleted with
          every slot, edge, conclusion, category and Hall-derived record;
        * fully indexed runs with no digest hit are retained field by field.

        The durable resume marker is written in the same transaction.  A
        resumed request returns the stored counts and deletes nothing again,
        so runs created after the original completion can never be touched.
        """
        already = self.erase_progress(request_id)
        if already is not None:
            return already
        try:
            self.conn.execute('BEGIN IMMEDIATE')
            all_runs = {row[0] for row in self.conn.execute(
                'SELECT run_id FROM runs')}
            # A run counts as fully indexed only when its index covers every
            # input identity recorded on the run row.
            complete = {row[0] for row in self.conn.execute(
                'SELECT i.run_id FROM run_identity_index i '
                'JOIN runs r ON r.run_id=i.run_id '
                'GROUP BY i.run_id HAVING COUNT(*)=r.identity_count')}
            legacy_runs = all_runs - complete
            matched = set()
            for chunk in _chunks(sorted(target_digests), _SQL_VAR_CHUNK):
                placeholders = ','.join('?' for _ in chunk)
                matched.update(row[0] for row in self.conn.execute(
                    'SELECT DISTINCT run_id FROM run_identity_index '
                    'WHERE id_digest IN (%s)' % placeholders, chunk))
            # Indexed-but-incomplete runs are legacy too: the index cannot
            # prove the missing identities are unrelated.
            doomed = legacy_runs | matched
            index_deleted, rows_deleted = self._delete_runs(doomed)
            self.conn.execute(
                'INSERT INTO erase_progress(request_id,runs_deleted,'
                'index_deleted,rows_deleted) VALUES(?,?,?,?)',
                (request_id, len(doomed), index_deleted, rows_deleted))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return {'request_id': request_id, 'runs_deleted': len(doomed),
                'index_deleted': index_deleted, 'rows_deleted': rows_deleted}
