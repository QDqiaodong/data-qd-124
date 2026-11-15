"""Disk-backed single-shot engine for the v1 contract at 1 GiB / 1M rows.

Pipeline (nothing larger than one batch or one token is held in memory):

1. streamjson.parse_contract streams the source into a private SQLite
   workfile in a private temporary directory (the disk intermediate layer).
   Duplicate ids are rejected by a PRIMARY KEY BLOB; categories and ids are
   stored as surrogatepass-encoded BLOBs so every Python str round-trips and
   BINARY ordering stays identical to Python's code-point ordering.
2. The nine global recodings are evaluated with SQL GROUP BY queries whose
   label expressions reproduce generalize.bucket exactly; candidate
   suppression counts, feasibility and the (cost, suppressed, age, postal)
   ordering are identical to model.analyze.
3. The report is written as a byte stream: one emission pass feeds a compact
   writer (stdout form, json.dumps default separators) and an indented writer
   (file form, indent=2) simultaneously.  The indented half lands in a
   temporary file next to the output and is atomically os.replace()d into
   place; only then is the compact half streamed to stdout.  Any input or
   computation failure therefore leaves the previous report untouched and
   produces no partial stdout, and the private temporary directory (which
   holds ids and categories) is removed in all outcomes.

model.analyze remains the in-memory reference implementation; the
measurement harness compares this engine against it field for field.
"""
from __future__ import annotations

import itertools
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from fractions import Fraction
from pathlib import Path

from .model import PRIVACY_SCOPE
from .streamjson import DEFAULT_CHUNK_BYTES, parse_contract

_CHUNK_ENV = 'TABLE_PRIVACY_CHUNK_BYTES'   # test-only knob: parser read size

_SCHEMA = """
PRAGMA journal_mode = OFF;
PRAGMA synchronous = OFF;
PRAGMA temp_store = FILE;
CREATE TABLE ids (id BLOB PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE records (age INTEGER NOT NULL, postal TEXT NOT NULL, category BLOB NOT NULL);
"""

# SQL label expressions mirroring generalize.bucket for the validated domain
# (age is an integer 0..120, postal is exactly five ASCII digits).
_AGE_SQL = (
    'CAST(age AS TEXT)',
    "((age / 10 * 10) || '-' || MIN(120, age / 10 * 10 + 9))",
    "'*'",
)
_POSTAL_SQL = (
    'postal',
    "(SUBSTR(postal, 1, 3) || '**')",
    "'*'",
)

_COUNTS_SQL = """
SELECT COALESCE(SUM(CASE WHEN cnt < ? THEN cnt END), 0),
       COALESCE(SUM(CASE WHEN cnt >= ? THEN 1 ELSE 0 END), 0)
FROM (SELECT {age} AS al, {postal} AS pl, COUNT(*) AS cnt
      FROM records GROUP BY al, pl)
"""

_KEPT_SQL = """
SELECT al, pl, category, n, sz FROM (
    SELECT al, pl, category, n, SUM(n) OVER (PARTITION BY al, pl) AS sz
    FROM (SELECT {age} AS al, {postal} AS pl, category, COUNT(*) AS n
          FROM records GROUP BY al, pl, category)
) WHERE sz >= ? ORDER BY al, pl, category
"""


def _encode(text):
    return text.encode('utf-8', 'surrogatepass')


class _Sink:
    """Batches validated records into the SQLite intermediate layer."""

    def __init__(self, conn):
        self._conn = conn

    def __call__(self, batch):
        try:
            self._conn.executemany(
                'INSERT INTO ids(id) VALUES(?)',
                [(_encode(row[0]),) for row in batch])
        except sqlite3.IntegrityError:
            raise ValueError('duplicate source row ID') from None
        self._conn.executemany(
            'INSERT INTO records(age, postal, category) VALUES(?,?,?)',
            [(row[1], row[2], _encode(row[3])) for row in batch])


# ---------------------------------------------------------------------------
# Streaming JSON report writer.  Emits byte-for-byte the same documents as
# json.dumps(..., sort_keys=True, ensure_ascii=False, allow_nan=False) with
# indent=2 (file form) or default separators (stdout form); report keys are
# always produced in sorted order by the emission code below.

_ESCAPES = {
    0x22: '\\"',
    0x5C: '\\\\',
    0x08: '\\b',
    0x09: '\\t',
    0x0A: '\\n',
    0x0C: '\\f',
    0x0D: '\\r',
}
_NEED_ESCAPE = re.compile(r'["\\\x00-\x1f]')


def _escape_str(text):
    """json.dumps(text, ensure_ascii=False) without the surrounding call."""
    if _NEED_ESCAPE.search(text) is None:
        return '"' + text + '"'
    parts = []
    for ch in text:
        code = ord(ch)
        if code in _ESCAPES:
            parts.append(_ESCAPES[code])
        elif code < 0x20:
            parts.append('\\u%04x' % code)
        else:
            parts.append(ch)
    return '"' + ''.join(parts) + '"'


def _escape_bytes(text):
    # Encoding a lone surrogate raises UnicodeEncodeError (a ValueError),
    # matching the reference implementation, whose json.dump to a UTF-8 file
    # fails on such input; the CLI maps it to exit 2 with the old report kept.
    return _escape_str(text).encode('utf-8')


class _JsonWriter:
    """Token-level JSON serializer for one output stream."""

    def __init__(self, write, pretty):
        self._write = write
        self._pretty = pretty
        self._stack = []
        self._counts = []

    def _pre_value(self):
        if self._stack and self._stack[-1] == '[':
            if self._counts[-1]:
                self._write(b', ' if not self._pretty else b',')
            if self._pretty:
                self._write(b'\n' + b'  ' * len(self._stack))
            self._counts[-1] += 1

    def begin(self, kind):
        self._pre_value()
        self._write(b'{' if kind == '{' else b'[')
        self._stack.append(kind)
        self._counts.append(0)

    def end(self):
        kind = self._stack.pop()
        count = self._counts.pop()
        if count and self._pretty:
            self._write(b'\n' + b'  ' * len(self._stack))
        self._write(b'}' if kind == '{' else b']')

    def key(self, name):
        if self._counts[-1]:
            self._write(b', ' if not self._pretty else b',')
        if self._pretty:
            self._write(b'\n' + b'  ' * len(self._stack))
        self._counts[-1] += 1
        self._write(_escape_bytes(name))
        self._write(b': ')

    def value(self, item):
        self._pre_value()
        if item is True:
            self._write(b'true')
        elif item is False:
            self._write(b'false')
        elif item is None:
            self._write(b'null')
        elif isinstance(item, int):
            self._write(str(item).encode('ascii'))
        elif isinstance(item, str):
            self._write(_escape_bytes(item))
        else:
            raise TypeError('cannot serialize %r' % type(item))

    def category_entry(self, escaped_category, count):
        """One 'category: count' entry inside a category_counts object."""
        if self._counts[-1]:
            self._write(b', ' if not self._pretty else b',')
        if self._pretty:
            self._write(b'\n' + b'  ' * len(self._stack))
        self._counts[-1] += 1
        self._write(escaped_category + b': ' + str(count).encode('ascii'))

    def released_row(self, age, category, postal):
        """One released_rows object from pre-escaped label bytes."""
        self._pre_value()
        if self._pretty:
            field = b'  ' * (len(self._stack) + 1)
            closing = b'  ' * len(self._stack)
            self._write(b'{\n' + field + b'"age": ' + age
                        + b',\n' + field + b'"category": ' + category
                        + b',\n' + field + b'"postal": ' + postal
                        + b'\n' + closing + b'}')
        else:
            self._write(b'{"age": ' + age + b', "category": ' + category
                        + b', "postal": ' + postal + b'}')

    def raw(self, data):
        self._write(data)


class _Multi:
    """Fans one token stream out to several writers (compact + indented)."""

    def __init__(self, writers):
        self._writers = writers

    def begin(self, kind):
        for w in self._writers:
            w.begin(kind)

    def end(self):
        for w in self._writers:
            w.end()

    def key(self, name):
        for w in self._writers:
            w.key(name)

    def value(self, item):
        for w in self._writers:
            w.value(item)

    def category_entry(self, escaped_category, count):
        for w in self._writers:
            w.category_entry(escaped_category, count)

    def released_row(self, age, category, postal):
        for w in self._writers:
            w.released_row(age, category, postal)

    def raw(self, data):
        for w in self._writers:
            w.raw(data)


# ---------------------------------------------------------------------------

def _candidate_counts(conn, age_level, postal_level, k):
    sql = _COUNTS_SQL.format(age=_AGE_SQL[age_level], postal=_POSTAL_SQL[postal_level])
    suppressed, kept = conn.execute(sql, (k, k)).fetchone()
    return suppressed, kept > 0


def _kept_class_rows(conn, age_level, postal_level, k):
    sql = _KEPT_SQL.format(age=_AGE_SQL[age_level], postal=_POSTAL_SQL[postal_level])
    return conn.execute(sql, (k,))


def _analyze(conn, k, budget, input_rows, digest):
    """Nine-candidate scan; mirrors model.analyze's selection exactly."""
    candidates = []
    feasible = []
    for age_level, postal_level in itertools.product(range(3), repeat=2):
        suppressed, kept = _candidate_counts(conn, age_level, postal_level, k)
        loss = Fraction(age_level + postal_level, 4)
        admissible = kept and suppressed <= budget
        candidates.append({'age_level': age_level, 'postal_level': postal_level,
                           'suppressed': suppressed,
                           'ordinal_generalization_cost': str(loss),
                           'feasible': admissible})
        if admissible:
            feasible.append((loss, suppressed, age_level, postal_level))
    meta = {'k': k, 'input_rows': input_rows, 'digest': digest,
            'candidates': candidates}
    if not feasible:
        meta['feasible'] = False
        return meta
    loss, suppressed, age_level, postal_level = min(feasible)
    meta.update(feasible=True, suppressed=suppressed,
                age_level=age_level, postal_level=postal_level,
                loss=str(loss))
    return meta


def _emit_classes(writer, conn, meta):
    """equivalence_classes array; returns released_count for the report."""
    writer.begin('[')
    released = 0
    current = None
    distinct = size = 0
    for al, pl, category, n, sz in _kept_class_rows(conn, meta['age_level'],
                                                    meta['postal_level'], meta['k']):
        if (al, pl) != current:
            if current is not None:
                writer.end()
                writer.key('distinct_categories')
                writer.value(distinct)
                writer.key('postal')
                writer.value(current[1])
                writer.key('size')
                writer.value(size)
                writer.end()
            writer.begin('{')
            writer.key('age')
            writer.value(al)
            writer.key('category_counts')
            writer.begin('{')
            current = (al, pl)
            distinct = 0
            size = sz
        writer.category_entry(_escape_bytes(category.decode('utf-8', 'surrogatepass')), n)
        distinct += 1
        released += n
    if current is not None:
        writer.end()
        writer.key('distinct_categories')
        writer.value(distinct)
        writer.key('postal')
        writer.value(current[1])
        writer.key('size')
        writer.value(size)
        writer.end()
    writer.end()
    return released


def _emit_released(writer, conn, meta):
    writer.begin('[')
    for al, pl, category, n, _sz in _kept_class_rows(conn, meta['age_level'],
                                                     meta['postal_level'], meta['k']):
        age = _escape_bytes(al)
        cat = _escape_bytes(category.decode('utf-8', 'surrogatepass'))
        postal = _escape_bytes(pl)
        for _ in range(n):
            writer.released_row(age, cat, postal)
    writer.end()


def _emit_result(writer, conn, meta):
    writer.begin('{')
    writer.key('candidates')
    writer.begin('[')
    for cand in meta['candidates']:
        writer.begin('{')
        writer.key('age_level')
        writer.value(cand['age_level'])
        writer.key('feasible')
        writer.value(cand['feasible'])
        writer.key('ordinal_generalization_cost')
        writer.value(cand['ordinal_generalization_cost'])
        writer.key('postal_level')
        writer.value(cand['postal_level'])
        writer.key('suppressed')
        writer.value(cand['suppressed'])
        writer.end()
    writer.end()
    writer.key('equivalence_classes')
    if meta['feasible']:
        released_count = _emit_classes(writer, conn, meta)
    else:
        writer.begin('[')
        writer.end()
    writer.key('feasible')
    writer.value(meta['feasible'])
    writer.key('input_rows')
    writer.value(meta['input_rows'])
    writer.key('k')
    writer.value(meta['k'])
    if meta['feasible']:
        writer.key('privacy_scope')
        writer.value(PRIVACY_SCOPE)
        writer.key('released_count')
        writer.value(released_count)
        writer.key('released_rows')
        _emit_released(writer, conn, meta)
        writer.key('selected')
        writer.begin('{')
        writer.key('age_level')
        writer.value(meta['age_level'])
        writer.key('ordinal_generalization_cost')
        writer.value(meta['loss'])
        writer.key('postal_level')
        writer.value(meta['postal_level'])
        writer.end()
        writer.key('suppressed_rows')
        writer.value(meta['suppressed'])
    else:
        writer.key('released_rows')
        writer.begin('[')
        writer.end()
    writer.end()


def _emit_report(writer, conn, meta):
    writer.begin('{')
    writer.key('result')
    _emit_result(writer, conn, meta)
    writer.key('schema_version')
    writer.value(1)
    writer.key('source_sha256')
    writer.value(meta['digest'])
    writer.end()
    writer.raw(b'\n')


def _chunk_size():
    raw = os.environ.get(_CHUNK_ENV)
    if raw is None:
        return DEFAULT_CHUNK_BYTES
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_CHUNK_BYTES


def _remove_tree(path):
    try:
        shutil.rmtree(path)
    except OSError as error:
        print('warning: could not remove private temporary directory %s: %s'
              % (path, error), file=sys.stderr)


def publish(source, output, stdout, chunk_size=None):
    """Run the single-shot contract end to end.

    Writes the indented report to ``output`` (atomically, preserving any
    previous report on failure) and the compact report to the ``stdout``
    binary stream.  Returns the small analysis metadata dict.  Raises
    ValueError/OSError/sqlite3.Error on any input or computation failure;
    the caller maps those to exit code 2.
    """
    if chunk_size is None:
        chunk_size = _chunk_size()
    tmp = tempfile.mkdtemp(prefix='table-privacy-')
    temp_report = None
    try:
        conn = sqlite3.connect(os.path.join(tmp, 'work.sqlite3'))
        try:
            conn.executescript(_SCHEMA)
            with open(source, 'rb') as stream:
                k, budget, input_rows, digest = parse_contract(
                    stream, _Sink(conn), chunk_size)
            conn.commit()
            meta = _analyze(conn, k, budget, input_rows, digest)
            dest = Path(output)
            if dest.is_symlink():
                raise ValueError('output cannot be a symlink')
            dest.parent.mkdir(parents=True, exist_ok=True)
            compact_path = os.path.join(tmp, 'report.compact')
            with open(compact_path, 'wb', buffering=1 << 20) as compact, \
                    tempfile.NamedTemporaryFile(mode='wb', dir=dest.parent,
                                                delete=False,
                                                buffering=1 << 20) as indented:
                temp_report = indented.name
                writer = _Multi([_JsonWriter(compact.write, pretty=False),
                                 _JsonWriter(indented.write, pretty=True)])
                _emit_report(writer, conn, meta)
        finally:
            conn.close()
        os.replace(temp_report, dest)
        temp_report = None
        with open(compact_path, 'rb') as stream:
            shutil.copyfileobj(stream, stdout, 1 << 20)
        stdout.flush()
        return meta
    finally:
        if temp_report is not None and os.path.exists(temp_report):
            os.unlink(temp_report)
        _remove_tree(tmp)
