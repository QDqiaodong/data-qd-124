"""Incremental strict JSON parsing for the single-shot input contract.

The source is consumed as a byte stream: chunks are decoded with an
incremental codec (multi-byte characters may straddle chunk boundaries), the
grammar is matched with position-based regexes directly on the buffer (no
substring copies), and each validated record is handed to a sink in bounded
batches.  Only the current token plus one batch of records is ever held in
memory, so a 1 GiB source with up to one million rows fits in a small
constant footprint.  ``records`` may appear before ``k``/``max_suppressed``;
the parameters are validated whenever they are encountered.

Rejection semantics mirror common.read + model.parse_input: duplicate object
keys, unknown fields, non-finite numbers, non-integer or boolean values in
integer positions, blank identifiers, malformed postals, oversized arrays and
trailing garbage all raise ValueError (the CLI maps that to exit 2).  The
SHA-256 digest covers every byte of the source, exactly like common.read.
"""
from __future__ import annotations

import codecs
import hashlib
import json
import os
import re

from .common import ident, number
from .model import MAX_BUDGET, MAX_K, MAX_ROWS

MAX_SOURCE_BYTES = 1 << 30          # 1 GiB
DEFAULT_CHUNK_BYTES = 1 << 20       # read/decode granularity
_BATCH_ROWS = 1000                  # records handed to the sink per flush
_MAX_STRING_CHARS = 4096            # decoded cap; the contract allows <=128
_MAX_STRING_RAW = 6 * _MAX_STRING_CHARS + 2
_MAX_NUMBER_CHARS = 4300            # CPython's int<->str conversion ceiling

_STRING_RE = re.compile(r'"((?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*)"')
_NUMBER_RE = re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?')
_POSTAL_RE = re.compile(r'[0-9]{5}')
_WS = ' \t\n\r'
_NUMBER_END = frozenset(' \t\n\r,]}')
_TOP_KEYS = frozenset(('k', 'max_suppressed', 'records'))
_RECORD_KEYS = frozenset(('id', 'age', 'postal', 'category'))
_MSG_TOP = 'expected object fields: k max_suppressed records'
_MSG_RECORD = 'expected object fields: id age postal category'
_MSG_IDENT = 'expected nonblank identifier, <=128 characters'
_MSG_POSTAL = 'postal must be exactly five ASCII digits'
_LITERALS = {'t': 'true', 'f': 'false', 'n': 'null'}


class _Reader:
    """Chunked byte source with incremental decoding and running SHA-256."""

    def __init__(self, stream, chunk_size):
        self._stream = stream
        self._chunk = max(1, int(chunk_size))
        self._hasher = hashlib.sha256()
        self._total = 0
        self._decoder = None
        self._pending = b''           # raw bytes held back for encoding sniffing
        self.buf = ''
        self.pos = 0
        self.eof = False

    def fill(self):
        """Append more input to buf.  On return, either buf grew or eof is
        True.  Token parsers call this in a loop until they can proceed."""
        if self.eof:
            return
        if self.pos:
            # Drop the consumed prefix; what remains is at most one token.
            self.buf = self.buf[self.pos:]
            self.pos = 0
        while True:
            chunk = self._stream.read(self._chunk)
            if not chunk:
                self.eof = True
                if self._decoder is None:
                    # Same encoding sniffing as json.loads(bytes): the first
                    # bytes decide utf-8 / utf-8-sig / utf-16 / utf-32.
                    self._decoder = codecs.getincrementaldecoder(
                        json.detect_encoding(self._pending))()
                self.buf += self._decoder.decode(self._pending, True)
                self._pending = b''
                return
            self._hasher.update(chunk)
            self._total += len(chunk)
            if self._total > MAX_SOURCE_BYTES:
                raise ValueError('JSON exceeds 1 GiB')
            if self._decoder is None:
                self._pending += chunk
                if len(self._pending) < 4:
                    continue
                self._decoder = codecs.getincrementaldecoder(
                    json.detect_encoding(self._pending))()
                chunk, self._pending = self._pending, b''
            text = self._decoder.decode(chunk, False)
            if text:
                self.buf += text
                return
            # The decoder is holding a partial multi-byte character; read on.

    def digest(self):
        return self._hasher.hexdigest()


def _skip_ws(r):
    while True:
        buf = r.buf
        pos = r.pos
        n = len(buf)
        while pos < n and buf[pos] in _WS:
            pos += 1
        r.pos = pos
        if pos < n or r.eof:
            return
        r.fill()


def _peek(r):
    """Next non-whitespace character, or '' at end of input."""
    _skip_ws(r)
    if r.pos < len(r.buf):
        return r.buf[r.pos]
    return ''


def _expect(r, ch):
    if _peek(r) != ch:
        raise ValueError('invalid JSON: expected %r' % ch)
    r.pos += 1


def _second_is_i(r):
    while len(r.buf) - r.pos < 2 and not r.eof:
        r.fill()
    return r.buf[r.pos + 1:r.pos + 2] == 'I'


def _parse_string(r):
    """Parse a string token; r.buf[r.pos] must be the opening quote."""
    while True:
        m = _STRING_RE.match(r.buf, r.pos)
        if m is not None:
            raw = m.group(1)
            r.pos = m.end()
            if '\\' in raw:
                # Rare path: reuse the strict stdlib decoder for escapes,
                # including surrogate pairs.
                value = json.loads('"' + raw + '"')
            else:
                value = raw
            if len(value) > _MAX_STRING_CHARS:
                raise ValueError('string value too long')
            return value
        if r.eof or len(r.buf) - r.pos > _MAX_STRING_RAW:
            raise ValueError('invalid or overlong JSON string')
        r.fill()


def _parse_number(r):
    """Parse a number token; returns an int, or None for a float token."""
    while True:
        m = _NUMBER_RE.match(r.buf, r.pos)
        if m is not None and (m.end() < len(r.buf) or r.eof):
            end = m.end()
            if end < len(r.buf) and r.buf[end] not in _NUMBER_END:
                raise ValueError('invalid JSON number')
            token = m.group(0)
            r.pos = end
            if len(token) > _MAX_NUMBER_CHARS:
                raise ValueError('JSON number too long')
            if '.' in token or 'e' in token or 'E' in token:
                return None
            return int(token)
        if r.eof or len(r.buf) - r.pos > _MAX_NUMBER_CHARS + 2:
            raise ValueError('invalid JSON number')
        r.fill()


def _parse_literal(r, word):
    while True:
        avail = len(r.buf) - r.pos
        n = min(avail, len(word))
        if r.buf[r.pos:r.pos + n] != word[:n]:
            raise ValueError('invalid JSON token')
        if avail >= len(word):
            r.pos += len(word)
            return
        if r.eof:
            raise ValueError('invalid JSON token')
        r.fill()


def _nonfinite(r):
    """Raise the nonfinite-number error if a NaN/Infinity token follows."""
    c = _peek(r)
    if c == 'N':
        _parse_literal(r, 'NaN')
        raise ValueError('nonfinite JSON number: NaN')
    if c == 'I':
        _parse_literal(r, 'Infinity')
        raise ValueError('nonfinite JSON number: Infinity')
    if c == '-' and _second_is_i(r):
        _parse_literal(r, '-Infinity')
        raise ValueError('nonfinite JSON number: -Infinity')
    return c


def _parse_int_value(r):
    """Value in an integer position (k, max_suppressed, age)."""
    c = _nonfinite(r)
    if c and (c.isdigit() or c == '-'):
        v = _parse_number(r)
        if v is None:
            raise ValueError('integer outside allowed bounds')
        return v
    if c in _LITERALS:
        _parse_literal(r, _LITERALS[c])
        raise ValueError('integer outside allowed bounds')
    if c in '"[{':
        raise ValueError('integer outside allowed bounds')
    raise ValueError('invalid JSON value')


def _parse_str_value(r, message):
    """Value in a string position (id, postal, category)."""
    c = _nonfinite(r)
    if c == '"':
        return _parse_string(r)
    if c in _LITERALS:
        _parse_literal(r, _LITERALS[c])
        raise ValueError(message)
    if c and (c.isdigit() or c == '-'):
        _parse_number(r)
        raise ValueError(message)
    if c in '[{':
        raise ValueError(message)
    raise ValueError('invalid JSON value')


def _parse_record(r):
    """Parse and validate one record object; returns (id, age, postal, category)."""
    if _peek(r) != '{':
        raise ValueError(_MSG_RECORD)
    r.pos += 1
    seen = set()
    rid = age = postal = category = None
    if _peek(r) == '}':
        r.pos += 1
    else:
        while True:
            if _peek(r) != '"':
                raise ValueError('expected object keys')
            key = _parse_string(r)
            if key in seen:
                raise ValueError('duplicate JSON key: ' + key)
            seen.add(key)
            _expect(r, ':')
            if key == 'id':
                rid = _parse_str_value(r, _MSG_IDENT)
            elif key == 'age':
                age = _parse_int_value(r)
            elif key == 'postal':
                postal = _parse_str_value(r, _MSG_POSTAL)
            elif key == 'category':
                category = _parse_str_value(r, _MSG_IDENT)
            else:
                raise ValueError(_MSG_RECORD)
            c = _peek(r)
            if c == ',':
                r.pos += 1
                continue
            if c == '}':
                r.pos += 1
                break
            raise ValueError("invalid JSON: expected ',' or '}'")
    if seen != _RECORD_KEYS:
        raise ValueError(_MSG_RECORD)
    ident(rid)
    number(age, 0, 120)
    ident(category)
    if _POSTAL_RE.fullmatch(postal) is None:
        raise ValueError(_MSG_POSTAL)
    return rid, age, postal, category


def _parse_records(r, sink):
    if _peek(r) != '[':
        raise ValueError('expected bounded array')
    r.pos += 1
    count = 0
    batch = []
    if _peek(r) == ']':
        r.pos += 1
        return 0
    while True:
        batch.append(_parse_record(r))
        count += 1
        if count > MAX_ROWS:
            raise ValueError('expected bounded array')
        if len(batch) >= _BATCH_ROWS:
            sink(batch)
            batch.clear()
        c = _peek(r)
        if c == ',':
            r.pos += 1
            continue
        if c == ']':
            r.pos += 1
            break
        raise ValueError("invalid JSON: expected ',' or ']'")
    if batch:
        sink(batch)
    return count


def parse_contract(stream, sink, chunk_size=DEFAULT_CHUNK_BYTES):
    """Stream-parse one contract document from a binary stream.

    ``sink`` receives batches of validated ``(id, age, postal, category)``
    tuples.  Returns ``(k, max_suppressed, row_count, source_sha256)``.
    """
    try:
        # Cheap up-front limit for regular files (matches the original
        # implementation, which rejects oversized input before parsing);
        # the reader enforces the same bound while streaming as a backstop.
        if os.fstat(stream.fileno()).st_size > MAX_SOURCE_BYTES:
            raise ValueError('JSON exceeds 1 GiB')
    except (OSError, AttributeError):
        pass
    r = _Reader(stream, chunk_size)
    k = budget = None
    rows = 0
    seen = set()
    if _peek(r) != '{':
        raise ValueError(_MSG_TOP)
    r.pos += 1
    if _peek(r) == '}':
        r.pos += 1
    else:
        while True:
            if _peek(r) != '"':
                raise ValueError('expected object keys')
            key = _parse_string(r)
            if key in seen:
                raise ValueError('duplicate JSON key: ' + key)
            seen.add(key)
            _expect(r, ':')
            if key == 'k':
                k = _parse_int_value(r)
                number(k, 2, MAX_K)
            elif key == 'max_suppressed':
                budget = _parse_int_value(r)
                number(budget, 0, MAX_BUDGET)
            elif key == 'records':
                rows = _parse_records(r, sink)
            else:
                raise ValueError(_MSG_TOP)
            c = _peek(r)
            if c == ',':
                r.pos += 1
                continue
            if c == '}':
                r.pos += 1
                break
            raise ValueError("invalid JSON: expected ',' or '}'")
    if seen != _TOP_KEYS:
        raise ValueError(_MSG_TOP)
    if rows == 0:
        raise ValueError('records cannot be empty')
    _skip_ws(r)
    if not r.eof or r.pos < len(r.buf):
        raise ValueError('extra data after JSON document')
    return k, budget, rows, r.digest()
