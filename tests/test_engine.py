"""Differential and robustness tests for the streaming single-shot engine.

engine.publish (SQLite intermediate layer + streaming report) must agree with
the in-memory reference implementation model.analyze field for field and byte
for byte, on any chunking of the input, while preserving every rejection
semantics of the original implementation.
"""
import codecs
import io
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from table_privacy import engine
from table_privacy.common import read
from table_privacy.model import analyze

ROOT = Path(__file__).resolve().parents[1]


def canonical(report):
    pretty = (json.dumps(report, sort_keys=True, ensure_ascii=False,
                         allow_nan=False, indent=2) + '\n').encode('utf-8')
    compact = (json.dumps(report, sort_keys=True, ensure_ascii=False,
                          allow_nan=False) + '\n').encode('utf-8')
    return pretty, compact


def reference(source_bytes):
    """Reference report via the original in-memory path (common.read+analyze)."""
    tmp = tempfile.NamedTemporaryFile(delete=False)
    try:
        tmp.write(source_bytes)
        tmp.close()
        data, digest = read(tmp.name)
    finally:
        os.unlink(tmp.name)
    return {'schema_version': 1, 'source_sha256': digest, 'result': analyze(data)}


def assert_report_fields_equal(testcase, got, want, path='report'):
    """Field-by-field comparison with precise failure locations."""
    if isinstance(want, dict):
        testcase.assertIsInstance(got, dict, path)
        testcase.assertEqual(set(got), set(want), path)
        for key in sorted(want):
            assert_report_fields_equal(testcase, got[key], want[key],
                                       '%s.%s' % (path, key))
    elif isinstance(want, list):
        testcase.assertIsInstance(got, list, path)
        testcase.assertEqual(len(got), len(want), path)
        for i, item in enumerate(want):
            assert_report_fields_equal(testcase, got[i], item, '%s[%d]' % (path, i))
    else:
        testcase.assertEqual(got, want, path)


def escape_random(text, rng):
    """Random valid JSON string token for text (random escape forms)."""
    out = ['"']
    for ch in text:
        code = ord(ch)
        choice = rng.randrange(8)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\n' and choice < 5:
            out.append('\\n')
        elif ch == '\t' and choice < 5:
            out.append('\\t')
        elif ch == '\r' and choice < 5:
            out.append('\\r')
        elif ch == '\b' and choice < 5:
            out.append('\\b')
        elif ch == '\f' and choice < 5:
            out.append('\\f')
        elif code < 0x20:
            out.append('\\u%04x' % code)
        elif ch == '/' and choice == 0:
            out.append('\\/')
        elif 0xD800 <= code <= 0xDFFF:
            out.append('\\u%04x' % code)        # lone surrogates must be escaped
        elif code > 0xFFFF and choice == 0:
            hi = 0xD800 + ((code - 0x10000) >> 10)
            lo = 0xDC00 + ((code - 0x10000) & 0x3FF)
            out.append('\\u%04x\\u%04x' % (hi, lo))
        elif choice in (1, 2):
            out.append('\\u%04x' % code)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def serialize(case, rng):
    """Serialize a contract dict with shuffled key order and random spacing."""
    def ws():
        return rng.choice(['', ' ', '  ', '\n', '\t', ' \n']) if rng.random() < 0.5 else ''

    def record_text(rec):
        keys = list(rec)
        rng.shuffle(keys)
        items = [escape_random(key, rng) + ws() + ':' + ws() +
                 (str(rec[key]) if key == 'age' else escape_random(rec[key], rng))
                 for key in keys]
        return '{' + ws() + (',' + ws()).join(items) + ws() + '}'

    items = []
    keys = ['k', 'max_suppressed', 'records']
    rng.shuffle(keys)
    for key in keys:
        if key == 'records':
            value = '[' + ws() + (',' + ws()).join(record_text(r) for r in case['records']) + ws() + ']'
        else:
            value = str(case[key])
        items.append(escape_random(key, rng) + ws() + ':' + ws() + value)
    return '{' + ws() + (',' + ws()).join(items) + ws() + '}'


def encode_random(text, rng):
    choice = rng.choices(['utf-8', 'utf-8-sig', 'utf-16-le-bom', 'utf-16-be-bom',
                          'utf-16-le', 'utf-16-be'],
                         weights=[68, 6, 5, 5, 8, 8])[0]
    if choice == 'utf-16-le-bom':
        return codecs.BOM_UTF16_LE + text.encode('utf-16-le')
    if choice == 'utf-16-be-bom':
        return codecs.BOM_UTF16_BE + text.encode('utf-16-be')
    return text.encode(choice)


CATEGORIES = ['blue', 'green', 'red', 'a', 'Z', 'é', '€', '😀', '𐀀', 'x y',
              'q"q', 'b\\b', 'sl/ash', '\x7f', '①②③', 'café', 'A', '0', '*',
              '~', 'é', 'ＸＹＺ', 'null', 'true', 'NaN-ish']


def random_case(rng, tag):
    rows = []
    for i in range(rng.randint(1, 30)):
        rows.append({
            'id': 'id-%s-%d' % (tag, i),
            'age': rng.choice([0, 1, 9, 10, 25, 42, 99, 119, 120,
                               rng.randint(0, 120)]),
            'postal': rng.choice(['00000', '12345', '99999', '00123',
                                  '%05d' % rng.randint(0, 99999)]),
            'category': rng.choice(CATEGORIES),
        })
    return {'k': rng.randint(2, 8), 'max_suppressed': rng.randint(0, 12),
            'records': rows}


class EngineDifferentialTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def run_engine(self, source_bytes, chunk_size=None):
        src = self.tmp / 'in.json'
        out = self.tmp / 'out.json'
        src.write_bytes(source_bytes)
        stdout = io.BytesIO()
        meta = engine.publish(src, out, stdout, chunk_size=chunk_size)
        return meta, out.read_bytes(), stdout.getvalue()

    def check_case(self, source_bytes, chunk_size):
        want = reference(source_bytes)
        want_pretty, want_compact = canonical(want)
        meta, file_bytes, stdout_bytes = self.run_engine(source_bytes, chunk_size)
        self.assertEqual(file_bytes, want_pretty, 'indented report file mismatch')
        self.assertEqual(stdout_bytes, want_compact, 'compact stdout mismatch')
        assert_report_fields_equal(self, json.loads(file_bytes), want)
        # The small metadata dict must agree with the reference analysis too.
        self.assertEqual(meta['input_rows'], want['result']['input_rows'])
        self.assertEqual(meta['feasible'], want['result']['feasible'])
        self.assertEqual(meta['candidates'], want['result']['candidates'])

    def test_fixture_byte_identical_to_reference(self):
        source = (ROOT / 'fixtures' / 'input.json').read_bytes()
        for chunk in (None, 1, 3, 7, 64):
            self.check_case(source, chunk)

    def test_randomized_cases_match_reference(self):
        rng = random.Random(124124)
        for i in range(120):
            case = random_case(rng, 'case%d' % i)
            source = encode_random(serialize(case, rng), rng)
            chunk = rng.choice([None, 1, 2, 3, 5, 7, 13, 64, 4096])
            with self.subTest(case=i, chunk=chunk):
                self.check_case(source, chunk)

    def test_records_may_precede_parameters(self):
        rows = ','.join('{"id":"r%d","age":30,"postal":"12345","category":"x"}' % i
                        for i in range(50))
        source = ('{"records":[%s],"max_suppressed":1,"k":2}' % rows).encode()
        self.check_case(source, 5)

    def test_trailing_whitespace_is_accepted_and_hashed(self):
        base = json.dumps({'k': 2, 'max_suppressed': 1, 'records': [
            {'id': 'a', 'age': 1, 'postal': '00000', 'category': 'c'}]})
        self.check_case((base + '  \n\t ').encode(), None)


class EngineRejectionTests(unittest.TestCase):
    """Every rejection of the original contract must survive streaming."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.good = {'k': 2, 'max_suppressed': 1, 'records': [
            {'id': 'a', 'age': 30, 'postal': '12345', 'category': 'x'},
            {'id': 'b', 'age': 31, 'postal': '12345', 'category': 'y'}]}

    def source(self, **overrides):
        case = dict(self.good)
        case.update(overrides)
        return json.dumps(case).encode()

    def record(self, **overrides):
        rec = {'id': 'z', 'age': 30, 'postal': '12345', 'category': 'c'}
        rec.update(overrides)
        return rec

    def assert_rejected(self, source_bytes, chunk_size=None):
        src = self.tmp / 'in.json'
        out = self.tmp / 'out.json'
        src.write_bytes(source_bytes)
        out.write_bytes(b'old')
        stdout = io.BytesIO()
        with self.assertRaises(ValueError):
            engine.publish(src, out, stdout, chunk_size=chunk_size)
        self.assertEqual(out.read_bytes(), b'old', 'previous report must survive')
        self.assertEqual(stdout.getvalue(), b'', 'stdout must not carry a partial report')

    def test_structure_rejections(self):
        self.assert_rejected(b'{}')
        self.assert_rejected(b'[]')
        self.assert_rejected(b'')
        self.assert_rejected(b'NaN')
        self.assert_rejected(b'{"a":1,"a":2}')
        self.assert_rejected(b'{"k":2,"k":3,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[],"x":1}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[]}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":{}}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[[]]}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000"}]}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[{"id":"a","id":"b","age":1,"postal":"00000","category":"c"}]}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c","x":1}]}')

    def test_parameter_rejections(self):
        for bad_k in ('1', '10001', '"2"', '2.0', 'true', 'NaN', 'Infinity', '-Infinity', 'null', '[2]'):
            self.assert_rejected(('{"k":%s,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]}' % bad_k).encode())
        for bad_budget in ('-1', '1000001', '1.5', 'false', 'NaN'):
            self.assert_rejected(('{"k":2,"max_suppressed":%s,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]}' % bad_budget).encode())
        # The new upper bounds themselves are accepted.
        ok = json.dumps({'k': 10000, 'max_suppressed': 1000000, 'records': [
            {'id': 'a', 'age': 1, 'postal': '00000', 'category': 'c'}]}).encode()
        meta, _, _ = self.run_engine_ok(ok)
        self.assertEqual(meta['k'], 10000)

    def run_engine_ok(self, source_bytes):
        src = self.tmp / 'in.json'
        out = self.tmp / 'out.json'
        src.write_bytes(source_bytes)
        stdout = io.BytesIO()
        meta = engine.publish(src, out, stdout)
        return meta, out.read_bytes(), stdout.getvalue()

    def test_record_field_rejections(self):
        bad_ages = ['-1', '121', '2.5', 'true', 'false', '"30"', 'NaN', 'Infinity', '-Infinity', '1e2', 'null']
        for bad in bad_ages:
            self.assert_rejected(('{"k":2,"max_suppressed":1,"records":[{"id":"z","age":%s,"postal":"12345","category":"c"}]}' % bad).encode())
        for bad_postal in ('"1234"', '"123456"', '"１２３４５"', '12345', 'null'):
            self.assert_rejected(('{"k":2,"max_suppressed":1,"records":[{"id":"z","age":1,"postal":%s,"category":"c"}]}' % bad_postal).encode())
        for bad_id in ('""', '" x"', '"x "', '"' + 'a' * 129 + '"', '5', 'null', '"a\\u0001b"'):
            self.assert_rejected(('{"k":2,"max_suppressed":1,"records":[{"id":%s,"age":1,"postal":"00000","category":"c"}]}' % bad_id).encode())
        for bad_cat in ('""', '" "', '"' + 'c' * 129 + '"', '7', 'false'):
            self.assert_rejected(('{"k":2,"max_suppressed":1,"records":[{"id":"z","age":1,"postal":"00000","category":%s}]}' % bad_cat).encode())

    def test_duplicate_id_rejected_across_chunks(self):
        rows = [('{"id":"dup","age":30,"postal":"12345","category":"x"}'),
                ('{"id":"other","age":31,"postal":"12345","category":"y"}'),
                ('{"id":"dup","age":32,"postal":"12345","category":"z"}')]
        source = ('{"records":[%s],"k":2,"max_suppressed":1}' % ','.join(rows)).encode()
        for chunk in (None, 1, 2, 3, 5, 7, 64):
            with self.subTest(chunk=chunk):
                self.assert_rejected(source, chunk_size=chunk)

    def test_trailing_garbage_rejected(self):
        good = json.dumps(self.good).encode()
        self.assert_rejected(good + b' x')
        self.assert_rejected(good + b'}{')
        self.assert_rejected(good + b'{}')
        self.assert_rejected(good + b'\x00')

    def test_malformed_json_rejected(self):
        self.assert_rejected(b'{"k":2,')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}],}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c\\xb"}]}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c\x01d"}]}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c}]}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":01,"postal":"00000","category":"c"}]}')
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":-,"postal":"00000","category":"c"}]}')

    def test_bad_encoding_rejected(self):
        self.assert_rejected(b'{"k":2,\xff\xfe}')
        # Truncated multi-byte UTF-8 character at end of input.
        self.assert_rejected('{"k":2,"max_suppressed":1,"records":[{"id":"é","age":1,"postal":"00000","category":"c"}]}'.encode('utf-8')[:-4])
        # Lone UTF-8 continuation byte inside a string.
        self.assert_rejected(b'{"k":2,"max_suppressed":1,"records":[{"id":"\x80","age":1,"postal":"00000","category":"c"}]}')


class SurrogateSemanticsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _publish(self, source_bytes):
        src = self.tmp / 'in.json'
        out = self.tmp / 'out.json'
        src.write_bytes(source_bytes)
        stdout = io.BytesIO()
        return engine.publish(src, out, stdout), out.read_bytes(), stdout.getvalue()

    def test_surrogate_pair_category_matches_reference(self):
        source = b'{"k":2,"max_suppressed":0,"records":[' \
                 b'{"id":"a","age":30,"postal":"12345","category":"\\ud83d\\ude00"},' \
                 b'{"id":"b","age":31,"postal":"12345","category":"\\ud83d\\ude00"}]}'
        _, file_bytes, stdout_bytes = self._publish(source)
        pretty, compact = canonical(reference(source))
        self.assertEqual(file_bytes, pretty)
        self.assertEqual(stdout_bytes, compact)
        self.assertIn('😀', json.loads(file_bytes)['result']['released_rows'][0]['category'])

    def test_lone_surrogate_in_suppressed_row_is_invisible(self):
        # The lone-surrogate category sits in a class below k at every level
        # that could be selected, so the report never contains it.
        source = b'{"k":2,"max_suppressed":1,"records":[' \
                 b'{"id":"a","age":30,"postal":"12345","category":"x"},' \
                 b'{"id":"b","age":30,"postal":"12345","category":"y"},' \
                 b'{"id":"c","age":31,"postal":"12345","category":"x"},' \
                 b'{"id":"s","age":99,"postal":"99999","category":"\\ud800"}]}'
        _, file_bytes, stdout_bytes = self._publish(source)
        pretty, compact = canonical(reference(source))
        self.assertEqual(file_bytes, pretty)
        self.assertEqual(stdout_bytes, compact)

    def test_lone_surrogate_in_released_row_fails_like_reference(self):
        source = b'{"k":2,"max_suppressed":0,"records":[' \
                 b'{"id":"a","age":30,"postal":"12345","category":"\\ud800"},' \
                 b'{"id":"b","age":30,"postal":"12345","category":"x"}]}'
        # The reference cannot serialize this report to UTF-8 either.
        with self.assertRaises(UnicodeEncodeError):
            canonical(reference(source))
        src = self.tmp / 'in.json'
        out = self.tmp / 'out.json'
        src.write_bytes(source)
        out.write_bytes(b'old')
        with self.assertRaises(ValueError):
            engine.publish(src, out, io.BytesIO())
        self.assertEqual(out.read_bytes(), b'old')


class TempCleanupTests(unittest.TestCase):
    def test_private_temp_data_removed_on_success_and_failure(self):
        with tempfile.TemporaryDirectory() as td:
            os.environ['TMPDIR'] = td
            try:
                src = Path(td) / 'in.json'
                out = Path(td) / 'out.json'
                src.write_text(json.dumps({'k': 2, 'max_suppressed': 1, 'records': [
                    {'id': 'a', 'age': 1, 'postal': '00000', 'category': 'secret'},
                    {'id': 'b', 'age': 2, 'postal': '00000', 'category': 'secret'}]}))
                engine.publish(src, out, io.BytesIO())
                self.assertEqual(os.listdir(td), sorted(['in.json', 'out.json']))
                src.write_text('{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"secret"},{"id":"a","age":2,"postal":"00000","category":"secret"}]}')
                with self.assertRaises(ValueError):
                    engine.publish(src, out, io.BytesIO())
                self.assertEqual(os.listdir(td), sorted(['in.json', 'out.json']))
            finally:
                os.environ.pop('TMPDIR', None)


class CLITests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.runner = self.tmp / 'run_cli.py'
        self.runner.write_text(
            'import sys\n'
            'sys.path.insert(0, %r)\n'
            'from table_privacy.cli import main\n'
            'raise SystemExit(main())\n' % str(ROOT / 'src'))

    def run_cli(self, source, output, chunk=None):
        env = dict(os.environ)
        if chunk is not None:
            env['TABLE_PRIVACY_CHUNK_BYTES'] = str(chunk)
        else:
            env.pop('TABLE_PRIVACY_CHUNK_BYTES', None)
        return subprocess.run(
            [sys.executable, '-I', str(self.runner), '--source', str(source),
             '--output', str(output)],
            capture_output=True, env=env)

    def test_cli_success_and_byte_identity(self):
        source = self.tmp / 'in.json'
        rng = random.Random(7)
        case = random_case(rng, 'cli')
        source.write_bytes(serialize(case, rng).encode('utf-8'))
        out = self.tmp / 'out.json'
        result = self.run_cli(source, out, chunk=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        pretty, compact = canonical(reference(source.read_bytes()))
        self.assertEqual(out.read_bytes(), pretty)
        self.assertEqual(result.stdout, compact)
        # Replay is byte-identical.
        again = self.run_cli(source, out)
        self.assertEqual(again.returncode, 0)
        self.assertEqual(out.read_bytes(), pretty)

    def test_cli_failure_preserves_old_report_and_stdout(self):
        source = self.tmp / 'in.json'
        out = self.tmp / 'out.json'
        out.write_bytes(b'old')
        for bad in (b'{}', b'{"a":1,"a":2}', b'NaN',
                    b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":true,"postal":"00000","category":"c"}]}',
                    b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]} trailing'):
            source.write_bytes(bad)
            result = self.run_cli(source, out, chunk=2)
            self.assertEqual(result.returncode, 2, bad)
            self.assertEqual(result.stdout, b'', 'stdout must not carry a partial report')
            self.assertEqual(out.read_bytes(), b'old')
        # source == output is refused and the source is untouched.
        source.write_bytes(b'{"k":2}')
        before = source.read_bytes()
        result = self.run_cli(source, source)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(source.read_bytes(), before)

    def test_cli_output_symlink_refused(self):
        source = self.tmp / 'in.json'
        source.write_text(json.dumps({'k': 2, 'max_suppressed': 1, 'records': [
            {'id': 'a', 'age': 1, 'postal': '00000', 'category': 'c'}]}))
        link = self.tmp / 'link.json'
        link.symlink_to(self.tmp / 'elsewhere.json')
        result = self.run_cli(source, link)
        self.assertEqual(result.returncode, 2)
        self.assertIn('symlink', result.stderr.decode())


if __name__ == '__main__':
    unittest.main()
