#!/usr/bin/env python3
"""Helpers for scripts/measure_linux.sh (Linux measurement of the streaming
single-shot engine).  Run with python3 -I; the table_privacy source tree is
passed explicitly with --src and nothing is imported from the environment.

Subcommands:
  small       differential battery: randomized small tables vs model.analyze
              (field order shuffling, records before parameters, cross-chunk
              duplicate keys/ids, trailing bad records, encodings, escapes)
  medium      ~60k-row run with full byte parity against the reference
  gen-big     generate the >256 MiB, 1,000,000-row high-cardinality source
  check-big   validate the big-run report/stdout without loading them
  gen-overflow  generate a 1,000,001-row source (row-limit rejection)
  diskfail    disk-write failure battery (exit 2, old report kept, no stdout)
  rlimit-run  exec the CLI under RLIMIT_FSIZE with SIGXFSZ ignored
"""
import argparse
import codecs
import hashlib
import io
import json
import os
import random
import subprocess
import sys

MIB = 1 << 20
ADDRESS_LIMIT = 256 * MIB


def fail(message):
    print('FAIL: ' + message)
    raise SystemExit(1)


def note(message):
    print('.... ' + message)


def canonical(report):
    pretty = (json.dumps(report, sort_keys=True, ensure_ascii=False,
                         allow_nan=False, indent=2) + '\n').encode('utf-8')
    compact = (json.dumps(report, sort_keys=True, ensure_ascii=False,
                          allow_nan=False) + '\n').encode('utf-8')
    return pretty, compact


def load_reference(src_dir):
    sys.path.insert(0, src_dir)
    from table_privacy.common import read
    from table_privacy.model import analyze

    def reference(source_bytes):
        import tempfile
        fd, name = tempfile.mkstemp()
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(source_bytes)
            data, digest = read(name)
        finally:
            os.unlink(name)
        return {'schema_version': 1, 'source_sha256': digest,
                'result': analyze(data)}

    return reference


def cli_runner(workdir, src_dir):
    runner = os.path.join(workdir, 'run_cli.py')
    with open(runner, 'w') as stream:
        stream.write('import sys\n'
                     'sys.path.insert(0, %r)\n'
                     'from table_privacy.cli import main\n'
                     'raise SystemExit(main())\n' % src_dir)
    return runner


def run_cli(runner, source, output, chunk=None, extra_env=None):
    env = dict(os.environ)
    if chunk is not None:
        env['TABLE_PRIVACY_CHUNK_BYTES'] = str(chunk)
    else:
        env.pop('TABLE_PRIVACY_CHUNK_BYTES', None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run([sys.executable, '-I', runner, '--source', source,
                           '--output', output],
                          capture_output=True, env=env)


def fields_equal(got, want, path, errors):
    if isinstance(want, dict):
        if not isinstance(got, dict) or set(got) != set(want):
            errors.append(path)
            return
        for key in sorted(want):
            fields_equal(got[key], want[key], '%s.%s' % (path, key), errors)
    elif isinstance(want, list):
        if not isinstance(got, list) or len(got) != len(want):
            errors.append(path)
            return
        for i, item in enumerate(want):
            fields_equal(got[i], item, '%s[%d]' % (path, i), errors)
    elif got != want:
        errors.append('%s (%r != %r)' % (path, got, want))


# ---------------------------------------------------------------------------
# Randomized source generation (shared with the small battery).

def escape_random(text, rng):
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
            out.append('\\u%04x' % code)
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


# ---------------------------------------------------------------------------

def cmd_small(args):
    reference = load_reference(args.src)
    runner = cli_runner(args.work, args.src)
    rng = random.Random(args.seed)
    src = os.path.join(args.work, 'case.json')
    out = os.path.join(args.work, 'report.json')
    checked = rejected = 0

    def expect_ok(source_bytes, chunk, label):
        nonlocal checked
        want = reference(source_bytes)
        want_pretty, want_compact = canonical(want)
        with open(src, 'wb') as stream:
            stream.write(source_bytes)
        if os.path.exists(out):
            os.unlink(out)
        result = run_cli(runner, src, out, chunk=chunk)
        if result.returncode != 0:
            fail('%s: exit %d stderr=%s' % (label, result.returncode,
                                            result.stderr.decode()[:300]))
        with open(out, 'rb') as stream:
            file_bytes = stream.read()
        if file_bytes != want_pretty:
            fail('%s: report file bytes differ from reference' % label)
        if result.stdout != want_compact:
            fail('%s: stdout bytes differ from reference' % label)
        errors = []
        fields_equal(json.loads(file_bytes), want, 'report', errors)
        if errors:
            fail('%s: field mismatch at %s' % (label, errors[0]))
        checked += 1

    def expect_rejected(source_bytes, chunk, label):
        nonlocal rejected
        with open(src, 'wb') as stream:
            stream.write(source_bytes)
        with open(out, 'wb') as stream:
            stream.write(b'old')
        result = run_cli(runner, src, out, chunk=chunk)
        if result.returncode != 2:
            fail('%s: expected exit 2, got %d stdout=%s'
                 % (label, result.returncode, result.stdout[:200]))
        if result.stdout != b'':
            fail('%s: stdout carries a partial report' % label)
        with open(out, 'rb') as stream:
            if stream.read() != b'old':
                fail('%s: previous report was not preserved' % label)
        rejected += 1

    # 1) Randomized valid tables: shuffled field order, records before
    #    parameters, escapes, encodings, tiny (cross-chunk) read sizes.
    for i in range(args.cases):
        case = random_case(rng, 'case%d' % i)
        source = encode_random(serialize(case, rng), rng)
        chunk = rng.choice([None, 1, 2, 3, 5, 7, 13, 64, 4096])
        expect_ok(source, chunk, 'random case %d (chunk=%s)' % (i, chunk))
    note('%d randomized small tables match model.analyze byte for byte' % args.cases)

    # 2) Cross-chunk duplicate keys and duplicate ids (tiny read sizes).
    dup_id = (b'{"records":[{"id":"dup","age":30,"postal":"12345","category":"x"},'
              b'{"id":"other","age":31,"postal":"12345","category":"y"},'
              b'{"id":"dup","age":32,"postal":"12345","category":"z"}],'
              b'"k":2,"max_suppressed":1}')
    dup_key_top = b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}],"k":3}'
    dup_key_rec = b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c","id":"b"}]}'
    for chunk in (1, 2, 3, 5, 7, 64, None):
        expect_rejected(dup_id, chunk, 'cross-chunk duplicate id (chunk=%s)' % chunk)
        expect_rejected(dup_key_top, chunk, 'cross-chunk duplicate top key (chunk=%s)' % chunk)
        expect_rejected(dup_key_rec, chunk, 'cross-chunk duplicate record key (chunk=%s)' % chunk)
    note('cross-chunk duplicate keys/ids rejected at every chunk size')

    # 3) Trailing bad records and trailing garbage.
    trailing_bad = b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"},{"id":"b","age":2,"postal":"bad!!","category":"c"}]}'
    trailing_trunc = b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"},{"id":"b","age":2,"postal":"00000","categ'
    trailing_garbage = b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]} garbage'
    trailing_brace = b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]}{'
    for chunk in (1, 4, None):
        expect_rejected(trailing_bad, chunk, 'trailing bad record (chunk=%s)' % chunk)
        expect_rejected(trailing_trunc, chunk, 'truncated trailing record (chunk=%s)' % chunk)
        expect_rejected(trailing_garbage, chunk, 'trailing garbage (chunk=%s)' % chunk)
        expect_rejected(trailing_brace, chunk, 'trailing brace (chunk=%s)' % chunk)
    note('trailing bad records and trailing garbage rejected, old report kept')

    # 4) Remaining rejection semantics of the original contract.
    good = b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":30,"postal":"12345","category":"x"},{"id":"b","age":31,"postal":"12345","category":"y"}]}'
    battery = {
        'empty object': b'{}',
        'not an object': b'[]',
        'empty input': b'',
        'nonfinite document': b'NaN',
        'unknown top field': b'{"k":2,"max_suppressed":1,"records":[],"x":1}',
        'missing field': b'{"k":2,"max_suppressed":1}',
        'empty records': b'{"k":2,"max_suppressed":1,"records":[]}',
        'records not array': b'{"k":2,"max_suppressed":1,"records":{}}',
        'k below range': b'{"k":1,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]}',
        'k above range': b'{"k":10001,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]}',
        'k float': b'{"k":2.0,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]}',
        'k boolean': b'{"k":true,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]}',
        'k nonfinite': b'{"k":NaN,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]}',
        'budget above range': b'{"k":2,"max_suppressed":1000001,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]}',
        'budget negative': b'{"k":2,"max_suppressed":-1,"records":[{"id":"a","age":1,"postal":"00000","category":"c"}]}',
        'boolean age': b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":true,"postal":"00000","category":"c"}]}',
        'float age': b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":2.5,"postal":"00000","category":"c"}]}',
        'age above range': b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":121,"postal":"00000","category":"c"}]}',
        'nonfinite age': b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":-Infinity,"postal":"00000","category":"c"}]}',
        'short postal': b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"1234","category":"c"}]}',
        'fullwidth postal': '{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"１２３４５","category":"c"}]}'.encode('utf-8'),
        'blank id': b'{"k":2,"max_suppressed":1,"records":[{"id":" ","age":1,"postal":"00000","category":"c"}]}',
        'overlong id': ('{"k":2,"max_suppressed":1,"records":[{"id":"' + 'a' * 129 + '","age":1,"postal":"00000","category":"c"}]}').encode(),
        'control char in id': b'{"k":2,"max_suppressed":1,"records":[{"id":"a\\u0001b","age":1,"postal":"00000","category":"c"}]}',
        'unknown record field': b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c","x":1}]}',
        'missing record field': b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000"}]}',
        'bad escape': b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c\\xb"}]}',
        'raw control in string': b'{"k":2,"max_suppressed":1,"records":[{"id":"a","age":1,"postal":"00000","category":"c\x01d"}]}',
        'bad utf-8': b'{"k":2,"max_suppressed":1,"records":[{"id":"\x80","age":1,"postal":"00000","category":"c"}]}',
    }
    for label, source in battery.items():
        expect_rejected(source, 3, label)
    note('%d rejection cases keep exit 2, old report and empty stdout' % len(battery))

    # 5) Boundary values accepted at the new limits.
    ok = json.dumps({'k': 10000, 'max_suppressed': 1000000, 'records': [
        {'id': 'a', 'age': 120, 'postal': '00123', 'category': 'c'},
        {'id': 'b', 'age': 120, 'postal': '00123', 'category': 'c'}]}).encode()
    expect_ok(ok, None, 'k=10000/max_suppressed=1000000 accepted')
    print('SMALL BATTERY PASS: %d valid cases byte-identical, %d rejections verified'
          % (checked, rejected))


def cmd_medium(args):
    reference = load_reference(args.src)
    runner = cli_runner(args.work, args.src)
    rng = random.Random(args.seed)
    src = os.path.join(args.work, 'medium.json')
    out = os.path.join(args.work, 'medium.report.json')
    note('generating %d-row medium source' % args.rows)
    pool = CATEGORIES + ['cat-%d' % i for i in range(2000)]
    with open(src, 'w', encoding='utf-8') as stream:
        stream.write('{"records":[')
        for i in range(args.rows):
            if i:
                stream.write(',')
            stream.write(json.dumps({
                'id': 'id-%d' % i,
                'age': rng.randint(0, 120),
                'postal': '%05d' % rng.randint(0, 99999),
                'category': rng.choice(pool)}, ensure_ascii=False))
        stream.write('],"k":%d,"max_suppressed":%d}'
                     % (rng.randint(2, 9), rng.randint(0, 200)))
    with open(src, 'rb') as stream:
        source = stream.read()
    want = reference(source)
    want_pretty, want_compact = canonical(want)
    result = run_cli(runner, src, out)
    if result.returncode != 0:
        fail('medium: exit %d stderr=%s' % (result.returncode, result.stderr.decode()[:300]))
    with open(out, 'rb') as stream:
        file_bytes = stream.read()
    if file_bytes != want_pretty:
        fail('medium: report file bytes differ from reference')
    if result.stdout != want_compact:
        fail('medium: stdout bytes differ from reference')
    errors = []
    fields_equal(json.loads(file_bytes), want, 'report', errors)
    if errors:
        fail('medium: field mismatch at %s' % errors[0])
    print('MEDIUM PASS: %d rows, report %.1f MiB, byte-identical to model.analyze'
          % (args.rows, len(file_bytes) / MIB))


def cmd_gen_big(args):
    path = args.path
    note('generating %d-row high-cardinality source at %s' % (args.rows, path))
    written = 0
    with open(path, 'wb') as stream:
        def emit(text):
            nonlocal written
            data = text.encode('ascii')
            stream.write(data)
            written += len(data)
        emit('{"records":[')
        for i in range(args.rows):
            prefix = ',' if i else ''
            rid = ('id' + hashlib.sha512(b'id-%d' % i).hexdigest())[:128]
            cat = ('c' + hashlib.sha512(b'cat-%d' % i).hexdigest())[:128]
            age = 30 + i % 10
            postal = '123%02d' % (i % 10)
            emit('%s{"id":"%s","age":%d,"postal":"%s","category":"%s"}'
                 % (prefix, rid, age, postal, cat))
        emit('],"k":2,"max_suppressed":0}')
    print('BIG SOURCE: %s (%d bytes, %.1f MiB)' % (path, written, written / MIB))
    if written <= ADDRESS_LIMIT:
        fail('big source must exceed the 256 MiB address-space limit')


def cmd_check_big(args):
    source_size = os.path.getsize(args.source)
    report_size = os.path.getsize(args.report)
    stdout_size = os.path.getsize(args.stdout)
    note('source %.1f MiB, report %.1f MiB, stdout %.1f MiB'
         % (source_size / MIB, report_size / MIB, stdout_size / MIB))
    if source_size <= ADDRESS_LIMIT:
        fail('source must exceed 256 MiB')
    if report_size <= ADDRESS_LIMIT:
        fail('report must exceed 256 MiB')
    if stdout_size <= ADDRESS_LIMIT:
        fail('stdout must exceed 256 MiB')

    digest = hashlib.sha256()
    with open(args.source, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    expected = [
        b'"source_sha256": "' + digest.hexdigest().encode() + b'"',
        b'"input_rows": 1000000',
        b'"k": 2',
        b'"released_count": 1000000',
        b'"suppressed_rows": 0',
        b'"selected": {"age_level": 0, "ordinal_generalization_cost": "0", "postal_level": 0}',
        b'"candidates": [{"age_level": 0, "feasible": true, "ordinal_generalization_cost": "0", "postal_level": 0, "suppressed": 0}',
    ]

    def scan(path, needles, prefix, suffix):
        found = {n: False for n in needles}
        overlap = max((len(n) for n in needles), default=0) + 1
        head = b''
        tail = b''
        with open(path, 'rb') as stream:
            prev = b''
            first = True
            for chunk in iter(lambda: stream.read(1 << 22), b''):
                if first:
                    head = chunk[:200]
                    first = False
                tail = (tail + chunk)[-200:]
                window = prev + chunk
                for needle in needles:
                    if not found[needle] and needle in window:
                        found[needle] = True
                prev = window[-overlap:]
        missing = [n for n, ok in found.items() if not ok]
        if missing:
            fail('%s: missing expected content %s' % (path, missing[0][:80]))
        if not head.startswith(prefix):
            fail('%s: bad prefix %r' % (path, head[:40]))
        if not tail.endswith(suffix):
            fail('%s: bad suffix %r' % (path, tail[-40:]))

    scan(args.stdout, expected, b'{"result": {"candidates": [', b'}\n')
    note('stdout carries the full compact report with the source SHA-256')
    scan(args.report, [b'"source_sha256": "' + digest.hexdigest().encode() + b'"',
                       b'"input_rows": 1000000'],
         b'{\n  "result": {\n    "candidates": [', b'}\n')
    note('report file carries the full indented report')
    print('BIG CHECK PASS: report and stdout complete, SHA-256 covers the source')


def cmd_gen_overflow(args):
    note('generating %d-row overflow source at %s' % (args.rows, args.path))
    with open(args.path, 'w') as stream:
        stream.write('{"k":2,"max_suppressed":0,"records":[')
        for i in range(args.rows):
            if i:
                stream.write(',')
            stream.write('{"id":"i%d","age":30,"postal":"12345","category":"c"}' % i)
        stream.write(']}')


def cmd_diskfail(args):
    runner = cli_runner(args.work, args.src)
    src = os.path.join(args.work, 'in.json')
    out = os.path.join(args.work, 'out.json')
    case = {'k': 2, 'max_suppressed': 1, 'records': [
        {'id': 'a', 'age': 30, 'postal': '12345', 'category': 'x'},
        {'id': 'b', 'age': 31, 'postal': '12345', 'category': 'y'}]}
    with open(src, 'w') as stream:
        stream.write(json.dumps(case))
    checked = 0

    def expect_fail(label, source, output, extra_env=None):
        nonlocal checked
        result = run_cli(runner, source, output, extra_env=extra_env)
        if result.returncode != 2:
            fail('%s: expected exit 2, got %d stdout=%s'
                 % (label, result.returncode, result.stdout[:200]))
        if result.stdout != b'':
            fail('%s: stdout carries a partial report' % label)
        checked += 1

    # Output parent is a regular file (deterministic ENOTDIR, root-safe).
    blocker = os.path.join(args.work, 'not-a-dir')
    with open(blocker, 'w') as stream:
        stream.write('x')
    expect_fail('output parent not a directory', src, os.path.join(blocker, 'r.json'))

    # Output path is a symlink.
    link = os.path.join(args.work, 'link.json')
    os.symlink(os.path.join(args.work, 'elsewhere.json'), link)
    expect_fail('output symlink', src, link)

    # Output path is an existing directory.
    expect_fail('output is a directory', src, args.work)

    # Source and output identical: source bytes must survive.
    with open(src, 'rb') as stream:
        before = stream.read()
    expect_fail('source == output', src, src)
    with open(src, 'rb') as stream:
        if stream.read() != before:
            fail('source == output: source was modified')
    note('path-based write failures: exit 2, empty stdout, inputs preserved')

    # Unwritable output directory (permission bits do not constrain root).
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        note('SKIP unwritable-directory case: running as root')
    else:
        ro = os.path.join(args.work, 'ro')
        os.mkdir(ro, 0o500)
        expect_fail('output directory not writable', src, os.path.join(ro, 'r.json'))
        os.chmod(ro, 0o700)

    # Write failures under RLIMIT_FSIZE (SIGXFSZ ignored so writes raise
    # EFBIG): a tiny limit fails while the SQLite intermediate layer is
    # written; a limit between the workfile size and the report size fails
    # mid-report.  Both must give exit 2, a preserved old report, empty
    # stdout and no leftover private temp data.
    rows = []
    for i in range(4000):
        rows.append({'id': 'i%d' % i, 'age': 30 + i % 10,
                     'postal': '123%02d' % (i % 10),
                     'category': ('c%040d' % i) + 'x' * 86})
    big = os.path.join(args.work, 'rlimit.json')
    with open(big, 'w') as stream:
        stream.write(json.dumps({'k': 2, 'max_suppressed': 0, 'records': rows}))
    out2 = os.path.join(args.work, 'rlimit.report.json')
    ok = run_cli(runner, big, out2)
    if ok.returncode != 0:
        fail('rlimit setup run failed: %s' % ok.stderr.decode()[:300])
    report_size = os.path.getsize(out2)
    source_size = os.path.getsize(big)
    tmpdir = os.path.join(args.work, 'rlimit-tmp')
    os.mkdir(tmpdir)

    def rlimit_case(label, limit):
        nonlocal checked
        with open(out2, 'wb') as stream:
            stream.write(b'old')
        env = dict(os.environ)
        env['TMPDIR'] = tmpdir
        proc = subprocess.run(
            [sys.executable, '-I', __file__, 'rlimit-run', '--bytes', str(limit),
             '--src', args.src, '--', '--source', big, '--output', out2],
            capture_output=True, env=env)
        if proc.returncode != 2:
            fail('%s: expected exit 2, got %d stderr=%s'
                 % (label, proc.returncode, proc.stderr.decode()[:300]))
        if proc.stdout != b'':
            fail('%s: stdout carries a partial report' % label)
        with open(out2, 'rb') as stream:
            if stream.read() != b'old':
                fail('%s: previous report was not preserved' % label)
        leftovers = os.listdir(tmpdir)
        if leftovers:
            fail('%s: private temporary data left behind: %s' % (label, leftovers))
        note('%s (RLIMIT_FSIZE=%d): exit 2, old report kept, '
             'stdout empty, temp cleaned' % (label, limit))
        checked += 1

    rlimit_case('write failure in the disk intermediate layer', 64 * 1024)
    rlimit_case('write failure mid-report',
                max(report_size // 2, source_size * 3 // 2))
    print('DISK-FAILURE BATTERY PASS: %d cases' % checked)


def cmd_rlimit_run(args):
    import resource
    import signal
    resource.setrlimit(resource.RLIMIT_FSIZE, (args.bytes, args.bytes))
    if hasattr(signal, 'SIGXFSZ'):
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    sys.path.insert(0, args.src)
    from table_privacy.cli import main
    sys.argv = ['table-privacy'] + args.cli_args
    raise SystemExit(main())


def cmd_rusage_run(args):
    """Exec a command and record the child's exit code, peak RSS and time."""
    import time
    pid = os.fork()
    if pid == 0:
        os.execvp(args.cmd[0], args.cmd)
    start = time.time()
    _, status, usage = os.wait4(pid, 0)
    elapsed = time.time() - start
    code = os.waitstatus_to_exitcode(status)
    with open(args.out, 'w') as stream:
        stream.write('%d %d %.1f\n' % (code, usage.ru_maxrss, elapsed))
    raise SystemExit(code)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)

    def add(name, func):
        p = sub.add_parser(name)
        p.set_defaults(func=func)
        return p

    p = add('small', cmd_small)
    p.add_argument('--src', required=True)
    p.add_argument('--work', required=True)
    p.add_argument('--cases', type=int, default=60)
    p.add_argument('--seed', type=int, default=124124)

    p = add('medium', cmd_medium)
    p.add_argument('--src', required=True)
    p.add_argument('--work', required=True)
    p.add_argument('--rows', type=int, default=60000)
    p.add_argument('--seed', type=int, default=99)

    p = add('gen-big', cmd_gen_big)
    p.add_argument('--path', required=True)
    p.add_argument('--rows', type=int, default=1000000)

    p = add('check-big', cmd_check_big)
    p.add_argument('--source', required=True)
    p.add_argument('--report', required=True)
    p.add_argument('--stdout', required=True)

    p = add('gen-overflow', cmd_gen_overflow)
    p.add_argument('--path', required=True)
    p.add_argument('--rows', type=int, default=1000001)

    p = add('diskfail', cmd_diskfail)
    p.add_argument('--src', required=True)
    p.add_argument('--work', required=True)

    p = add('rlimit-run', cmd_rlimit_run)
    p.add_argument('--bytes', type=int, required=True)
    p.add_argument('--src', required=True)
    p.add_argument('cli_args', nargs=argparse.REMAINDER)

    p = add('rusage-run', cmd_rusage_run)
    p.add_argument('--out', required=True)
    p.add_argument('cmd', nargs=argparse.REMAINDER)

    args = parser.parse_args()
    for remainder in ('cli_args', 'cmd'):
        value = getattr(args, remainder, None)
        if value and value[:1] == ['--']:
            setattr(args, remainder, value[1:])
    args.func(args)


if __name__ == '__main__':
    main()
