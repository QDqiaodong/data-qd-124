"""End-to-end CLI tests for the linkage audit entry point."""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK_FIX = ROOT / 'fixtures' / 'linkage'


def load(name):
    return json.loads((LINK_FIX / name).read_text())


class LinkageCLITests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.audit = self.tmp / 'audit.sqlite'
        self.addCleanup(self._tmp.cleanup)

    def _runner(self, name):
        bootstrap = self.tmp / 'bootstrap'
        bootstrap.mkdir(exist_ok=True)
        runner = bootstrap / name
        runner.write_text(
            'import sys\n'
            'sys.path.insert(0, %r)\n'
            'from table_privacy.linkage_cli import main\n'
            'raise SystemExit(main())\n' % str(ROOT / 'src'))
        return runner

    def _cmd(self, report, helpers, audit=None):
        runner = self._runner('run_linkage.py')
        command = [sys.executable, '-I', str(runner),
                   '--report', str(report), '--helpers', str(helpers),
                   '--audit-db', str(audit or self.audit)]
        return subprocess.run(command, capture_output=True, text=True)

    def _table_privacy(self, source, output):
        runner = self._runner('run_table_privacy.py')
        runner.write_text(
            'import sys\n'
            'sys.path.insert(0, %r)\n'
            'from table_privacy.cli import main\n'
            'raise SystemExit(main())\n' % str(ROOT / 'src'))
        return subprocess.run(
            [sys.executable, '-I', str(runner), '--source', str(source),
             '--output', str(output)], capture_output=True, text=True)

    def test_real_report_then_forced_audit_persists_everything(self):
        # 1. Generate a genuine schema-1 report with the single-shot CLI.
        source = self.tmp / 'source.json'
        source.write_text(json.dumps({
            'k': 2, 'max_suppressed': 1,
            'records': [
                {'id': 'R1', 'age': 21, 'postal': '12345', 'category': 'green'},
                {'id': 'R2', 'age': 24, 'postal': '12345', 'category': 'green'},
                {'id': 'R3', 'age': 42, 'postal': '98765', 'category': 'blue'},
                {'id': 'R4', 'age': 45, 'postal': '98765', 'category': 'blue'}]},
            indent=2))
        report = self.tmp / 'report.json'
        first = self._table_privacy(source, report)
        self.assertEqual(first.returncode, 0, first.stderr)
        generated = json.loads(report.read_text())
        self.assertEqual(generated['schema_version'], 1)

        helpers = self.tmp / 'helpers.json'
        helpers.write_text(json.dumps([
            {'id': 'H1', 'age_min': 20, 'age_max': 29, 'postal_prefix': '12345'},
            {'id': 'H2', 'age_min': 20, 'age_max': 29, 'postal_prefix': '12345'},
            {'id': 'H3', 'age_min': 40, 'age_max': 50, 'postal_prefix': '98765'},
            {'id': 'H4', 'age_min': 44, 'age_max': 46, 'postal_prefix': '98765'}]))
        run = self._cmd(report, helpers)
        self.assertEqual(run.returncode, 0, run.stderr)
        summary = json.loads(run.stdout)
        self.assertEqual(summary['status'], 'consistent')
        self.assertEqual(summary['identity_count'], 4)
        self.assertEqual(summary['forced_exposure_count'], 4)
        self.assertEqual(summary['unusable_edge_count'], 0)
        self.assertIsNone(summary['hall_witness'])
        # stdout must never carry helper ids.
        for hid in ('H1', 'H2', 'H3', 'H4', 'R1'):
            self.assertNotIn(hid, run.stdout)

        with sqlite3.connect(self.audit) as conn:
            self.assertEqual(conn.execute(
                "SELECT value FROM meta WHERE key='audit_schema_version'").fetchone()[0],
                '1')
            self.assertEqual(conn.execute(
                'SELECT status,identity_count,slot_count,edge_count,maxflow FROM runs'
            ).fetchone(), ('consistent', 4, 2, 4, 4))
            outcomes = conn.execute(
                'SELECT id,forced_exposure,forced_category FROM identity_outcomes '
                'ORDER BY identity_index').fetchall()
            self.assertEqual(outcomes, [
                ('H1', 1, 'green'), ('H2', 1, 'green'),
                ('H3', 1, 'blue'), ('H4', 1, 'blue')])
            possible = conn.execute(
                'SELECT identity_index,category FROM identity_possible_categories '
                'ORDER BY identity_index,category').fetchall()
            self.assertEqual([c for _i, c in possible],
                             ['green', 'green', 'blue', 'blue'])
            edges = conn.execute(
                'SELECT COUNT(*),SUM(matched),SUM(usable) FROM edges').fetchone()
            self.assertEqual(edges, (4, 4, 4))
            self.assertEqual(conn.execute(
                'SELECT SUM(capacity) FROM slots').fetchone()[0], 4)
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM hall_witnesses').fetchone()[0], 0)

    def test_hall_failure_run_stores_witness_ids_and_slots(self):
        run = self._cmd(LINK_FIX / 'report_hall_fail.json',
                        LINK_FIX / 'helpers_hall_fail.json')
        self.assertEqual(run.returncode, 0, run.stderr)
        summary = json.loads(run.stdout)
        self.assertEqual(summary['status'], 'inconsistent')
        self.assertEqual(summary['forced_exposure_count'], 0)
        self.assertEqual(summary['hall_witness'],
                         {'deficit': 2, 'neighbor_capacity': 2,
                          'neighbor_slot_count': 2, 'witness_set_size': 4})
        with sqlite3.connect(self.audit) as conn:
            witness = conn.execute(
                'SELECT witness_set_size,neighbor_slot_count,neighbor_capacity,'
                'deficit FROM hall_witnesses').fetchone()
            self.assertEqual(witness, (4, 2, 2, 2))
            ids = [row[0] for row in conn.execute(
                'SELECT id FROM hall_witness_identities ORDER BY id')]
            self.assertEqual(ids, ['X1', 'X2', 'X3', 'X4'])
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM identity_outcomes').fetchone()[0], 0)
            self.assertTrue(conn.execute(
                'SELECT COUNT(*) FROM edges WHERE usable IS NOT NULL').fetchone()[0] == 0)
            self.assertEqual(conn.execute(
                'SELECT SUM(capacity) FROM hall_witness_slots').fetchone()[0], 2)

    def test_invalid_input_exits_2_and_preserves_old_database(self):
        good = self._cmd(LINK_FIX / 'report_forced.json',
                         LINK_FIX / 'helpers_forced.json')
        self.assertEqual(good.returncode, 0, good.stderr)
        before = self.audit.read_bytes()

        # Malformed helper JSON.
        bad_helpers = self.tmp / 'bad.json'
        bad_helpers.write_text('[{not json')
        bad = self._cmd(LINK_FIX / 'report_forced.json', bad_helpers)
        self.assertEqual(bad.returncode, 2)
        self.assertIn('Expecting', bad.stderr)
        self.assertEqual(self.audit.read_bytes(), before)

        # Semantically invalid helper (age out of range).
        bad_helpers.write_text(json.dumps(
            [{'id': 'Z', 'age_min': 130, 'age_max': 130, 'postal_prefix': ''}]))
        bad = self._cmd(LINK_FIX / 'report_forced.json', bad_helpers)
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(self.audit.read_bytes(), before)

        # Count mismatch: one helper too few.
        short = self.tmp / 'short.json'
        short.write_text(json.dumps(load('helpers_forced.json')[:-1]))
        bad = self._cmd(LINK_FIX / 'report_forced.json', short)
        self.assertEqual(bad.returncode, 2)
        self.assertIn('must equal', bad.stderr)
        self.assertEqual(self.audit.read_bytes(), before)

        # Infeasible report is rejected.
        infeasible = {'schema_version': 1, 'source_sha256': 'a' * 64,
                      'result': {'candidates': [], 'equivalence_classes': [],
                                 'feasible': False, 'input_rows': 1, 'k': 2,
                                 'released_rows': []}}
        bad_report = self.tmp / 'infeasible.json'
        bad_report.write_text(json.dumps(infeasible))
        bad = self._cmd(bad_report, LINK_FIX / 'helpers_forced.json')
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(self.audit.read_bytes(), before)

        with sqlite3.connect(self.audit) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM runs').fetchone()[0], 1)

    def test_invalid_input_never_creates_a_database(self):
        missing = self.tmp / 'never.sqlite'
        short = self.tmp / 'short.json'
        short.write_text(json.dumps(load('helpers_forced.json')[:-1]))
        bad = self._cmd(LINK_FIX / 'report_forced.json', short, audit=missing)
        self.assertEqual(bad.returncode, 2)
        self.assertFalse(missing.exists())

    def test_runs_append_and_repeated_inputs_are_separate_runs(self):
        first = self._cmd(LINK_FIX / 'report_forced.json',
                          LINK_FIX / 'helpers_forced.json')
        second = self._cmd(LINK_FIX / 'report_forced.json',
                           LINK_FIX / 'helpers_forced.json')
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(json.loads(first.stdout)['run_id'],
                            json.loads(second.stdout)['run_id'])
        with sqlite3.connect(self.audit) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM runs').fetchone()[0], 2)
            digests = conn.execute(
                'SELECT DISTINCT report_sha256,helpers_sha256 FROM runs').fetchall()
            self.assertEqual(len(digests), 1)

    def test_path_conflicts_and_symlinks_are_refused(self):
        same = self._cmd(LINK_FIX / 'report_forced.json',
                         LINK_FIX / 'report_forced.json')
        self.assertEqual(same.returncode, 2)
        link = self.tmp / 'link.sqlite'
        link.symlink_to(self.tmp / 'target.sqlite')
        blocked = self._cmd(LINK_FIX / 'report_forced.json',
                            LINK_FIX / 'helpers_forced.json', audit=link)
        self.assertEqual(blocked.returncode, 2)
        self.assertIn('symlink', blocked.stderr)

    def test_unrelated_sqlite_database_is_rejected_and_untouched(self):
        foreign = self.tmp / 'foreign.sqlite'
        with sqlite3.connect(foreign) as conn:
            conn.execute('CREATE TABLE unrelated(x INTEGER)')
            conn.execute("INSERT INTO unrelated VALUES (1)")
        before = foreign.read_bytes()
        blocked = self._cmd(LINK_FIX / 'report_forced.json',
                            LINK_FIX / 'helpers_forced.json', audit=foreign)
        self.assertEqual(blocked.returncode, 2)
        self.assertIn('not a linkage audit store', blocked.stderr)
        self.assertEqual(foreign.read_bytes(), before)
        with sqlite3.connect(foreign) as conn:
            self.assertEqual(conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall(),
                [('unrelated',)])

    def test_inputs_are_subject_to_the_8_mib_json_limit(self):
        oversized = self.tmp / 'oversized.json'
        oversized.write_text('[' + ','.join(
            '{"id":"%05d","age_min":0,"age_max":0,"postal_prefix":""}' % i
            for i in range(200000)) + ']')
        self.assertGreater(oversized.stat().st_size, 8 * 1024 * 1024)
        blocked = self._cmd(LINK_FIX / 'report_forced.json', oversized)
        self.assertEqual(blocked.returncode, 2)
        self.assertIn('8 MB', blocked.stderr)
        self.assertFalse(self.audit.exists())

    def test_scale_2000_identities_20000_edges_runs_without_enumeration(self):
        n = 2000
        per_bucket = n // 10
        rows, classes = [], []
        for b in range(10):
            age_label = '%d-%d' % (b * 10, min(120, b * 10 + 9))
            postal_label = '%03d**' % (b + 1)
            for _ in range(per_bucket):
                rows.append({'age': age_label, 'postal': postal_label,
                             'category': 'cat'})
            classes.append({'age': age_label, 'postal': postal_label,
                            'size': per_bucket, 'distinct_categories': 1,
                            'category_counts': {'cat': per_bucket}})
        report = self.tmp / 'big_report.json'
        report.write_text(json.dumps({
            'schema_version': 1, 'source_sha256': 'c' * 64,
            'result': {'candidates': [], 'equivalence_classes': classes,
                       'feasible': True, 'input_rows': n, 'k': 2,
                       'privacy_scope': 'x', 'released_count': n,
                       'released_rows': rows,
                       'selected': {'age_level': 1, 'postal_level': 1,
                                    'ordinal_generalization_cost': '1/2'},
                       'suppressed_rows': 0}}))
        helpers = self.tmp / 'big_helpers.json'
        helpers.write_text(json.dumps([
            {'id': 'H%04d' % i, 'age_min': 0, 'age_max': 120,
             'postal_prefix': ''} for i in range(n)]))
        start = time.monotonic()
        run = self._cmd(report, helpers)
        elapsed = time.monotonic() - start
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertLess(elapsed, 10.0)
        summary = json.loads(run.stdout)
        self.assertEqual(summary['edge_count'], 20000)
        self.assertEqual(summary['identity_count'], 2000)
        self.assertEqual(summary['maxflow'], 2000)
        with sqlite3.connect(self.audit) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM edges').fetchone()[0], 20000)
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM identity_possible_categories').fetchone()[0], 2000)


if __name__ == '__main__':
    unittest.main()
