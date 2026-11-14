import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERIES_FIX = ROOT / 'fixtures' / 'series'


def load(name):
    return json.loads((SERIES_FIX / name).read_text())


class SeriesCLITests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ledger = self.tmp / 'ledger.sqlite'
        self.addCleanup(self._tmp.cleanup)

    def _cmd(self, fixture, batch, report, crash_hook=None):
        # -I (isolated mode) ignores PYTHONPATH and skips site initialization,
        # so a small wrapper script injects the source tree itself; no
        # environment-controlled import path is trusted.
        bootstrap = self.tmp / 'bootstrap'
        bootstrap.mkdir(exist_ok=True)
        runner = bootstrap / 'run_series.py'
        runner.write_text(
            'import sys\n'
            'sys.path.insert(0, %r)\n'
            'from table_privacy.series_cli import main\n'
            'raise SystemExit(main())\n' % str(ROOT / 'src'))
        command = [sys.executable, '-I', str(runner),
                   '--source', str(SERIES_FIX / fixture),
                   '--batch-id', batch,
                   '--ledger', str(self.ledger),
                   '--report', str(self.tmp / report)]
        env = dict(os.environ)
        if crash_hook:
            env['TABLE_PRIVACY_CRASH_HOOK'] = crash_hook
        else:
            env.pop('TABLE_PRIVACY_CRASH_HOOK', None)
        return subprocess.run(command, capture_output=True, text=True, env=env)

    def _run_path(self, source, batch, report, env):
        bootstrap = self.tmp / 'bootstrap'
        bootstrap.mkdir(exist_ok=True)
        runner = bootstrap / 'run_series.py'
        runner.write_text(
            'import sys\n'
            'sys.path.insert(0, %r)\n'
            'from table_privacy.series_cli import main\n'
            'raise SystemExit(main())\n' % str(ROOT / 'src'))
        command = [sys.executable, '-I', str(runner),
                   '--source', str(source), '--batch-id', batch,
                   '--ledger', str(self.ledger), '--report', str(report)]
        return subprocess.run(command, capture_output=True, text=True, env=env)

    def _history_counts(self):
        with sqlite3.connect(self.ledger) as conn:
            return conn.execute(
                'SELECT version,id,label FROM history ORDER BY version,id').fetchall()

    def test_two_rounds_end_to_end_and_no_id_leaks(self):
        r = self._cmd('identities_round1.json', 'b1', 'r1.json')
        self.assertEqual(r.returncode, 0, r.stderr)
        report1 = json.loads(r.stdout)
        self.assertEqual((report1['batch_id'], report1['version']), ('b1', 1))
        on_disk = json.loads((self.tmp / 'r1.json').read_text())
        self.assertEqual(on_disk, report1)

        r2 = self._cmd('identities_round2.json', 'b2', 'r2.json')
        self.assertEqual(r2.returncode, 0, r2.stderr)
        report2 = json.loads(r2.stdout)
        self.assertEqual(report2['version'], 2)
        # Public artifacts and stdout never contain ids, mappings or tracks.
        ids = ['"id_alpha"', '"id_beta"', '"id_zulu"', '"id_whis"', '"id_papa"', '"id_qube"']
        for blob in (r.stdout, r2.stdout,
                     (self.tmp / 'r1.json').read_text(),
                     (self.tmp / 'r2.json').read_text()):
            for rid in ids:
                self.assertNotIn(rid, blob)
        rows = self._history_counts()
        by_key = {(v, i): label for v, i, label in rows}
        # z is suppressed in round 1 (empty label) then returns in round 2.
        self.assertEqual(by_key[(1, 'id_zulu')], '')
        self.assertNotEqual(by_key[(2, 'id_zulu')], '')
        # p and q are absent in round 2: uniform empty label, still linked.
        self.assertEqual(by_key[(2, 'id_papa')], '')
        self.assertEqual(by_key[(2, 'id_qube')], '')
        # w is new: no backfilled rows, only its round-2 label.
        self.assertNotIn((1, 'id_whis'), by_key)
        self.assertNotEqual(by_key[(2, 'id_whis')], '')
        self.assertEqual(len(rows), 11)                 # 5 + (4 present + 2 absent)

    def test_kill_after_db_commit_then_recovery_completes_publication(self):
        killed = self._cmd('identities_round1.json', 'b1', 'r1.json',
                           crash_hook='after_db_commit')
        self.assertEqual(killed.returncode, 99, killed.stderr)
        # The ledger append is durable; the public file was never replaced.
        self.assertFalse((self.tmp / 'r1.json').exists())
        with sqlite3.connect(self.ledger) as conn:
            state = conn.execute(
                "SELECT state FROM batches WHERE batch_id='b1'").fetchone()[0]
            history_rows = conn.execute(
                'SELECT COUNT(*) FROM history').fetchone()[0]
        self.assertEqual(state, 'committed')
        self.assertEqual(history_rows, 5)

        # Recovery runs inside the next invocation; the same batch id replays
        # to the identical published version without touching history again.
        retry = self._cmd('identities_round1.json', 'b1', 'r1.json')
        self.assertEqual(retry.returncode, 0, retry.stderr)
        report = json.loads(retry.stdout)
        self.assertEqual(report['version'], 1)
        self.assertEqual((self.tmp / 'r1.json').read_text(), retry.stdout)
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                "SELECT state FROM batches WHERE batch_id='b1'").fetchone()[0],
                'published')
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM history').fetchone()[0], 5)
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM batches').fetchone()[0], 1)

    def test_kill_after_file_replace_then_recovery_is_idempotent(self):
        killed = self._cmd('identities_round1.json', 'b1', 'r1.json',
                           crash_hook='after_file_replace')
        self.assertEqual(killed.returncode, 99, killed.stderr)
        # File already replaced atomically; only the state update is missing.
        self.assertTrue((self.tmp / 'r1.json').exists())
        before = (self.tmp / 'r1.json').read_bytes()
        retry = self._cmd('identities_round1.json', 'b1', 'r1.json')
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertEqual((self.tmp / 'r1.json').read_bytes(), before)
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                "SELECT state FROM batches WHERE batch_id='b1'").fetchone()[0],
                'published')
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM history').fetchone()[0], 5)
        # A genuinely new batch is accepted only after recovery finished.
        nxt = self._cmd('identities_round2.json', 'b2', 'r2.json')
        self.assertEqual(nxt.returncode, 0, nxt.stderr)
        self.assertEqual(json.loads(nxt.stdout)['version'], 2)
        self.assertEqual(len(self._history_counts()), 11)

    def test_replay_same_sha_and_params_is_byte_identical_conflict_rejected(self):
        first = self._cmd('identities_round1.json', 'dup', 'd.json')
        self.assertEqual(first.returncode, 0, first.stderr)
        again = self._cmd('identities_round1.json', 'dup', 'd.json')
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(again.stdout, first.stdout)
        # Same batch id, different source bytes -> conflict.
        other = self.tmp / 'other.json'
        other.write_text((SERIES_FIX / 'identities_round2.json').read_text())
        env = dict(os.environ)
        env.pop('TABLE_PRIVACY_CRASH_HOOK', None)
        conflict = self._run_path(other, 'dup', self.tmp / 'd.json', env)
        self.assertEqual(conflict.returncode, 2)
        self.assertIn('already exists', conflict.stderr)

    def test_infeasible_counterexample_round_is_reported_without_ledger_advance(self):
        self.assertEqual(self._cmd('counterexample_round1.json', 'c1', 'c1.json').returncode, 0)
        self.assertEqual(self._cmd('counterexample_round2.json', 'c2', 'c2.json').returncode, 0)
        third = self._cmd('counterexample_round3.json', 'c3', 'c3.json')
        self.assertEqual(third.returncode, 0, third.stderr)
        report = json.loads(third.stdout)
        self.assertIsNone(report['version'])
        self.assertFalse(report['result']['feasible'])
        self.assertFalse((self.tmp / 'c3.json').exists())
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                'SELECT MAX(version) FROM batches').fetchone()[0], 2)
            # Retrying the infeasible batch stays idempotent and non-advancing.
        retry = self._cmd('counterexample_round3.json', 'c3', 'c3.json')
        self.assertEqual(retry.stdout, third.stdout)
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM batches').fetchone()[0], 2)

    def test_report_path_reuse_and_symlinks_are_refused(self):
        ok = self._cmd('identities_round1.json', 'b1', 'shared.json')
        self.assertEqual(ok.returncode, 0, ok.stderr)
        reused = self._cmd('identities_round2.json', 'b2', 'shared.json')
        self.assertEqual(reused.returncode, 2)
        link = self.tmp / 'fresh-link.json'
        link.symlink_to(self.tmp / 'elsewhere.json')
        env = dict(os.environ)
        env.pop('TABLE_PRIVACY_CRASH_HOOK', None)
        r = self._run_path(SERIES_FIX / 'identities_round1.json', 'b3', link, env)
        self.assertEqual(r.returncode, 2)
        self.assertIn('symlink', r.stderr)


if __name__ == '__main__':
    unittest.main()
