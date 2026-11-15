"""End-to-end CLI, barrier and crash-recovery acceptance tests for erasure.

Every concurrency scenario uses real subprocesses and file-based barriers
(``TABLE_PRIVACY_GATE_ROOT``); no timing is guessed with sleeps.  Crash points
use the same ``TABLE_PRIVACY_CRASH_HOOK`` hard-exit mechanism as the serial
publication tests, and the matrix runs each scenario under both the default
rollback journal and WAL.
"""
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
SERIES_FIX = ROOT / 'fixtures' / 'series'
SRC = ROOT / 'src'


def load_series(name):
    return json.loads((SERIES_FIX / name).read_text())


def wildcard_report(n):
    rows = [{'age': '20-29', 'postal': '111**', 'category': 'blue'}] * n
    return {'schema_version': 1,
        'source_sha256': 'a' * 64, 'result': {
            'candidates': [],
            'equivalence_classes': [
                {'age': '20-29', 'postal': '111**', 'size': n,
                 'distinct_categories': 1, 'category_counts': {'blue': n}}],
            'feasible': True, 'input_rows': n, 'k': 2, 'privacy_scope': 'x',
            'released_count': n, 'released_rows': rows,
            'selected': {'age_level': 1, 'postal_level': 1,
                         'ordinal_generalization_cost': '1/2'},
            'suppressed_rows': 0}}


def wildcard_helpers(ids):
    return [{'id': rid, 'age_min': 0, 'age_max': 120, 'postal_prefix': ''}
            for rid in ids]


def _wait_until(predicate, timeout=30.0):
    """Poll a deterministic file/database condition; not used to order races."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError('condition was not reached before the deadline')


class EraseCLIHarness(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ledger = self.tmp / 'ledger.sqlite'
        self.audit = self.tmp / 'audit.sqlite'
        self.gates = self.tmp / 'gates'
        self.gates.mkdir()
        self.bootstrap = self.tmp / 'bootstrap'
        self.bootstrap.mkdir()
        self.addCleanup(self._tmp.cleanup)

    # ------------------------------------------------------------------ #
    # Subprocess runners
    # ------------------------------------------------------------------ #

    def _runner(self, name, module):
        runner = self.bootstrap / name
        runner.write_text(
            'import sys\n'
            'sys.path.insert(0, %r)\n'
            'from %s import main\n'
            'raise SystemExit(main())\n' % (str(SRC), module))
        return runner

    def _env(self, crash_hook=None, gate_root=None):
        env = dict(os.environ)
        env.pop('TABLE_PRIVACY_CRASH_HOOK', None)
        env.pop('TABLE_PRIVACY_GATE_ROOT', None)
        if crash_hook:
            env['TABLE_PRIVACY_CRASH_HOOK'] = crash_hook
        if gate_root:
            env['TABLE_PRIVACY_GATE_ROOT'] = str(gate_root)
        return env

    def series_cmd(self, fixture, batch, report, audit=None, journal_mode=None):
        cmd = [sys.executable, '-I',
               str(self._runner('run_series.py', 'table_privacy.series_cli')),
               '--source', str(fixture), '--batch-id', batch,
               '--ledger', str(self.ledger), '--report', str(report)]
        if audit is not None:
            cmd += ['--audit-db', str(audit)]
        if journal_mode:
            cmd += ['--journal-mode', journal_mode]
        return cmd

    def linkage_cmd(self, report, helpers, ledger=None, journal_mode=None):
        cmd = [sys.executable, '-I',
               str(self._runner('run_linkage.py', 'table_privacy.linkage_cli')),
               '--report', str(report), '--helpers', str(helpers),
               '--audit-db', str(self.audit)]
        if ledger is not None:
            cmd += ['--ledger', str(ledger)]
        if journal_mode:
            cmd += ['--journal-mode', journal_mode]
        return cmd

    def erase_cmd(self, ids_file, request_id, journal_mode=None,
                  resume=False, status=False):
        cmd = [sys.executable, '-I',
               str(self._runner('run_erase.py', 'table_privacy.erase_cli')),
               '--ledger', str(self.ledger),
               '--audit-db', str(self.audit),
               '--request-id', request_id]
        if resume:
            cmd.append('--resume')
        elif status:
            cmd.append('--status')
        else:
            cmd += ['--ids', str(ids_file)]
        if journal_mode:
            cmd += ['--journal-mode', journal_mode]
        return cmd

    def run_proc(self, cmd, **kwargs):
        return subprocess.run(cmd, capture_output=True, text=True,
                              env=self._env(**kwargs))

    # ------------------------------------------------------------------ #
    # Fixture construction
    # ------------------------------------------------------------------ #

    def publish_series(self, journal_mode=None):
        r1 = self.tmp / 'r1.json'
        r2 = self.tmp / 'r2.json'
        first = self.run_proc(self.series_cmd(
            SERIES_FIX / 'identities_round1.json', 'b1', r1,
            journal_mode=journal_mode))
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.run_proc(self.series_cmd(
            SERIES_FIX / 'identities_round2.json', 'b2', r2,
            journal_mode=journal_mode))
        self.assertEqual(second.returncode, 0, second.stderr)
        return r1, r2

    def write_audit_inputs(self, name, ids):
        report = self.tmp / ('%s_report.json' % name)
        helpers = self.tmp / ('%s_helpers.json' % name)
        report.write_text(json.dumps(wildcard_report(len(ids))))
        helpers.write_text(json.dumps(wildcard_helpers(ids)))
        return report, helpers

    def run_linkage(self, name, ids, journal_mode=None, bound=False):
        report, helpers = self.write_audit_inputs(name, ids)
        proc = self.run_proc(self.linkage_cmd(
            report, helpers,
            ledger=self.ledger if bound else None,
            journal_mode=journal_mode))
        return proc

    def bind_and_erase(self, ids, request_id='req-1', journal_mode=None):
        ids_file = self.tmp / 'ids.json'
        ids_file.write_text(json.dumps(list(ids)))
        proc = self.run_proc(self.erase_cmd(ids_file, request_id,
                                       journal_mode=journal_mode))
        return proc

    def history_ids(self):
        with sqlite3.connect(self.ledger) as conn:
            return {row[0] for row in conn.execute(
                'SELECT DISTINCT id FROM history')}

    def audit_run_ids(self):
        with sqlite3.connect(self.audit) as conn:
            return [row[0] for row in conn.execute(
                'SELECT run_id FROM runs ORDER BY run_id')]

    def _reset(self):
        """Fresh, empty database pair so matrix subtests never share state."""
        self._tmp.cleanup()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.ledger = self.tmp / 'ledger.sqlite'
        self.audit = self.tmp / 'audit.sqlite'
        self.gates = self.tmp / 'gates'
        self.gates.mkdir()
        self.bootstrap = self.tmp / 'bootstrap'
        self.bootstrap.mkdir()


class EraseCLICommandTests(EraseCLIHarness):
    def test_erase_cli_full_flow_and_id_free_outputs(self):
        self.publish_series()
        proc_link = self.run_linkage('rel', ['id_alpha', 'id_beta'])
        self.assertEqual(proc_link.returncode, 0, proc_link.stderr)
        proc = self.bind_and_erase(['id_alpha', 'id_beta'])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        view = json.loads(proc.stdout)
        self.assertEqual(view['state'], 'done')
        self.assertEqual(view['id_count'], 2)
        for token in ('id_alpha', 'id_beta'):
            self.assertNotIn(token, proc.stdout)
            self.assertNotIn(token, proc.stderr)
        self.assertNotIn('id_alpha', self.history_ids())
        self.assertEqual(self.audit_run_ids(), [])
        # --status and --resume work without the id file.
        status = self.run_proc(self.erase_cmd(None, 'req-1', status=True))
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout)['state'], 'done')
        resume = self.run_proc(self.erase_cmd(None, 'req-1', resume=True))
        self.assertEqual(resume.returncode, 0, resume.stderr)
        self.assertEqual(json.loads(resume.stdout)['state'], 'done')

    def test_changed_id_set_same_request_is_rejected_and_state_unchanged(self):
        self.publish_series()
        first = self.bind_and_erase(['id_alpha'], request_id='req-x')
        self.assertEqual(first.returncode, 0, first.stderr)
        conflict = self.bind_and_erase(['id_beta'], request_id='req-x')
        self.assertEqual(conflict.returncode, 2)
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                'SELECT id_fingerprint FROM erase_tasks WHERE request_id=?',
                ('req-x',)).fetchone()[0],
                json.loads(first.stdout)['id_set_fingerprint'])

    def test_bound_store_rejects_omitted_or_swapped_partner_on_old_cli(self):
        self.publish_series()
        self.assertEqual(self.bind_and_erase(['id_alpha']).returncode, 0)
        # Old CLI shape (no --audit-db) against the now-bound ledger.
        report = self.tmp / 'late.json'
        omitted = self.run_proc(self.series_cmd(
            SERIES_FIX / 'identities_round2.json', 'b-late', report))
        self.assertEqual(omitted.returncode, 2)
        self.assertIn('bound', omitted.stderr)
        # Swap in a different audit database.
        foreign_audit = self.tmp / 'foreign.sqlite'
        swapped = self.run_proc(self.series_cmd(
            SERIES_FIX / 'identities_round2.json', 'b-swap', report,
            audit=foreign_audit))
        self.assertEqual(swapped.returncode, 2)
        self.assertIn('different audit database', swapped.stderr)
        # And the linkage side without its ledger partner.
        rep, helpers = self.write_audit_inputs('x', ['id_whis', 'id_zulu'])
        no_ledger = self.run_proc(self.linkage_cmd(rep, helpers))
        self.assertEqual(no_ledger.returncode, 2)
        self.assertIn('bound', no_ledger.stderr)

    def test_series_acceptance_targets_gone_others_intact_and_replays_exit_2(self):
        r1_path, r2_path = self.publish_series()
        import hashlib
        sha_before = {p: hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in (r1_path, r2_path)}
        self.assertEqual(self.bind_and_erase(
            ['id_alpha', 'id_zulu']).returncode, 0)
        remaining = self.history_ids()
        self.assertNotIn('id_alpha', remaining)
        self.assertNotIn('id_zulu', remaining)
        for rid in ('id_beta', 'id_papa', 'id_qube', 'id_whis'):
            self.assertIn(rid, remaining)
        # Public report bytes are identical before/after.
        for path, digest in sha_before.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        # Old batch replay carrying a target -> exit 2, state preserved.
        replay = self.run_proc(self.series_cmd(
            SERIES_FIX / 'identities_round1.json', 'b1',
            self.tmp / 'replay.json', audit=self.audit))
        self.assertEqual(replay.returncode, 2)
        # New batch with a target -> exit 2.
        fresh_path = self.tmp / 'fresh-source.json'
        fresh_path.write_text((SERIES_FIX / 'identities_round1.json').read_text())
        new_batch = self.run_proc(self.series_cmd(
            fresh_path, 'b-new', self.tmp / 'new.json', audit=self.audit))
        self.assertEqual(new_batch.returncode, 2)
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual([row[0] for row in conn.execute(
                'SELECT version FROM batches ORDER BY version')], [1, 2])
        # Wipe the remaining population, then publish fresh identities: the
        # next version stays continuous.
        wipe = self.bind_and_erase(sorted(remaining), request_id='req-2')
        self.assertEqual(wipe.returncode, 0, wipe.stderr)
        fresh_source = self.tmp / 'fresh-ids.json'
        fresh_source.write_text(json.dumps({
            'k': 2, 'max_suppressed': 1, 'records': [
                {'id': 'fresh1', 'age': 21, 'postal': '11111',
                 'category': 'blue'},
                {'id': 'fresh2', 'age': 22, 'postal': '11122',
                 'category': 'blue'}]}))
        published = self.run_proc(self.series_cmd(
            fresh_source, 'b3', self.tmp / 'r3.json', audit=self.audit))
        self.assertEqual(published.returncode, 0, published.stderr)
        self.assertEqual(json.loads(published.stdout)['version'], 3)

    def test_linkage_acceptance_legacy_related_unrelated_mix(self):
        # A pre-binding run without an identity index (legacy), a fully
        # indexed related run and a fully indexed unrelated run.
        legacy = self.run_linkage('legacy', ['id_whis', 'id_zulu'])
        self.assertEqual(legacy.returncode, 0, legacy.stderr)
        with sqlite3.connect(self.audit) as conn:
            conn.execute('DELETE FROM run_identity_index')
            conn.commit()
        related = self.run_linkage('related', ['id_alpha', 'id_beta'])
        self.assertEqual(related.returncode, 0)
        unrelated = self.run_linkage('unrelated', ['id_papa', 'id_qube'])
        self.assertEqual(unrelated.returncode, 0)
        unrelated_id = json.loads(unrelated.stdout)['run_id']
        proc = self.bind_and_erase(['id_alpha'])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.audit_run_ids(), [unrelated_id])
        with sqlite3.connect(self.audit) as conn:
            # The surviving run keeps its full index and derived records.
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM run_identity_index').fetchone()[0], 2)
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM identity_outcomes').fetchone()[0], 2)


    def test_half_binding_crash_is_recovered_and_foreign_partner_rejected(self):
        self.publish_series()
        ids_file = self.tmp / 'ids.json'
        ids_file.write_text(json.dumps(['id_alpha']))
        # Crash after the audit side committed its binding row.
        killed = subprocess.run(
            self.erase_cmd(ids_file, 'req-bind'),
            capture_output=True, text=True,
            env=self._env(crash_hook='after_binding_audit'))
        self.assertEqual(killed.returncode, 99)
        with sqlite3.connect(self.audit) as conn:
            self.assertIsNotNone(conn.execute(
                "SELECT value FROM meta WHERE key='privacy_binding_token'").fetchone())
        with sqlite3.connect(self.ledger) as conn:
            self.assertIsNone(conn.execute(
                "SELECT value FROM meta WHERE key='privacy_binding_token'").fetchone())
        # A retry completes the binding and the erase.
        retry = self.run_proc(self.erase_cmd(ids_file, 'req-bind'))
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertEqual(json.loads(retry.stdout)['state'], 'done')
        # The legacy (partner-less) entry points now fail closed on both sides.
        rep, helpers = self.write_audit_inputs('x', ['id_papa'])
        no_ledger = self.run_proc(self.linkage_cmd(rep, helpers))
        self.assertEqual(no_ledger.returncode, 2)

    def test_argument_mistakes_exit_2_without_touching_stores(self):
        self.publish_series()
        ids_file = self.tmp / 'ids.json'
        ids_file.write_text(json.dumps(['id_alpha']))
        # --resume and --status together.
        bad = self.run_proc(
            [sys.executable, '-I',
             str(self._runner('run_erase.py', 'table_privacy.erase_cli')),
             '--ledger', str(self.ledger), '--audit-db', str(self.audit),
             '--request-id', 'r', '--resume', '--status'])
        self.assertEqual(bad.returncode, 2)
        # --resume with an --ids file is rejected.
        bad = self.run_proc(
            [sys.executable, '-I',
             str(self._runner('run_erase.py', 'table_privacy.erase_cli')),
             '--ledger', str(self.ledger), '--audit-db', str(self.audit),
             '--request-id', 'r', '--resume', '--ids', str(ids_file)])
        self.assertEqual(bad.returncode, 2)
        # No mode and no ids file.
        bad = self.run_proc(
            [sys.executable, '-I',
             str(self._runner('run_erase.py', 'table_privacy.erase_cli')),
             '--ledger', str(self.ledger), '--audit-db', str(self.audit),
             '--request-id', 'r'])
        self.assertEqual(bad.returncode, 2)
        # Empty id set.
        empty = self.tmp / 'empty.json'
        empty.write_text('[]')
        bad = self.run_proc(self.erase_cmd(empty, 'r'))
        self.assertEqual(bad.returncode, 2)
        # Nothing was created in either store.
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM erase_tasks').fetchone()[0], 0)


class EraseJournalMatrixTests(EraseCLIHarness):
    """The barrier/kill matrix runs identically under both journal modes."""

    def _arm_gate(self, name):
        gate = self.gates / name
        gate.mkdir(parents=True, exist_ok=True)
        for sentinel in ('ready', 'wait', 'released'):
            p = gate / sentinel
            if p.exists():
                p.unlink()
        (gate / 'ready').touch()
        (gate / 'wait').touch()

    def _release_gate(self, name):
        (self.gates / name / 'released').touch()

    def _wait_at_gate(self, name):
        _wait_until(lambda: (self.gates / name / 'wait').exists())

    def _barrier_series_writer(self, journal_mode, batch='b-race',
                               fixture='identities_round2.json'):
        self._arm_gate('series_pre_commit')
        proc = subprocess.Popen(
            self.series_cmd(SERIES_FIX / fixture, batch,
                            self.tmp / ('%s.json' % batch),
                            audit=self.audit, journal_mode=journal_mode),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self._env(gate_root=self.gates), text=True)
        self._wait_at_gate('series_pre_commit')
        return proc

    def _barrier_linkage_writer(self, journal_mode):
        report, helpers = self.write_audit_inputs(
            'race', ['id_alpha', 'id_beta'])
        self._arm_gate('linkage_pre_commit')
        proc = subprocess.Popen(
            self.linkage_cmd(report, helpers, ledger=self.ledger,
                             journal_mode=journal_mode),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self._env(gate_root=self.gates), text=True)
        self._wait_at_gate('linkage_pre_commit')
        return proc

    def test_series_writer_loses_race_to_eraser(self):
        for journal_mode in (None, 'wal'):
            with self.subTest(journal_mode=journal_mode or 'delete'):
                self._run_series_race(journal_mode)

    def _run_series_race(self, journal_mode):
        self._reset()
        self.publish_series(journal_mode=journal_mode)
        # Bind first so the writer opens with its partner.
        self.assertEqual(self.bind_and_erase(
            ['id_whis'], request_id='req-bind',
            journal_mode=journal_mode).returncode, 0)
        writer = self._barrier_series_writer(journal_mode)
        # While the writer is paused post-computation, erase another target
        # present in the racing batch.
        eraser = self.bind_and_erase(
            ['id_alpha'], request_id='req-race',
            journal_mode=journal_mode)
        self.assertEqual(eraser.returncode, 0, eraser.stderr)
        self._release_gate('series_pre_commit')
        out, err = writer.communicate(timeout=30)
        self.assertEqual(writer.returncode, 2, (out, err))
        self.assertIn('tombstoned', err)
        # No resurrection: the target stays absent, the batch never landed.
        self.assertNotIn('id_alpha', self.history_ids())
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual([row[0] for row in conn.execute(
                'SELECT version FROM batches ORDER BY version')], [1, 2])
        # Unrelated writers succeed again after the request completed.
        fresh = self.tmp / 'fresh.json'
        fresh.write_text(json.dumps({
            'k': 2, 'max_suppressed': 1, 'records': [
                {'id': 'ok1', 'age': 21, 'postal': '11111',
                 'category': 'blue'},
                {'id': 'ok2', 'age': 22, 'postal': '11122',
                 'category': 'blue'}]}))
        recovered = self.run_proc(self.series_cmd(
            fresh, 'b-ok', self.tmp / 'ok.json', audit=self.audit,
            journal_mode=journal_mode))
        self.assertEqual(recovered.returncode, 0, recovered.stderr)

    def test_linkage_writer_loses_race_to_eraser(self):
        for journal_mode in (None, 'wal'):
            with self.subTest(journal_mode=journal_mode or 'delete'):
                self._run_linkage_race(journal_mode)

    def _run_linkage_race(self, journal_mode):
        self._reset()
        self.publish_series(journal_mode=journal_mode)
        self.assertEqual(self.bind_and_erase(
            ['id_whis'], request_id='req-bind',
            journal_mode=journal_mode).returncode, 0)
        writer = self._barrier_linkage_writer(journal_mode)
        eraser = self.bind_and_erase(
            ['id_alpha'], request_id='req-race',
            journal_mode=journal_mode)
        self.assertEqual(eraser.returncode, 0, eraser.stderr)
        self._release_gate('linkage_pre_commit')
        out, err = writer.communicate(timeout=30)
        self.assertEqual(writer.returncode, 2, (out, err))
        self.assertIn('tombstoned', err)
        # The racing run never persisted.
        with sqlite3.connect(self.audit) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM runs').fetchone()[0], 0)
        # An unrelated run goes through normally once done is registered.
        rep, helpers = self.write_audit_inputs(
            'fine', ['id_papa', 'id_qube'])
        fine = self.run_proc(self.linkage_cmd(
            rep, helpers, ledger=self.ledger, journal_mode=journal_mode))
        self.assertEqual(fine.returncode, 0, fine.stderr)

    def test_series_erase_kill_between_and_before_done_then_resume(self):
        for journal_mode in (None, 'wal'):
            with self.subTest(journal_mode=journal_mode or 'delete'):
                self._run_series_kill_matrix(journal_mode)

    def _run_series_kill_matrix(self, journal_mode):
        # One fresh pair per kill point: between the two database commits,
        # after the audit commit but before the ledger progress record, and
        # after progress but before the done registration.
        hooks = ('erase_after_series_phase', 'erase_after_audit_purge',
                 'erase_after_audit_progress')
        for hook in hooks:
            with self.subTest(hook=hook):
                self._reset()
                self.publish_series(journal_mode=journal_mode)
                request_id = 'req-kill-' + hook.split('_')[-1]
                ids_file = self.tmp / 'ids.json'
                ids_file.write_text(json.dumps(['id_alpha']))
                killed = subprocess.run(
                    self.erase_cmd(ids_file, request_id,
                                   journal_mode=journal_mode),
                    capture_output=True, text=True,
                    env=self._env(crash_hook=hook))
                self.assertEqual(killed.returncode, 99, killed.stderr)
                with sqlite3.connect(self.ledger) as conn:
                    self.assertEqual(conn.execute(
                        'SELECT state FROM erase_tasks WHERE request_id=?',
                        (request_id,)).fetchone()[0], 'pending')
                    # Pending blocks new batches in both stores.
                    blocked = self.run_proc(self.series_cmd(
                        SERIES_FIX / 'identities_round1.json', 'b-blocked',
                        self.tmp / 'blocked.json', audit=self.audit,
                        journal_mode=journal_mode))
                    self.assertEqual(blocked.returncode, 2)
                resumed = self.run_proc(self.erase_cmd(
                    None, request_id, resume=True,
                    journal_mode=journal_mode))
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                self.assertEqual(json.loads(resumed.stdout)['state'], 'done')
                # Repeated resume never deletes a later unrelated run.
                rep, helpers = self.write_audit_inputs(
                    'post', ['id_papa', 'id_qube'])
                post = self.run_proc(self.linkage_cmd(
                    rep, helpers, ledger=self.ledger,
                    journal_mode=journal_mode))
                self.assertEqual(post.returncode, 0, post.stderr)
                post_id = json.loads(post.stdout)['run_id']
                again = self.run_proc(self.erase_cmd(
                    None, request_id, resume=True,
                    journal_mode=journal_mode))
                self.assertEqual(again.returncode, 0, again.stderr)
                self.assertEqual(self.audit_run_ids(), [post_id])

    def test_linkage_erase_kill_before_audit_commit_then_resume(self):
        for journal_mode in (None, 'wal'):
            with self.subTest(journal_mode=journal_mode or 'delete'):
                self._run_linkage_kill(journal_mode)

    def _run_linkage_kill(self, journal_mode):
        self._reset()
        self.publish_series(journal_mode=journal_mode)
        self.run_linkage('rel', ['id_alpha', 'id_beta'],
                         journal_mode=journal_mode)
        ids_file = self.tmp / 'ids.json'
        ids_file.write_text(json.dumps(['id_alpha']))
        killed = subprocess.run(
            self.erase_cmd(ids_file, 'req-kill',
                           journal_mode=journal_mode),
            capture_output=True, text=True,
            env=self._env(crash_hook='erase_before_audit_purge'))
        self.assertEqual(killed.returncode, 99, killed.stderr)
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                "SELECT state FROM erase_tasks WHERE request_id='req-kill'"
            ).fetchone()[0], 'pending')
        with sqlite3.connect(self.audit) as conn:
            self.assertIsNone(conn.execute(
                "SELECT request_id FROM erase_progress "
                "WHERE request_id='req-kill'").fetchone())
        # A new run is blocked while pending.
        rep, helpers = self.write_audit_inputs('blocked', ['id_papa'])
        blocked = self.run_proc(self.linkage_cmd(
            rep, helpers, ledger=self.ledger, journal_mode=journal_mode))
        self.assertEqual(blocked.returncode, 2)
        resumed = self.run_proc(self.erase_cmd(
            None, 'req-kill', resume=True, journal_mode=journal_mode))
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(json.loads(resumed.stdout)['state'], 'done')
        self.assertEqual(self.audit_run_ids(), [])
        # Unrelated writes work again.
        rep, helpers = self.write_audit_inputs('fine', ['id_papa', 'id_qube'])
        fine = self.run_proc(self.linkage_cmd(
            rep, helpers, ledger=self.ledger, journal_mode=journal_mode))
        self.assertEqual(fine.returncode, 0, fine.stderr)


if __name__ == '__main__':
    unittest.main()
