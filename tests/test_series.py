import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from table_privacy.model import analyze
from table_privacy.series import (EMPTY, SCHEMA_VERSION, SeriesError, Store,
                                  analyze_series, publish, recover)

ROOT = Path(__file__).resolve().parents[1]
SERIES_FIX = ROOT / 'fixtures' / 'series'


def load(name):
    return json.loads((SERIES_FIX / name).read_text())


def history_from(store):
    return store.history()


class SeriesAlgorithmTests(unittest.TestCase):
    def test_first_round_matches_single_shot_contract(self):
        data = load('counterexample_round1.json')
        result, decisions = analyze_series(data, {})
        single = analyze(data)
        self.assertTrue(result['feasible'])
        self.assertEqual({k: v for k, v in result.items() if k != 'privacy_scope'},
                         {k: v for k, v in single.items() if k != 'privacy_scope'})
        # Every released identity got its current bucket label.
        self.assertEqual(sorted(decisions), ['A', 'B', 'C', 'D', 'E', 'F'])

    def test_counterexample_each_round_alone_feasible_but_joint_round3_infeasible(self):
        r1, r2, r3 = (load('counterexample_round1.json'),
                      load('counterexample_round2.json'),
                      load('counterexample_round3.json'))
        # Each round on its own satisfies the original single-shot contract.
        for data in (r1, r2, r3):
            self.assertTrue(analyze(data)['feasible'])

        res1, d1 = analyze_series(r1, {})
        h1 = {rid: (d1.get(rid, EMPTY),) for rid in (r['id'] for r in r1['records'])}
        res2, d2 = analyze_series(r2, h1)
        self.assertTrue(res2['feasible'])
        h2 = {rid: (h1[rid][0], d2.get(rid, EMPTY))
              for rid in (r['id'] for r in r1['records'])}
        res3, d3 = analyze_series(r3, h2)
        # Round 3 is feasible alone but every joint group is below k across
        # all nine candidates once the full history sequence is considered.
        self.assertFalse(res3['feasible'])
        self.assertEqual(d3, {})
        self.assertTrue(all(not c['feasible'] for c in res3['candidates']))
        self.assertEqual(res3['released_rows'], [])

    def test_new_absent_and_suppressed_identities_share_empty_label(self):
        r1, r2 = load('identities_round1.json'), load('identities_round2.json')
        res1, d1 = analyze_series(r1, {})
        self.assertEqual(res1['suppressed_rows'], 1)
        self.assertNotIn('id_zulu', d1)                  # suppressed -> empty label
        h1 = {rid: (d1.get(rid, EMPTY),) for rid in
              (r['id'] for r in r1['records'])}
        self.assertEqual(h1['id_zulu'], (EMPTY,))

        res2, d2 = analyze_series(r2, h1)
        self.assertTrue(res2['feasible'])
        # z was suppressed (empty history label) and w is brand new (backfilled
        # empty history): their empty pasts are indistinguishable, so they form
        # one joint group of size k in the current bucket and are both kept.
        self.assertIn('id_zulu', d2)
        self.assertIn('id_whis', d2)
        self.assertEqual(d2['id_zulu'], d2['id_whis'])
        self.assertEqual(d2['id_alpha'], d2['id_beta'])
        # p and q are absent this round; the caller records the uniform empty
        # label for them, and they never appear among release decisions.
        self.assertEqual(d2.get('id_papa', EMPTY), EMPTY)
        self.assertEqual(d2.get('id_qube', EMPTY), EMPTY)
        # No public artifact may carry an id.
        blob = json.dumps(res2)
        for rid in ('id_alpha', 'id_beta', 'id_zulu', 'id_whis', 'id_papa', 'id_qube'):
            self.assertNotIn(rid, blob)

    def test_absent_history_is_backfilled_with_empty_labels(self):
        data = load('identities_round2.json')
        # Existing identities have one past label; w has none. After
        # backfill, w's empty past must be indistinguishable from the
        # suppressed identity z's empty label, so they share a joint group.
        history = {'id_alpha': ('20-29|111**',), 'id_beta': ('20-29|111**',),
                   'id_zulu': (EMPTY,)}
        result, decisions = analyze_series(data, history)
        self.assertTrue(result['feasible'])
        self.assertEqual(decisions['id_whis'], decisions['id_zulu'])


class LedgerProtocolTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ledger = self.tmp / 'ledger.sqlite'
        self.addCleanup(self._tmp.cleanup)

    def _report(self, name):
        return self.tmp / name

    def _publish_fixture(self, store, fixture, batch, report_name):
        data = load(fixture)
        return publish(store, batch, data,
                       'sha-' + fixture, self._report(report_name))

    def test_successful_round_appends_each_history_label_once(self):
        with Store(self.ledger) as store:
            status, payload = self._publish_fixture(
                store, 'identities_round1.json', 'b1', 'r1.json')
            self.assertEqual(status, 'published')
            report = json.loads(payload)
            self.assertEqual(report['batch_id'], 'b1')
            self.assertEqual(report['version'], 1)
            self.assertEqual(report['schema_version'], SCHEMA_VERSION)
            rows = store.conn.execute(
                'SELECT id,label FROM history WHERE version=1 ORDER BY id').fetchall()
            self.assertEqual(len(rows), 5)
            labels = dict(rows)
            self.assertNotEqual(labels['id_alpha'], EMPTY)
            self.assertEqual(labels['id_zulu'], EMPTY)            # suppressed
            self.assertEqual(store.get_batch('b1')['state'], 'published')

            status2, payload2 = self._publish_fixture(
                store, 'identities_round2.json', 'b2', 'r2.json')
            self.assertEqual(status2, 'published')
            report2 = json.loads(payload2)
            self.assertEqual(report2['version'], 2)
            # Append-only: exactly one row per id per version, nothing rewritten.
            counts = store.conn.execute(
                'SELECT version,COUNT(*) FROM history GROUP BY version').fetchall()
            self.assertEqual(counts, [(1, 5), (2, 6)])
            # Absent p and q get the uniform empty label in round 2; new w
            # appears for the first time and the suppressed-then-returned z
            # is linked across rounds.
            for absent in ('id_papa', 'id_qube'):
                label = store.conn.execute(
                    'SELECT label FROM history WHERE version=2 AND id=?',
                    (absent,)).fetchone()[0]
                self.assertEqual(label, EMPTY)
            w_versions = store.conn.execute(
                'SELECT version FROM history WHERE id=? ORDER BY version', ('id_whis',)).fetchall()
            self.assertEqual(w_versions, [(2,)])           # past backfilled, not inserted
            z_versions = store.conn.execute(
                'SELECT version,label FROM history WHERE id=? ORDER BY version',
                ('id_zulu',)).fetchall()
            self.assertEqual([v for v, _ in z_versions], [1, 2])
            self.assertEqual(z_versions[0][1], EMPTY)      # suppressed round 1
            self.assertNotEqual(z_versions[1][1], EMPTY)   # returned round 2
            full = store.history()
            self.assertEqual(len(full['id_alpha']), 2)
            self.assertEqual(full['id_papa'], ('40-49|222**', EMPTY))

    def test_infeasible_round_does_not_advance_ledger(self):
        r1, r2, r3 = (load('counterexample_round1.json'),
                      load('counterexample_round2.json'),
                      load('counterexample_round3.json'))
        with Store(self.ledger) as store:
            publish(store, 'c1', r1, 'h1', self._report('c1.json'))
            publish(store, 'c2', r2, 'h2', self._report('c2.json'))
            versions_before = store.conn.execute(
                'SELECT COUNT(*) FROM batches').fetchone()[0]
            history_before = store.conn.execute(
                'SELECT COUNT(*) FROM history').fetchone()[0]
            status, payload = publish(
                store, 'c3-bad', r3, 'h3', self._report('c3.json'))
            self.assertEqual(status, 'infeasible')
            self.assertFalse((self.tmp / 'c3.json').exists())
            self.assertEqual(store.conn.execute(
                'SELECT COUNT(*) FROM batches').fetchone()[0], versions_before)
            self.assertEqual(store.conn.execute(
                'SELECT COUNT(*) FROM history').fetchone()[0], history_before)
            self.assertIsNone(store.get_batch('c3-bad'))
            report = json.loads(payload)
            self.assertIsNone(report['version'])
            self.assertFalse(report['result']['feasible'])
            # A feasible later batch still gets the next sequential version.
            status2, payload2 = publish(
                store, 'c4', r1, 'h4', self._report('c4.json'))
            self.assertEqual(status2, 'published')
            self.assertEqual(json.loads(payload2)['version'], 3)

    def test_tampered_public_file_is_restored_from_ledger_on_replay(self):
        with Store(self.ledger) as store:
            status, payload = self._publish_fixture(
                store, 'identities_round1.json', 'b1', 'r1.json')
            on_disk = self.tmp / 'r1.json'
            self.assertEqual(on_disk.read_bytes(), payload)
            on_disk.write_bytes(b'tampered')
            # Replaying the identical batch reconciles the file with the ledger.
            status2, payload2 = self._publish_fixture(
                store, 'identities_round1.json', 'b1', 'r1.json')
            self.assertEqual(status2, 'published')
            self.assertEqual(payload2, payload)
            self.assertEqual(on_disk.read_bytes(), payload)
            # No duplicate history or batch rows were created.
            self.assertEqual(store.conn.execute(
                'SELECT COUNT(*) FROM batches').fetchone()[0], 1)
            self.assertEqual(store.conn.execute(
                'SELECT COUNT(*) FROM history').fetchone()[0], 5)

    def test_same_batch_replay_returns_same_version_and_bytes(self):
        with Store(self.ledger) as store:
            status1, p1 = self._publish_fixture(
                store, 'identities_round1.json', 'dup', 'rep.json')
        with Store(self.ledger) as store:
            status2, p2 = self._publish_fixture(
                store, 'identities_round1.json', 'dup', 'rep.json')
        self.assertEqual((status1, status2), ('published', 'published'))
        self.assertEqual(p1, p2)
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM batches').fetchone()[0], 1)
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM history').fetchone()[0], 5)

    def test_batch_id_conflict_on_different_sha_or_params_or_path_is_rejected(self):
        with Store(self.ledger) as store:
            self._publish_fixture(store, 'identities_round1.json', 'b', 'a.json')
            with self.assertRaises(SeriesError):
                publish(store, 'b',
                        load('identities_round1.json'), 'different-sha',
                        self._report('a.json'))
            with self.assertRaises(SeriesError):
                publish(store, 'b',
                        load('identities_round1.json'), 'sha-identities_round1.json',
                        self._report('other.json'))
        # Ledger unchanged after rejected attempts.
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM batches').fetchone()[0], 1)

    def test_recovery_after_committed_state_republishes_and_marks(self):
        with Store(self.ledger) as store:
            self._publish_fixture(store, 'identities_round1.json', 'b1', 'v1.json')
            # Simulate a crash after DB commit but before file replacement.
            store.conn.execute("UPDATE batches SET state='committed' WHERE batch_id='b1'")
            store.conn.commit()
            (self.tmp / 'v1.json').unlink()
            latest = recover(store)
            self.assertEqual(latest['state'], 'published')
            self.assertTrue((self.tmp / 'v1.json').exists())
            # Idempotent: a second recovery reconciles without duplication.
            recover(store)
            counts = store.conn.execute(
                'SELECT version,COUNT(*) FROM history GROUP BY version').fetchall()
            self.assertEqual(counts, [(1, 5)])

    def test_recovery_failure_blocks_next_batch(self):
        with Store(self.ledger) as store:
            self._publish_fixture(store, 'identities_round1.json', 'b1', 'v1.json')
            store.conn.execute("UPDATE batches SET state='committed' WHERE batch_id='b1'")
            store.conn.commit()
        # Point the pending report under a regular file: creating it fails
        # deterministically (ENOTDIR), independent of the running uid.
        blocker = self.tmp / 'not-a-dir'
        blocker.write_text('id_alpha')
        with Store(self.ledger) as store:
            store.conn.execute(
                "UPDATE batches SET report_path=? WHERE batch_id='b1'",
                (str(blocker / 'v1.json'),))
            store.conn.commit()
            with self.assertRaises(OSError):
                recover(store)
            with self.assertRaises((SeriesError, OSError)):
                self._publish_fixture(
                    store, 'identities_round1.json', 'b2', 'v2.json')
            # No new batch or history row snuck in while recovery was blocked.
            self.assertEqual(store.conn.execute(
                'SELECT COUNT(*) FROM batches').fetchone()[0], 1)
            self.assertEqual(store.conn.execute(
                'SELECT COUNT(*) FROM history').fetchone()[0], 5)

    @unittest.skipIf(hasattr(os, 'geteuid') and os.geteuid() == 0,
                     'permission bits do not constrain root')
    def test_unwritable_report_directory_blocks_recovery(self):
        with Store(self.ledger) as store:
            self._publish_fixture(store, 'identities_round1.json', 'b1', 'v1.json')
            store.conn.execute("UPDATE batches SET state='committed' WHERE batch_id='b1'")
            store.conn.commit()
        blocked_dir = self.tmp / 'ro'
        blocked_dir.mkdir()
        (self.tmp / 'v1.json').unlink()
        with Store(self.ledger) as store:
            store.conn.execute(
                "UPDATE batches SET report_path=? WHERE batch_id='b1'",
                (str(blocked_dir / 'v1.json'),))
            store.conn.commit()
            blocked_dir.chmod(0o500)
            with self.assertRaises(OSError):
                recover(store)
        blocked_dir.chmod(0o700)

    def test_published_versions_are_append_only_and_never_rolled_back(self):
        with Store(self.ledger) as store:
            self._publish_fixture(store, 'identities_round1.json', 'b1', 'v1.json')
            self._publish_fixture(store, 'identities_round2.json', 'b2', 'v2.json')
            versions = [r[0] for r in store.conn.execute(
                'SELECT version FROM batches ORDER BY version')]
            self.assertEqual(versions, [1, 2])
            with self.assertRaises(sqlite3.IntegrityError):
                store.conn.execute(
                    'INSERT INTO batches(batch_id,version,source_sha256,k,'
                    "max_suppressed,report_path,state,report_json,report_sha256) "
                    "VALUES('id_alpha',1,'s',2,1,'id_papa','committed','{}','d')")


if __name__ == '__main__':
    unittest.main()
