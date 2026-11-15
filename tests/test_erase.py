"""Library-level acceptance tests for cross-database subject erasure.

Covers series history/tombstone semantics, linkage digest indexing,
conservative legacy purges, binding fail-closed behavior, idempotency and the
resume state machine.  Subprocess, barrier and journal-mode scenarios live in
``test_erase_cli.py``.
"""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from table_privacy.erase import (id_set_fingerprint, read_id_set, request_status,
                                 resume_erase, run_erase)
from table_privacy.linkage import AuditStore, LinkageError, analyze_linkage
from table_privacy.series import SeriesError, Store, id_digest, publish, recover

ROOT = Path(__file__).resolve().parents[1]
SERIES_FIX = ROOT / 'fixtures' / 'series'
LINK_FIX = ROOT / 'fixtures' / 'linkage'


def load_series(name):
    return json.loads((SERIES_FIX / name).read_text())


def wildcard_report(n, source_sha='a' * 64):
    """Feasible schema-1 report with one bucket, n identical released rows."""
    rows = [{'age': '20-29', 'postal': '111**', 'category': 'blue'}] * n
    return {'schema_version': 1, 'source_sha256': source_sha, 'result': {
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


def make_run(audit, ids, report_sha='r', helpers_sha='h', store_kwargs=None):
    report = wildcard_report(len(ids))
    result = analyze_linkage(report, wildcard_helpers(ids),
                             report_sha, helpers_sha)
    with AuditStore(audit, **(store_kwargs or {})) as store:
        return store.persist(result), result


class EraseTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ledger = self.tmp / 'ledger.sqlite'
        self.audit = self.tmp / 'audit.sqlite'
        self.addCleanup(self._tmp.cleanup)

    def publish_rounds(self):
        r1 = load_series('identities_round1.json')
        r2 = load_series('identities_round2.json')
        reports = {}
        with Store(self.ledger) as store:
            _st, p1 = publish(store, 'b1', r1, 'sha-r1', self.tmp / 'r1.json')
            _st, p2 = publish(store, 'b2', r2, 'sha-r2', self.tmp / 'r2.json')
            reports['r1'] = p1
            reports['r2'] = p2
        return r1, r2, reports

    def history_ids(self):
        with sqlite3.connect(self.ledger) as conn:
            return {row[0] for row in conn.execute(
                'SELECT DISTINCT id FROM history')}

    def history_rows_for(self, rid):
        with sqlite3.connect(self.ledger) as conn:
            return conn.execute(
                'SELECT version,label FROM history WHERE id=? ORDER BY version',
                (rid,)).fetchall()

    def erase(self, request_id, ids):
        return run_erase(self.ledger, self.audit, request_id, set(ids))

    def bound_series_store(self):
        return Store(self.ledger, audit_path=self.audit)

    def bound_audit_store(self):
        return AuditStore(self.audit, ledger_path=self.ledger)


class SeriesEraseTests(EraseTestBase):
    def test_target_history_vanishes_other_identities_unchanged(self):
        r1, r2, _ = self.publish_rounds()
        before = {rid: self.history_rows_for(rid)
                  for rid in ('id_papa', 'id_qube', 'id_whis', 'id_zulu')}
        view = self.erase('req-1', ['id_alpha', 'id_beta'])
        self.assertEqual(view['state'], 'done')
        self.assertNotIn('id_alpha', self.history_ids())
        self.assertNotIn('id_beta', self.history_ids())
        # Every other identity's full history is byte-for-byte unchanged.
        for rid, rows in before.items():
            self.assertEqual(self.history_rows_for(rid), rows, rid)
        with sqlite3.connect(self.ledger) as conn:
            versions = [row[0] for row in conn.execute(
                'SELECT version FROM batches ORDER BY version')]
            self.assertEqual(versions, [1, 2])
            self.assertEqual(view['series_history_deleted'], 4)

    def test_old_batch_replay_and_new_batch_with_target_exit_path_fail(self):
        self.publish_rounds()
        self.erase('req-1', ['id_alpha'])
        r2 = load_series('identities_round2.json')
        # Replay of an old batch whose input carries the tombstoned id.
        with self.assertRaises(SeriesError):
            with self.bound_series_store() as store:
                publish(store, 'b2', r2, 'sha-r2', self.tmp / 'r2.json')
        # A brand new batch carrying the target is rejected without state change.
        with sqlite3.connect(self.ledger) as conn:
            batches_before = conn.execute(
                'SELECT COUNT(*) FROM batches').fetchone()[0]
        with self.assertRaises(SeriesError):
            with self.bound_series_store() as store:
                publish(store, 'b-new', r2, 'sha-new', self.tmp / 'new.json')
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM batches').fetchone()[0], batches_before)
            self.assertNotIn('id_alpha',
                             {row[0] for row in conn.execute(
                                 'SELECT DISTINCT id FROM history')})

    def test_version_sequence_stays_continuous_after_wiping_a_group(self):
        self.publish_rounds()
        # Erase every identity currently known to the ledger.
        self.erase('req-wipe', sorted(self.history_ids()))
        self.assertEqual(self.history_ids(), set())
        fresh = {'k': 2, 'max_suppressed': 1, 'records': [
            {'id': 'fresh1', 'age': 21, 'postal': '11111', 'category': 'blue'},
            {'id': 'fresh2', 'age': 22, 'postal': '11122', 'category': 'blue'}]}
        with self.bound_series_store() as store:
            status, payload = publish(
                store, 'b3', fresh, 'sha-r3', self.tmp / 'r3.json')
        self.assertEqual(status, 'published')
        self.assertEqual(json.loads(payload)['version'], 3)
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual([row[0] for row in conn.execute(
                'SELECT version FROM batches ORDER BY version')], [1, 2, 3])

    def test_public_report_bytes_are_unchanged_by_erase(self):
        _r1, _r2, reports = self.publish_rounds()
        on_disk = {name: (self.tmp / (name + '.json')).read_bytes()
                   for name in ('r1', 'r2')}
        import hashlib
        sha_before = {name: hashlib.sha256(blob).hexdigest()
                      for name, blob in on_disk.items()}
        self.erase('req-1', ['id_alpha', 'id_beta'])
        for name, blob in on_disk.items():
            self.assertEqual((self.tmp / (name + '.json')).read_bytes(), blob)
            self.assertEqual(hashlib.sha256(
                (self.tmp / (name + '.json')).read_bytes()).hexdigest(),
                sha_before[name])
        # The ledger's stored report bytes reconcile too.
        with self.bound_series_store() as store:
            recover(store)

    def test_tombstones_and_task_rows_hold_only_digests(self):
        self.publish_rounds()
        ids = ['id_alpha', 'id_beta']
        self.erase('req-1', ids)
        with sqlite3.connect(self.ledger) as conn:
            blob = '\n'.join(
                str(row) for row in conn.execute(
                    'SELECT request_id,id_fingerprint,id_count,state FROM '
                    'erase_tasks').fetchall()) + '\n' + '\n'.join(
                str(row) for row in conn.execute(
                    'SELECT id_digest,request_id FROM tombstones').fetchall())
        for rid in ids:
            self.assertNotIn(rid, blob)
        expected = {id_digest(rid) for rid in ids}
        stored = {row[0] for row in sqlite3.connect(self.ledger).execute(
            'SELECT id_digest FROM tombstones')}
        self.assertEqual(stored, expected)

    def test_same_request_same_set_is_idempotent_changed_set_rejected(self):
        self.publish_rounds()
        view1 = self.erase('req-1', ['id_alpha', 'id_beta', 'id_alpha'])
        view2 = self.erase('req-1', ['id_beta', 'id_alpha'])  # reordered/dup
        self.assertEqual(view1, view2)
        with self.assertRaises(SeriesError):
            self.erase('req-1', ['id_alpha', 'id_zulu'])
        # The rejected conflict changed nothing.
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM erase_tasks").fetchone()[0], 1)

    def test_resume_done_task_does_not_delete_later_unrelated_runs(self):
        self.publish_rounds()
        make_run(self.audit, ['id_alpha', 'id_beta'])
        self.erase('req-1', ['id_alpha'])
        # After completion, a brand new unrelated run is accepted and must
        # survive a repeated resume of the finished request.
        new_id, _result = make_run(
            self.audit, ['id_whis', 'id_zulu'],
            store_kwargs={'ledger_path': self.ledger})
        view = resume_erase(self.ledger, self.audit, 'req-1')
        self.assertEqual(view['state'], 'done')
        with sqlite3.connect(self.audit) as conn:
            self.assertEqual(conn.execute(
                'SELECT run_id FROM runs').fetchall(), [(new_id,)])
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM run_identity_index').fetchone()[0], 2)

    def test_status_never_requires_ids_and_unknown_request_fails(self):
        self.publish_rounds()
        self.erase('req-1', ['id_alpha'])
        view = request_status(self.ledger, self.audit, 'req-1')
        self.assertEqual(view['state'], 'done')
        self.assertNotIn('id_alpha', json.dumps(view))
        with self.assertRaises(SeriesError):
            request_status(self.ledger, self.audit, 'nope')

    def test_id_file_validation(self):
        ids_path = self.tmp / 'ids.json'
        ids_path.write_text(json.dumps(['x', 'x', '  y  ']))
        with self.assertRaises(ValueError):
            read_id_set(ids_path)  # surrounding whitespace is not allowed
        ids_path.write_text(json.dumps(['x', 'x', 'y']))
        self.assertEqual(read_id_set(ids_path), {'x', 'y'})
        ids_path.write_text('[]')
        with self.assertRaises(ValueError):
            read_id_set(ids_path)
        ids_path.write_text('["ok", 7]')
        with self.assertRaises(ValueError):
            read_id_set(ids_path)
        self.assertEqual(
            id_set_fingerprint(['a', 'b']), id_set_fingerprint(['b', 'a']))


class LinkageEraseTests(EraseTestBase):
    def _audit_counts(self):
        with sqlite3.connect(self.audit) as conn:
            return {table: conn.execute(
                'SELECT COUNT(*) FROM %s' % table).fetchone()[0]
                for table in ('runs', 'slots', 'edges', 'identity_outcomes',
                              'identity_possible_categories', 'hall_witnesses',
                              'hall_witness_identities', 'hall_witness_slots',
                              'run_identity_index')}

    def test_new_runs_persist_complete_digest_index_atomically(self):
        run_id, result = make_run(self.audit, ['H1', 'H2', 'H3', 'H4'])
        with sqlite3.connect(self.audit) as conn:
            rows = conn.execute(
                'SELECT identity_index,id_digest FROM run_identity_index '
                'ORDER BY identity_index').fetchall()
        self.assertEqual(len(rows), 4)
        self.assertEqual([digest for _i, digest in rows],
                         [id_digest(rid) for rid in ('H1', 'H2', 'H3', 'H4')])
        # No plaintext id appears in the index table.
        blob = json.dumps(rows)
        for rid in ('H1', 'H2', 'H3', 'H4'):
            self.assertNotIn(rid, blob)

    def test_indexed_related_run_is_deleted_unrelated_run_kept_field_by_field(self):
        related_id, _ = make_run(self.audit, ['id_alpha', 'id_beta'])
        unrelated_id, _ = make_run(self.audit, ['id_whis', 'id_zulu'])
        before_unrelated = self._audit_counts()
        self.erase('req-1', ['id_alpha'])
        with sqlite3.connect(self.audit) as conn:
            surviving = [row[0] for row in conn.execute(
                'SELECT run_id FROM runs')]
            self.assertEqual(surviving, [unrelated_id])
            # Every derived table lost the related run's rows and kept the
            # unrelated run's rows exactly.
            for table in ('slots', 'edges', 'identity_outcomes',
                          'identity_possible_categories',
                          'run_identity_index'):
                ids_left = {row[0] for row in conn.execute(
                    'SELECT DISTINCT run_id FROM %s' % table)}
                self.assertEqual(ids_left, {unrelated_id}, table)
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM run_identity_index').fetchone()[0], 2)
        view = request_status(self.ledger, self.audit, 'req-1')
        self.assertEqual(view['audit_runs_deleted'], 1)

    def test_legacy_run_without_index_is_conservatively_purged(self):
        # Simulate a pre-binding run: a normal run row set with no index rows.
        run_id, _ = make_run(self.audit, ['id_whis', 'id_zulu'])
        with sqlite3.connect(self.audit) as conn:
            conn.execute('DELETE FROM run_identity_index')
            conn.commit()
        unrelated_new_id, _ = make_run(self.audit, ['id_papa', 'id_qube'])
        self.erase('req-1', ['id_alpha'])  # target absent from both runs
        with sqlite3.connect(self.audit) as conn:
            surviving = [row[0] for row in conn.execute(
                'SELECT run_id FROM runs')]
            # The unindexed legacy run cannot be proven unrelated and is gone;
            # the fully indexed unrelated run is retained.
            self.assertEqual(surviving, [unrelated_new_id])

    def test_target_in_inconsistent_non_hall_input_still_deletes_run(self):
        # Build an inconsistent run whose Hall witness is a strict subset of
        # the input identities: four constrained helpers share one capacity-2
        # bucket (deficit 2), while a fifth free helper matches a separate
        # capacity-3 bucket.  The erase target is the free identity, which is
        # an input subject but not part of the witness set.
        report = {'schema_version': 1, 'source_sha256': 'a' * 64, 'result': {
            'candidates': [],
            'equivalence_classes': [
                {'age': '30-39', 'postal': '555**', 'size': 2,
                 'distinct_categories': 1,
                 'category_counts': {'red': 2}},
                {'age': '0-9', 'postal': '100**', 'size': 3,
                 'distinct_categories': 1,
                 'category_counts': {'blue': 3}}],
            'feasible': True, 'input_rows': 5, 'k': 2, 'privacy_scope': 'x',
            'released_count': 5,
            'released_rows': (
                [{'age': '30-39', 'postal': '555**', 'category': 'red'}] * 2
                + [{'age': '0-9', 'postal': '100**',
                    'category': 'blue'}] * 3),
            'selected': {'age_level': 1, 'postal_level': 1,
                         'ordinal_generalization_cost': '1/2'},
            'suppressed_rows': 0}}
        constrained = [
            {'id': 'X%d' % i, 'age_min': 30, 'age_max': 39,
             'postal_prefix': '555'} for i in range(4)]
        free = {'id': 'FREE1', 'age_min': 0, 'age_max': 9,
                'postal_prefix': '100'}
        helpers = constrained + [free]
        result = analyze_linkage(report, helpers, 'rh', 'hh')
        self.assertEqual(result['status'], 'inconsistent')
        witness_ids = {result['identities'][i]['id']
                       for i in result['hall']['witness_identities']}
        self.assertEqual(witness_ids, {'X0', 'X1', 'X2', 'X3'})
        target = 'FREE1'
        self.assertNotIn(target, witness_ids)
        with AuditStore(self.audit) as store:
            run_id = store.persist(result)
        self.erase('req-1', [target])
        with sqlite3.connect(self.audit) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM runs').fetchone()[0], 0)
            for table in ('hall_witnesses', 'hall_witness_identities',
                          'hall_witness_slots', 'edges', 'slots',
                          'run_identity_index'):
                self.assertEqual(conn.execute(
                    'SELECT COUNT(*) FROM %s' % table).fetchone()[0], 0, table)

    def test_inconsistent_run_without_target_is_retained_when_indexed(self):
        report = json.loads((LINK_FIX / 'report_hall_fail.json').read_text())
        helpers = json.loads((LINK_FIX / 'helpers_hall_fail.json').read_text())
        result = analyze_linkage(report, helpers, 'rh', 'hh')
        with AuditStore(self.audit) as store:
            run_id = store.persist(result)
        self.erase('req-1', ['someone_else'])
        with sqlite3.connect(self.audit) as conn:
            self.assertEqual(conn.execute(
                'SELECT run_id FROM runs').fetchall(), [(run_id,)])
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM hall_witness_identities').fetchone()[0], 4)


class BindingTests(EraseTestBase):
    def test_unbound_databases_keep_legacy_entry_points(self):
        # Old flows work with no partner argument and produce no binding rows.
        self.publish_rounds()
        make_run(self.audit, ['id_alpha', 'id_beta'])
        with sqlite3.connect(self.ledger) as conn:
            self.assertIsNone(conn.execute(
                "SELECT value FROM meta WHERE key='privacy_binding_token'").fetchone())
        with sqlite3.connect(self.audit) as conn:
            self.assertIsNone(conn.execute(
                "SELECT value FROM meta WHERE key='privacy_binding_token'").fetchone())

    def test_bound_writers_fail_closed_without_or_with_wrong_partner(self):
        self.publish_rounds()
        make_run(self.audit, ['id_alpha'])
        self.erase('req-1', ['id_alpha'])
        with self.assertRaises(SeriesError):
            Store(self.ledger)
        with self.assertRaises(LinkageError):
            AuditStore(self.audit)
        other_ledger = self.tmp / 'other-ledger.sqlite'
        other_audit = self.tmp / 'other-audit.sqlite'
        with self.assertRaises(SeriesError):
            Store(self.ledger, audit_path=other_audit)
        with self.assertRaises(LinkageError):
            AuditStore(self.audit, ledger_path=other_ledger)

    def test_pairing_a_bound_with_unbound_database_is_rejected(self):
        self.publish_rounds()
        make_run(self.audit, ['id_alpha'])
        self.erase('req-1', ['id_alpha'])
        # A fresh, unbound partner cannot be grafted onto a bound database.
        fresh_audit = self.tmp / 'fresh.sqlite'
        with self.assertRaises(SeriesError):
            with Store(self.ledger, audit_path=fresh_audit) as ledger, \
                    AuditStore(fresh_audit, ledger_path=self.ledger) as audit:
                from table_privacy.erase import ensure_binding
                ensure_binding(ledger, audit)

    def test_pending_erase_blocks_both_writers_at_the_api(self):
        self.publish_rounds()
        make_run(self.audit, ['id_alpha'])
        # Hand-craft the pending state without finishing phase 2.
        from table_privacy.erase import ensure_binding
        with Store(self.ledger, audit_path=self.audit) as ledger, \
                AuditStore(self.audit, ledger_path=self.ledger) as audit:
            ensure_binding(ledger, audit)
            ledger.begin_erase('req-pending',
                               id_set_fingerprint(['id_alpha']),
                               ['id_alpha'])
        r2 = load_series('identities_round2.json')
        with self.assertRaises(SeriesError):
            with Store(self.ledger, audit_path=self.audit) as store:
                publish(store, 'b-late', r2, 'sha-late', self.tmp / 'late.json')
        report = wildcard_report(2)
        result = analyze_linkage(report, wildcard_helpers(['id_whis', 'id_zulu']),
                                 'r', 'h')
        with self.assertRaises(LinkageError):
            with AuditStore(self.audit, ledger_path=self.ledger) as store:
                store.persist(result)
        # Completing the request reopens both stores to unrelated subjects.
        view = resume_erase(self.ledger, self.audit, 'req-pending')
        self.assertEqual(view['state'], 'done')
        with Store(self.ledger, audit_path=self.audit) as store:
            status, _payload = publish(
                store, 'b-ok',
                {'k': 2, 'max_suppressed': 1, 'records': [
                    {'id': 'fresh1', 'age': 21, 'postal': '11111',
                     'category': 'blue'},
                    {'id': 'fresh2', 'age': 22, 'postal': '11122',
                     'category': 'blue'}]},
                'sha-ok', self.tmp / 'ok.json')
            self.assertEqual(status, 'published')
        with AuditStore(self.audit, ledger_path=self.ledger) as store:
            self.assertIsInstance(store.persist(result), int)


    def test_half_binding_recovery_completes_and_foreign_partner_fails_closed(self):
        self.publish_rounds()
        from table_privacy.erase import ensure_binding
        # Audit side bound, ledger side still unbound, back-pointer correct.
        with AuditStore(self.audit, ledger_path=self.ledger) as audit:
            audit.install_binding('t' * 64, str(self.ledger.resolve()))
        with Store(self.ledger, audit_path=self.audit) as ledger, \
                AuditStore(self.audit, ledger_path=self.ledger) as audit2:
            token = ensure_binding(ledger, audit2)
            self.assertEqual(token, 't' * 64)
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute(
                "SELECT value FROM meta WHERE key='privacy_binding_token'"
            ).fetchone()[0], 't' * 64)
        # The same bound audit cannot be paired with a different ledger: the
        # store constructor itself fails closed before any write is possible.
        foreign_ledger = self.tmp / 'foreign-ledger.sqlite'
        Store(foreign_ledger).close()
        with self.assertRaises(LinkageError):
            AuditStore(self.audit, ledger_path=foreign_ledger)


if __name__ == '__main__':
    unittest.main()
