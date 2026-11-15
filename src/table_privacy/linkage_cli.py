"""CLI for the linkage-risk audit against one public schema-1 release.

The command imports only a public report and a helper-identity JSON array into
a private SQLite audit database.  It never reads the private source table or
the serial-release ledger.  Validation and the complete combinatorial solve
run in memory before the audit database is opened, so any illegal input exits
with code 2 while the previous database contents stay untouched.

After the audit database has been bound to a series ledger by
``table-privacy-erase``, every invocation must pass ``--ledger``; the bound
ledger's pending/tombstone state is then checked inside the write transaction.
"""
DESCRIPTION = ('Linkage-risk audit: match a helper-identity array against one '
               'public schema-1 release into a private SQLite audit store.')
import argparse
import json
import sqlite3
import sys
from pathlib import Path

from .common import read
from .linkage import AUDIT_SCHEMA_VERSION, AuditStore, LinkageError, analyze_linkage


def _public_summary(run_id, result):
    """Build the id-free stdout payload; identity-level data stays in the DB."""
    summary = {
        'audit_schema_version': AUDIT_SCHEMA_VERSION,
        'run_id': run_id,
        'report_sha256': result['report_sha256'],
        'helpers_sha256': result['helpers_sha256'],
        'report_source_sha256': result['report_source_sha256'],
        'status': result['status'],
        'identity_count': result['identity_count'],
        'slot_count': result['slot_count'],
        'edge_count': result['edge_count'],
        'total_capacity': result['total_capacity'],
        'maxflow': result['maxflow'],
    }
    if result['status'] == 'consistent':
        summary['forced_exposure_count'] = sum(
            o['forced_exposure'] for o in result['outcomes'])
        summary['unusable_edge_count'] = sum(
            1 for edge in result['edges'] if not edge['usable'])
        summary['hall_witness'] = None
    else:
        hall = result['hall']
        summary['forced_exposure_count'] = 0
        summary['unusable_edge_count'] = 0
        summary['hall_witness'] = {
            'witness_set_size': len(hall['witness_identities']),
            'neighbor_slot_count': len(hall['neighbor_slots']),
            'neighbor_capacity': hall['neighbor_capacity'],
            'deficit': hall['deficit']}
    return summary


def run_audit(report_path, helpers_path, audit_path, ledger_path=None,
              journal_mode=None):
    report_data, report_digest = read(report_path)
    helper_data, helpers_digest = read(helpers_path)
    # Solve completely before touching the audit database: illegal input must
    # leave an existing (or would-be) store untouched.
    result = analyze_linkage(report_data, helper_data, report_digest, helpers_digest)
    with AuditStore(audit_path, ledger_path=ledger_path,
                    journal_mode=journal_mode) as store:
        run_id = store.persist(result)
    return _public_summary(run_id, result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--report', type=Path, required=True,
                        help='public schema-1 table-privacy report JSON')
    parser.add_argument('--helpers', type=Path, required=True,
                        help='JSON array of helper identities '
                             '(id, age_min, age_max, postal_prefix)')
    parser.add_argument('--audit-db', type=Path, required=True,
                        help='private SQLite audit database path (never published)')
    parser.add_argument('--ledger', type=Path,
                        help='bound series ledger; required once the audit '
                             'database has been bound by table-privacy-erase')
    parser.add_argument('--journal-mode', choices=('delete', 'wal'),
                        help="SQLite journal mode (defaults to SQLite's "
                             'rollback journal)')
    args = parser.parse_args(argv)
    try:
        paths = (args.report.resolve(), args.helpers.resolve(),
                 args.audit_db.resolve())
        if len(set(paths)) != 3:
            raise ValueError('report, helpers and audit-db paths must all differ')
        summary = run_audit(args.report, args.helpers, args.audit_db,
                            ledger_path=args.ledger,
                            journal_mode=args.journal_mode)
    except (ValueError, TypeError, KeyError, OSError, OverflowError,
            RecursionError, LinkageError, sqlite3.Error) as error:
        print(str(error), file=sys.stderr)
        return 2
    # stdout carries aggregate counts only: no ids, mappings or helper rows.
    sys.stdout.write(json.dumps(summary, sort_keys=True,
                                ensure_ascii=False, allow_nan=False) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
