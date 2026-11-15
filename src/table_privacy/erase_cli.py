"""CLI for cross-database subject erasure (private retention termination).

The command operates on the private series ledger and the private linkage
audit database only.  It is not an anonymization or disclosure analysis, and
it does not touch SQLite free pages, backups or external raw inputs.  Every
stdout/stderr line is free of plaintext ids: only request metadata, digests
and aggregate counts are emitted.
"""
DESCRIPTION = ('Erase subjects from the bound series ledger and linkage audit '
               'database; digests only, resumable by request id.')
import argparse
import json
import sqlite3
import sys
from pathlib import Path

from .erase import (read_id_set, request_status, resume_erase, run_erase)
from .linkage import LinkageError
from .series import SeriesError


def _emit(view):
    sys.stdout.write(json.dumps(view, sort_keys=True,
                                ensure_ascii=False, allow_nan=False) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--ledger', type=Path, required=True,
                        help='private series SQLite ledger path')
    parser.add_argument('--audit-db', type=Path, required=True,
                        help='private linkage SQLite audit database path')
    parser.add_argument('--request-id', required=True,
                        help='stable id of this erasure request; used for '
                             '--resume and --status')
    parser.add_argument('--ids', type=Path,
                        help='JSON file with a non-empty array of id strings; '
                             'order and duplicates are ignored')
    parser.add_argument('--resume', action='store_true',
                        help='continue an interrupted request without --ids')
    parser.add_argument('--status', action='store_true',
                        help='print the id-free task state without --ids')
    parser.add_argument('--journal-mode', choices=('delete', 'wal'),
                        help='SQLite journal mode for both databases '
                             "(defaults to SQLite's rollback journal)")
    args = parser.parse_args(argv)
    if args.status and args.resume:
        print('--resume and --status are mutually exclusive', file=sys.stderr)
        return 2
    if not args.status and not args.resume and args.ids is None:
        print('--ids is required unless --resume or --status is given',
              file=sys.stderr)
        return 2
    if (args.resume or args.status) and args.ids is not None:
        print('--ids must not be supplied with --resume or --status',
              file=sys.stderr)
        return 2
    try:
        if args.ledger.resolve() == args.audit_db.resolve():
            raise ValueError('ledger and audit-db paths must differ')
        if args.status:
            view = request_status(args.ledger, args.audit_db, args.request_id,
                                  journal_mode=args.journal_mode)
        elif args.resume:
            view = resume_erase(args.ledger, args.audit_db, args.request_id,
                                journal_mode=args.journal_mode)
        else:
            ids = read_id_set(args.ids)
            view = run_erase(args.ledger, args.audit_db, args.request_id, ids,
                             journal_mode=args.journal_mode)
    except (ValueError, TypeError, KeyError, OSError, OverflowError,
            RecursionError, SeriesError, LinkageError, sqlite3.Error,
            json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 2
    _emit(view)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
