"""CLI for serial releases of one synthetic population with a private SQLite ledger."""
DESCRIPTION = ('Serial k-anonymous releases with a private SQLite ledger; '
               'the single-shot table-privacy entry point remains available.')
import argparse
import sqlite3
import sys
from pathlib import Path

from .common import read
from .series import SeriesError, Store, publish


def run_series(source, batch_id, ledger, report):
    """Read the original contract input and publish one serial release."""
    data, digest = read(source)
    with Store(ledger) as store:
        status, payload = publish(store, batch_id, data, digest, report)
    return status, payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--source', type=Path, required=True,
                        help='input JSON using the original single-shot contract')
    parser.add_argument('--batch-id', required=True,
                        help='unique batch identifier for this release attempt')
    parser.add_argument('--ledger', type=Path, required=True,
                        help='private SQLite ledger path (never published)')
    parser.add_argument('--report', type=Path, required=True,
                        help='public report output path')
    args = parser.parse_args(argv)
    try:
        if args.source.resolve() == args.report.resolve():
            raise ValueError('input and report must differ')
        if args.ledger.resolve() == args.report.resolve():
            raise ValueError('ledger and report must differ')
        status, payload = run_series(args.source, args.batch_id,
                                     args.ledger, args.report)
    except (ValueError, TypeError, KeyError, OSError, OverflowError,
            RecursionError, SeriesError, sqlite3.Error) as error:
        print(str(error), file=sys.stderr)
        return 2
    # stdout carries only the public report bytes: no ids, mappings or tracks.
    sys.stdout.write(payload.decode('utf-8'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
