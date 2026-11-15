DESCRIPTION='Global recoding search for k-anonymous synthetic tables'
import argparse, sqlite3, sys
from pathlib import Path
from .common import read
from .model import analyze
from . import engine

def run(source):
    """In-memory reference path for small inputs (<=8 MB); kept for tests."""
    data,digest=read(source)
    return {'schema_version':1,'source_sha256':digest,'result':analyze(data)}

def main():
    parser=argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.source.resolve()==args.output.resolve():raise ValueError('input and output must differ')
        engine.publish(args.source,args.output,sys.stdout.buffer)
    except (ValueError,TypeError,KeyError,OSError,OverflowError,RecursionError,sqlite3.Error) as error:
        print(str(error),file=sys.stderr);return 2
    return 0

if __name__=='__main__':raise SystemExit(main())
