"""Strict local JSON contract and atomic report publication."""
from pathlib import Path
import hashlib, json, os, tempfile, time

def require(obj,keys):
    if not isinstance(obj,dict) or set(obj)!=set(keys.split()):raise ValueError('expected object fields: '+keys)

def ident(v):
    if not isinstance(v,str) or not v or v!=v.strip() or len(v)>128 or any(ord(c)<32 for c in v):
        raise ValueError('expected nonblank identifier, <=128 characters')
    return v

def number(v,minimum=0,maximum=10**9):
    if type(v) is not int or not minimum<=v<=maximum:raise ValueError('integer outside allowed bounds')
    return v

def rows(value,limit=20000):
    if not isinstance(value,list) or len(value)>limit:raise ValueError('expected bounded array')
    return value

def read(path):
    with Path(path).open('rb') as stream:raw=stream.read(8_000_001)
    if len(raw)>8_000_000:raise ValueError('JSON exceeds 8 MB')
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError('duplicate JSON key: '+k)
            result[k]=v
        return result
    def invalid(v):raise ValueError('nonfinite JSON number: '+v)
    data=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)
    return data,hashlib.sha256(raw).hexdigest()

def save(path,report):
    dest=Path(path)
    if dest.is_symlink():raise ValueError('output cannot be a symlink')
    dest.parent.mkdir(parents=True,exist_ok=True);temp=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=dest.parent,delete=False) as stream:
            temp=stream.name;json.dump(report,stream,sort_keys=True,ensure_ascii=False,allow_nan=False,indent=2);stream.write('\n')
        os.replace(temp,dest)
    finally:
        if temp and os.path.exists(temp):os.unlink(temp)

# ---------------------------------------------------------------------------
# Deterministic barriers used by the concurrency acceptance tests.  These are
# inert in production: the environment variable is only set inside test
# subprocesses.  A named gate is a directory containing three sentinel files;
# ``gate_wait`` blocks until the gate is released (or the deadline expires) and
# ``gate_release`` clears it.  Coordination is driven solely by file events,
# never by wall-clock guessing between concurrent operations.
# ---------------------------------------------------------------------------

_GATE_READY = 'ready'
_GATE_WAIT = 'wait'
_GATE_RELEASED = 'released'


def gate_root():
    """Return the test barrier root, or None outside a test subprocess."""
    root = os.environ.get('TABLE_PRIVACY_GATE_ROOT')
    return Path(root) if root else None


def gate_arm(name):
    """Create the named gate in the waiting state. No-op outside tests."""
    root = gate_root()
    if root is None:
        return
    gate = root / name
    gate.mkdir(parents=True, exist_ok=True)
    for sentinel in (_GATE_READY, _GATE_WAIT, _GATE_RELEASED):
        try:
            (gate / sentinel).unlink()
        except FileNotFoundError:
            pass
    (gate / _GATE_READY).touch()
    (gate / _GATE_WAIT).touch()


def gate_wait(name, timeout=60.0):
    """Block at the named gate until ``gate_release`` is called elsewhere.

    No-op when no barrier root is configured (production).  Returns once the
    released sentinel appears; raises TimeoutError at the deadline so a broken
    test fails deterministically instead of hanging.
    """
    root = gate_root()
    if root is None:
        return
    gate = root / name
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if (gate / _GATE_RELEASED).exists():
            return
        time.sleep(0.01)
    raise TimeoutError('gate %r was not released within %.0fs' % (name, timeout))


def gate_release(name):
    """Release every waiter blocked on the named gate."""
    root = gate_root()
    if root is None:
        return
    gate = root / name
    (gate / _GATE_RELEASED).touch()
