"""Regenerate the self-contained linkage audit fixtures.

The public report files are produced through model.analyze so their envelope is
identical to a real table-privacy run; helper JSON arrays are hand-authored
synthetic inputs.  Run with:

    PYTHONPATH=src python3 -I scripts/build_linkage_fixtures.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from table_privacy.model import analyze
OUT = ROOT / 'fixtures' / 'linkage'


def write(name, payload):
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / name
    path.write_text(json.dumps(payload, sort_keys=True, ensure_ascii=False,
                               allow_nan=False, indent=2) + '\n',
                    encoding='utf-8')
    print('wrote', path)


def envelope(records, k=2, max_suppressed=1):
    source = {'k': k, 'max_suppressed': max_suppressed, 'records': records}
    result = analyze(source)
    assert result['feasible']
    return {'schema_version': 1,
            'source_sha256': '0' * 64,
            'result': result}


# --- forced: single-category buckets, capacity competition forces each id -- #
# Repeated full postcodes make the report select postal_level 0.  Both buckets
# are single-category, so every identity that can only reach one bucket is
# forced to that category; the ambiguous variant widens H1 across buckets.
forced_records = [
    {'id': 'R1', 'age': 21, 'postal': '12345', 'category': 'green'},
    {'id': 'R2', 'age': 24, 'postal': '12345', 'category': 'green'},
    {'id': 'R3', 'age': 42, 'postal': '98765', 'category': 'blue'},
    {'id': 'R4', 'age': 45, 'postal': '98765', 'category': 'blue'},
]
write('report_forced.json', envelope(forced_records))
write('helpers_forced.json', [
    {'id': 'H1', 'age_min': 20, 'age_max': 29, 'postal_prefix': '12345'},
    {'id': 'H2', 'age_min': 20, 'age_max': 29, 'postal_prefix': '12345'},
    {'id': 'H3', 'age_min': 40, 'age_max': 50, 'postal_prefix': '98765'},
    {'id': 'H4', 'age_min': 44, 'age_max': 46, 'postal_prefix': '98765'},
])
# Ambiguous variant: H3 also spans the green bucket.  Both green slots can then
# be filled without H1, and H1 can equally land on either bucket, so its
# category is ambiguous while H2/H3/H4 stay forced.
write('helpers_ambiguous.json', [
    {'id': 'H1', 'age_min': 0, 'age_max': 120, 'postal_prefix': ''},
    {'id': 'H2', 'age_min': 20, 'age_max': 29, 'postal_prefix': '12345'},
    {'id': 'H3', 'age_min': 20, 'age_max': 50, 'postal_prefix': ''},
    {'id': 'H4', 'age_min': 44, 'age_max': 46, 'postal_prefix': '98765'},
])
# Mixed-category bucket fixture: one bucket (20-29/12345) holds a blue and a
# green slot, so a helper restricted to that bucket has both categories
# possible and must not be labelled a forced exposure.
mixed_records = [
    {'id': 'M1', 'age': 21, 'postal': '12345', 'category': 'blue'},
    {'id': 'M2', 'age': 24, 'postal': '12345', 'category': 'green'},
]
write('report_mixed.json', envelope(mixed_records, max_suppressed=0))
write('helpers_mixed.json', [
    {'id': 'K1', 'age_min': 20, 'age_max': 29, 'postal_prefix': '12345'},
    {'id': 'K2', 'age_min': 20, 'age_max': 29, 'postal_prefix': '12345'},
])

# --- wildcard: age "*" and postal "*" buckets, categories are ambiguous ----- #
# Includes the age-120 boundary and a leading-zero postcode; both helpers span
# the full domain so neither identity can ever be forced.
wild_records = [
    {'id': 'W1', 'age': 120, 'postal': '00001', 'category': 'red'},
    {'id': 'W2', 'age': 7, 'postal': '90009', 'category': 'blue'},
]
write('report_wildcard.json', envelope(wild_records, max_suppressed=0))
write('helpers_wildcard.json', [
    {'id': 'A', 'age_min': 0, 'age_max': 120, 'postal_prefix': ''},
    {'id': 'B', 'age_min': 0, 'age_max': 120, 'postal_prefix': ''},
])

# --- hall failure: four narrow helpers can only reach one capacity-2 bucket  #
# Adjacency is bucket-granular (every slot in a bucket shares its labels), so
# the deficiency is constructed at bucket level: all four helpers intersect the
# 30-39/555** bucket (joint capacity 2) and none reaches 80-89/777** (capacity
# 2).  The witness is all four identities with neighbour capacity 2.
hall_records = [
    {'id': 'P1', 'age': 30, 'postal': '55500', 'category': 'red'},
    {'id': 'P2', 'age': 35, 'postal': '55501', 'category': 'green'},
    {'id': 'P3', 'age': 80, 'postal': '77700', 'category': 'blue'},
    {'id': 'P4', 'age': 81, 'postal': '77701', 'category': 'blue'},
]
write('report_hall_fail.json', envelope(hall_records, max_suppressed=1))
write('helpers_hall_fail.json', [
    {'id': 'X1', 'age_min': 30, 'age_max': 39, 'postal_prefix': '555'},
    {'id': 'X2', 'age_min': 30, 'age_max': 30, 'postal_prefix': '555'},
    {'id': 'X3', 'age_min': 39, 'age_max': 39, 'postal_prefix': '555'},
    {'id': 'X4', 'age_min': 32, 'age_max': 33, 'postal_prefix': '55500'},
])
