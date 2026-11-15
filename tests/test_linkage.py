"""Unit tests for the linkage-risk audit graph algorithms and validation."""
import json
import random
import unittest
from collections import Counter
from pathlib import Path

from table_privacy.linkage import (MAX_EDGES, MAX_IDENTITIES,
                                   LinkageError, age_intersects, analyze_linkage,
                                   parse_age_label, parse_helpers, parse_postal_label,
                                   parse_report, postal_intersects)

ROOT = Path(__file__).resolve().parents[1]
LINK_FIX = ROOT / 'fixtures' / 'linkage'


def load(name):
    return json.loads((LINK_FIX / name).read_text())


def brute_force_audit(slots, identities):
    """Reference solver: expand slot copies and backtrack over assignments.

    Repeated slots are expanded here only; the production solver never does.
    Returns (possible_categories, usable_edges); an empty set of matchings
    means no full matching exists.
    """
    copies = []
    for slot in slots:
        copies.extend([slot['index']] * slot['capacity'])
    adj = {i: set() for i in range(len(identities))}
    for i, identity in enumerate(identities):
        for slot in slots:
            j = slot['index']
            if (age_intersects(identity['age_min'], identity['age_max'], slot['age_label'])
                    and postal_intersects(identity['postal_prefix'], slot['postal_label'])):
                adj[i].add(j)

    assignments = set()
    chosen = []
    remaining = Counter(copies)

    def backtrack(i):
        if i == len(identities):
            if all(v == 0 for v in remaining.values()):
                assignments.add(tuple(chosen))
            return
        for j in sorted(adj[i]):
            if remaining[j] > 0:
                remaining[j] -= 1
                chosen.append(j)
                backtrack(i + 1)
                chosen.pop()
                remaining[j] += 1

    backtrack(0)
    possible = {i: set() for i in range(len(identities))}
    usable = set()
    category_of = {s['index']: s['category'] for s in slots}
    for assignment in assignments:
        for i, j in enumerate(assignment):
            possible[i].add(category_of[j])
            usable.add((i, j))
    return assignments, possible, usable, adj


class LabelTests(unittest.TestCase):
    def test_age_labels_including_120_and_wildcard(self):
        self.assertEqual(parse_age_label('37'), (0, (37, 37)))
        self.assertEqual(parse_age_label('0'), (0, (0, 0)))
        self.assertEqual(parse_age_label('120'), (0, (120, 120)))
        self.assertEqual(parse_age_label('120-120'), (1, (120, 120)))
        self.assertEqual(parse_age_label('20-29'), (1, (20, 29)))
        self.assertEqual(parse_age_label('*'), (2, None))
        for bad in ('007', '121', '21-30', '19-28', '25-35', 'abc', '', '10-19x'):
            with self.assertRaises(LinkageError):
                parse_age_label(bad)

    def test_postal_labels_preserve_leading_zeros(self):
        self.assertEqual(parse_postal_label('*'), (2, ''))
        self.assertEqual(parse_postal_label('00123'), (0, '00123'))
        self.assertEqual(parse_postal_label('001**'), (1, '001'))
        for bad in ('0012', '001234', '01**', '001*', 'abcde', ''):
            with self.assertRaises(LinkageError):
                parse_postal_label(bad)

    def test_age_intersection_boundaries(self):
        self.assertTrue(age_intersects(120, 120, '120-120'))
        self.assertTrue(age_intersects(119, 120, '120-120'))
        self.assertFalse(age_intersects(118, 119, '120-120'))
        self.assertTrue(age_intersects(0, 0, '0-9'))
        self.assertTrue(age_intersects(0, 120, '*'))
        self.assertFalse(age_intersects(30, 31, '20-29'))
        self.assertTrue(age_intersects(29, 30, '20-29'))

    def test_postal_prefix_intersection(self):
        self.assertTrue(postal_intersects('', '*'))
        self.assertTrue(postal_intersects('', '12345'))
        self.assertTrue(postal_intersects('1', '12345'))
        self.assertTrue(postal_intersects('12345', '12345'))
        self.assertFalse(postal_intersects('12346', '12345'))
        self.assertTrue(postal_intersects('12', '123**'))
        self.assertTrue(postal_intersects('12399', '123**'))
        self.assertFalse(postal_intersects('124', '123**'))
        self.assertTrue(postal_intersects('1234', '123**'))


class ValidationTests(unittest.TestCase):
    def test_report_counts_must_reconcile(self):
        report = load('report_forced.json')
        slots, digest = parse_report(report)
        self.assertEqual(sum(s['capacity'] for s in slots), 4)
        self.assertEqual(digest, '0' * 64)

        tampered = json.loads(json.dumps(report))
        tampered['result']['released_rows'].pop()
        with self.assertRaises(LinkageError):
            parse_report(tampered)

        tampered = json.loads(json.dumps(report))
        tampered['result']['equivalence_classes'][0]['size'] = 3
        with self.assertRaises(LinkageError):
            parse_report(tampered)

        tampered = json.loads(json.dumps(report))
        tampered['schema_version'] = 2
        with self.assertRaises(LinkageError):
            parse_report(tampered)

        infeasible = {'schema_version': 1, 'source_sha256': 'a' * 64,
                      'result': {'candidates': [], 'equivalence_classes': [],
                                 'feasible': False, 'input_rows': 5, 'k': 2,
                                 'released_rows': []}}
        with self.assertRaises(LinkageError):
            parse_report(infeasible)

    def test_helper_validation_ranges_prefixes_and_unique_ids(self):
        helpers = load('helpers_forced.json')
        rows = parse_helpers(helpers)
        self.assertEqual([r['id'] for r in rows], ['H1', 'H2', 'H3', 'H4'])
        for bad in [
            [{'id': 'A', 'age_min': 121, 'age_max': 121, 'postal_prefix': ''}],
            [{'id': 'A', 'age_min': -1, 'age_max': 0, 'postal_prefix': ''}],
            [{'id': 'A', 'age_min': 5, 'age_max': 4, 'postal_prefix': ''}],
            [{'id': 'A', 'age_min': 0, 'age_max': 0, 'postal_prefix': '123456'}],
            [{'id': 'A', 'age_min': 0, 'age_max': 0, 'postal_prefix': '12a'}],
            [{'id': 'A', 'age_min': True, 'age_max': 0, 'postal_prefix': ''}],
            [{'id': 'A', 'age_min': 0, 'age_max': 0, 'postal_prefix': 5}],
            [{'id': 5, 'age_min': 0, 'age_max': 0, 'postal_prefix': ''}],
        ]:
            with self.assertRaises((LinkageError, ValueError)):
                parse_helpers(bad)
        with self.assertRaises(LinkageError):
            parse_helpers([
                {'id': 'A', 'age_min': 0, 'age_max': 0, 'postal_prefix': ''},
                {'id': 'A', 'age_min': 0, 'age_max': 0, 'postal_prefix': ''}])

    def test_helper_count_mismatch_is_invalid_not_hall_failure(self):
        report = load('report_forced.json')
        helpers = load('helpers_forced.json')[:-1]
        with self.assertRaises(LinkageError):
            analyze_linkage(report, helpers, 'r', 'h')

    def test_leading_zero_postal_and_duplicate_json_shape_are_rejected(self):
        report = load('report_wildcard.json')
        # The wildcard report keeps the leading-zero postcode of its source.
        self.assertEqual(report['result']['released_rows'][0]['postal'], '*')
        bad_sha = json.loads(json.dumps(report))
        bad_sha['source_sha256'] = 'F' * 64
        with self.assertRaises(LinkageError):
            parse_report(bad_sha)
        tampered = json.loads(json.dumps(report))
        tampered['result']['released_count'] = 99
        with self.assertRaises(LinkageError):
            parse_report(tampered)
        tampered = json.loads(json.dumps(report))
        tampered['result']['equivalence_classes'][0]['distinct_categories'] = 1
        with self.assertRaises(LinkageError):
            parse_report(tampered)

    def test_postal_prefix_leading_zeros_intersect_correctly(self):
        report = load('report_wildcard.json')
        helpers = [
            {'id': 'A', 'age_min': 120, 'age_max': 120, 'postal_prefix': '00001'},
            {'id': 'B', 'age_min': 0, 'age_max': 0, 'postal_prefix': '00002'},
        ]
        result = analyze_linkage(report, helpers, 'r', 'h')
        self.assertEqual(result['status'], 'consistent')
        # The wildcard postal label intersects every prefix, including the
        # all-leading-zero ones; both identities stay ambiguous.
        for outcome in result['outcomes']:
            self.assertEqual(outcome['possible_categories'], ['blue', 'red'])


class ForcedFixtureTests(unittest.TestCase):
    def setUp(self):
        self.report = load('report_forced.json')
        self.helpers = load('helpers_forced.json')
        self.result = analyze_linkage(self.report, self.helpers, 'rh', 'hh')

    def test_consistent_run_edges_and_forced_exposures(self):
        res = self.result
        self.assertEqual(res['status'], 'consistent')
        # Two single-category slots of capacity 2, one per disjoint bucket.
        self.assertEqual((res['identity_count'], res['slot_count'],
                          res['edge_count'], res['maxflow']), (4, 2, 4, 4))
        by_id = {res['identities'][o['identity_index']]['id']: o
                 for o in res['outcomes']}
        for hid, category in (('H1', 'green'), ('H2', 'green'),
                              ('H3', 'blue'), ('H4', 'blue')):
            self.assertTrue(by_id[hid]['forced_exposure'], hid)
            self.assertEqual(by_id[hid]['forced_category'], category)
            self.assertEqual(by_id[hid]['possible_categories'], [category])

    def test_matches_brute_force_on_expanded_slots(self):
        slots, _ = parse_report(self.report)
        identities = parse_helpers(self.helpers)
        matchings, possible, usable, _ = brute_force_audit(slots, identities)
        self.assertGreater(len(matchings), 0)
        for outcome in self.result['outcomes']:
            i = outcome['identity_index']
            self.assertEqual(set(outcome['possible_categories']), possible[i])
            self.assertEqual(bool(outcome['forced_exposure']), len(possible[i]) == 1)
        for edge in self.result['edges']:
            key = (edge['identity_index'], edge['slot_index'])
            self.assertEqual(bool(edge['usable']), key in usable)
        # The flow matching itself must be one of the brute-force matchings.
        flow_matching = {(e['identity_index'], e['slot_index'])
                         for e in self.result['edges'] if e['matched']}
        self.assertEqual(len(flow_matching), 4)
        self.assertTrue(any(set(enumerate(m)) == flow_matching for m in matchings))

    def test_ambiguous_helper_loses_forced_exposure_but_agrees_with_brute_force(self):
        helpers = load('helpers_ambiguous.json')
        result = analyze_linkage(self.report, helpers, 'rh', 'hh')
        self.assertEqual(result['status'], 'consistent')
        wide = next(o for o in result['outcomes']
                    if result['identities'][o['identity_index']]['id'] == 'H1')
        self.assertFalse(wide['forced_exposure'])
        self.assertEqual(wide['possible_categories'], ['blue', 'green'])
        slots, _ = parse_report(self.report)
        identities = parse_helpers(helpers)
        matchings, possible, usable, _ = brute_force_audit(slots, identities)
        self.assertGreater(len(matchings), 1)
        for edge in result['edges']:
            key = (edge['identity_index'], edge['slot_index'])
            self.assertEqual(bool(edge['usable']), key in usable)

    def test_candidate_edge_unusable_in_every_full_matching_is_flagged(self):
        # Two full-postcode buckets, each a single-category slot of capacity 2.
        # H3,H4 can only ever fill slot 1 (its capacity 2), so the extra edges
        # H1->slot1 and H2->slot1 can appear in no full matching even though a
        # full matching (H1,H2->slot0; H3,H4->slot1) exists.
        report = {
            'schema_version': 1, 'source_sha256': 'e' * 64,
            'result': {
                'candidates': [],
                'equivalence_classes': [
                    {'age': '20-29', 'postal': '11111', 'size': 2,
                     'distinct_categories': 1, 'category_counts': {'red': 2}},
                    {'age': '30-39', 'postal': '22222', 'size': 2,
                     'distinct_categories': 1, 'category_counts': {'blue': 2}}],
                'feasible': True, 'input_rows': 4, 'k': 2,
                'privacy_scope': 'x', 'released_count': 4,
                'released_rows': [
                    {'age': '20-29', 'postal': '11111', 'category': 'red'},
                    {'age': '20-29', 'postal': '11111', 'category': 'red'},
                    {'age': '30-39', 'postal': '22222', 'category': 'blue'},
                    {'age': '30-39', 'postal': '22222', 'category': 'blue'}],
                'selected': {'age_level': 1, 'postal_level': 0,
                             'ordinal_generalization_cost': '1/4'},
                'suppressed_rows': 0}}
        helpers = [
            {'id': 'H1', 'age_min': 20, 'age_max': 39, 'postal_prefix': ''},
            {'id': 'H2', 'age_min': 20, 'age_max': 39, 'postal_prefix': ''},
            {'id': 'H3', 'age_min': 30, 'age_max': 39, 'postal_prefix': '22222'},
            {'id': 'H4', 'age_min': 30, 'age_max': 39, 'postal_prefix': '22222'}]
        result = analyze_linkage(report, helpers, 'r', 'h')
        self.assertEqual(result['status'], 'consistent')
        self.assertEqual(result['edge_count'], 6)
        edge_map = {(e['identity_index'], e['slot_index']): e
                    for e in result['edges']}
        # Edges into slot 1 from the wide identities are never part of a full
        # matching because H3 and H4 exhaust that slot's capacity.
        self.assertFalse(edge_map[(0, 1)]['usable'])
        self.assertFalse(edge_map[(1, 1)]['usable'])
        self.assertTrue(edge_map[(0, 0)]['usable'])
        self.assertTrue(edge_map[(1, 0)]['usable'])
        self.assertTrue(edge_map[(2, 1)]['usable'])
        self.assertTrue(edge_map[(3, 1)]['usable'])
        # Both wide identities are still forced to red by capacity competition.
        for hid in ('H1', 'H2'):
            outcome = next(o for o in result['outcomes']
                           if result['identities'][o['identity_index']]['id'] == hid)
            self.assertEqual(outcome['possible_categories'], ['red'])
            self.assertTrue(outcome['forced_exposure'])
        # Exact agreement with the brute-force expansion.
        slots, _ = parse_report(report)
        identities = parse_helpers(helpers)
        _matchings, possible, usable, _ = brute_force_audit(slots, identities)
        self.assertEqual(usable, {(0, 0), (1, 0), (2, 1), (3, 1)})
        for edge in result['edges']:
            self.assertEqual(bool(edge['usable']),
                             (edge['identity_index'], edge['slot_index']) in usable)
        for outcome in result['outcomes']:
            self.assertEqual(set(outcome['possible_categories']),
                             possible[outcome['identity_index']])
        for outcome in result['outcomes']:
            i = outcome['identity_index']
            self.assertEqual(set(outcome['possible_categories']), possible[i])

    def test_mixed_category_bucket_is_never_a_forced_exposure(self):
        result = analyze_linkage(load('report_mixed.json'),
                                 load('helpers_mixed.json'), 'r', 'h')
        self.assertEqual(result['status'], 'consistent')
        slots, _ = parse_report(load('report_mixed.json'))
        identities = parse_helpers(load('helpers_mixed.json'))
        matchings, possible, usable, _ = brute_force_audit(slots, identities)
        self.assertEqual(len(matchings), 2)
        for outcome in result['outcomes']:
            self.assertFalse(outcome['forced_exposure'])
            self.assertEqual(set(outcome['possible_categories']),
                             {'blue', 'green'})
            self.assertEqual(set(outcome['possible_categories']),
                             possible[outcome['identity_index']])
        for edge in result['edges']:
            self.assertTrue(edge['usable'])
            self.assertIn((edge['identity_index'], edge['slot_index']), usable)


class WildcardAndHallTests(unittest.TestCase):
    def test_wildcard_bucket_is_fully_ambiguous(self):
        result = analyze_linkage(load('report_wildcard.json'),
                                 load('helpers_wildcard.json'), 'r', 'h')
        self.assertEqual(result['status'], 'consistent')
        self.assertEqual(result['edge_count'], 4)
        for outcome in result['outcomes']:
            self.assertFalse(outcome['forced_exposure'])
            self.assertIsNone(outcome['forced_category'])
            self.assertEqual(outcome['possible_categories'], ['blue', 'red'])
        slots, _ = parse_report(load('report_wildcard.json'))
        identities = parse_helpers(load('helpers_wildcard.json'))
        _m, possible, usable, _ = brute_force_audit(slots, identities)
        for edge in result['edges']:
            self.assertTrue(edge['usable'])
        for outcome in result['outcomes']:
            self.assertEqual(set(outcome['possible_categories']),
                             possible[outcome['identity_index']])

    def test_hall_failure_records_witness_and_no_guessed_probability(self):
        report = load('report_hall_fail.json')
        helpers = load('helpers_hall_fail.json')
        self.assertEqual(len(report['result']['released_rows']), 4)
        self.assertEqual(len(helpers), 4)
        result = analyze_linkage(report, helpers, 'r', 'h')
        self.assertEqual(result['status'], 'inconsistent')
        self.assertEqual(result['outcomes'], [])
        hall = result['hall']
        # All four helpers are restricted to the 30-39/555** bucket, whose two
        # category slots jointly provide capacity 2: deficit 4 - 2 = 2.
        self.assertEqual(len(hall['witness_identities']), 4)
        self.assertEqual(hall['neighbor_capacity'], 2)
        self.assertEqual(hall['deficit'], 2)
        self.assertEqual(len(hall['neighbor_slots']), 2)
        for j in hall['neighbor_slots']:
            slot = result['slots'][j]
            self.assertEqual((slot['age_label'], slot['postal_label']),
                             ('30-39', '555**'))
        self.assertEqual(
            sorted(result['identities'][i]['id']
                   for i in hall['witness_identities']),
            ['X1', 'X2', 'X3', 'X4'])
        # No outcome category is invented for an unsolvable instance.
        self.assertTrue(all(edge['usable'] is None for edge in result['edges']))

    def test_isolated_identity_is_hall_witness_of_size_one(self):
        report = load('report_forced.json')
        helpers = load('helpers_forced.json')
        # The 12345 bucket uses full five-digit labels, so an unrelated prefix
        # intersects nothing: H1 becomes isolated.
        helpers[0]['postal_prefix'] = '99999'
        result = analyze_linkage(report, helpers, 'r', 'h')
        self.assertEqual(result['status'], 'inconsistent')
        hall = result['hall']
        self.assertEqual(len(hall['witness_identities']), 1)
        self.assertEqual(len(hall['neighbor_slots']), 0)
        self.assertEqual(hall['neighbor_capacity'], 0)
        self.assertEqual(hall['deficit'], 1)
        self.assertEqual(
            [result['identities'][i]['id'] for i in hall['witness_identities']],
            ['H1'])


class RandomizedBruteForceTests(unittest.TestCase):
    def test_random_small_graphs_agree_with_brute_force(self):
        rng = random.Random(20261115)
        age_labels = ['0', '20-29', '120-120', '*']
        postal_labels = ['00123', '123**', '*']
        for trial in range(60):
            n = rng.randint(1, 7)
            slots = []
            categories = ['red', 'blue', 'green']
            remaining = n
            for index in range(n):
                capacity = rng.randint(1, remaining)
                remaining -= capacity
                slots.append({
                    'index': index,
                    'age_label': rng.choice(age_labels),
                    'postal_label': rng.choice(postal_labels),
                    'category': rng.choice(categories),
                    'capacity': capacity})
                if remaining == 0:
                    break
            identities = [{
                'id': 'I%d' % i,
                'age_min': (lo := rng.randint(0, 120)),
                'age_max': rng.randint(lo, 120),
                'postal_prefix': ''}
                for i in range(n)]
            # Add a random 0..5 digit prefix while keeping leading zeros legal.
            for pos, identity in enumerate(identities):
                length = rng.randint(0, 5)
                identity['postal_prefix'] = ''.join(
                    str(rng.randint(0, 9)) for _ in range(length))
            parsed_identities = parse_helpers(identities)
            matchings, possible, usable, adj = brute_force_audit(
                slots, parsed_identities)
            released = []
            classes = {}
            for slot in slots:
                key = (slot['age_label'], slot['postal_label'])
                for _ in range(slot['capacity']):
                    released.append({'age': key[0], 'postal': key[1],
                                     'category': slot['category']})
                view = classes.setdefault(key, Counter())
                view[slot['category']] += slot['capacity']
            report = {
                'schema_version': 1, 'source_sha256': 'f' * 64,
                'result': {
                    'candidates': [], 'equivalence_classes': [
                        {'age': age, 'postal': postal, 'size': sum(counts.values()),
                         'distinct_categories': len(counts),
                         'category_counts': dict(counts)}
                        for (age, postal), counts in sorted(classes.items())],
                    'feasible': True, 'input_rows': n, 'k': 2,
                    'privacy_scope': 'x', 'released_count': n,
                    'released_rows': released,
                    'selected': {'age_level': 1, 'postal_level': 1,
                                 'ordinal_generalization_cost': '1/2'},
                    'suppressed_rows': 0}}
            result = analyze_linkage(report, identities, 'r', 'h')
            parsed_result_identities = result['identities']
            if not matchings:
                self.assertEqual(result['status'], 'inconsistent')
                hall = result['hall']
                witness = [result['identities'][i]['id']
                           for i in hall['witness_identities']]
                # The stored witness really is Hall-deficient.
                neighbor = set()
                for i in hall['witness_identities']:
                    neighbor.update(adj[i])
                cap = sum(slots[j]['capacity'] for j in neighbor)
                self.assertEqual(cap, hall['neighbor_capacity'])
                self.assertLess(cap, len(witness))
            else:
                self.assertEqual(result['status'], 'consistent')
                for outcome in result['outcomes']:
                    i = outcome['identity_index']
                    self.assertEqual(set(outcome['possible_categories']), possible[i])
                for edge in result['edges']:
                    self.assertEqual(
                        bool(edge['usable']),
                        (edge['identity_index'], edge['slot_index']) in usable)


class LimitTests(unittest.TestCase):
    def _n_star_report(self, n):
        rows = [{'age': '30-39', 'postal': '100**', 'category': 'c%d' % (i % 3)}
                for i in range(n)]
        counts = Counter(r['category'] for r in rows)
        return {'schema_version': 1, 'source_sha256': 'b' * 64,
                'result': {
                    'candidates': [],
                    'equivalence_classes': [{
                        'age': '30-39', 'postal': '100**', 'size': n,
                        'distinct_categories': len(counts),
                        'category_counts': dict(sorted(counts.items()))}],
                    'feasible': True, 'input_rows': n, 'k': 2,
                    'privacy_scope': 'x', 'released_count': n,
                    'released_rows': rows,
                    'selected': {'age_level': 1, 'postal_level': 1,
                                 'ordinal_generalization_cost': '1/2'},
                    'suppressed_rows': 0}}

    def test_supported_scale_2000_identities_20000_edges(self):
        n = MAX_IDENTITIES
        # Ten distinct buckets gives each of 2000 helpers ten edges -> 20000.
        buckets = [(b * 10, '%03d' % (b + 1)) for b in range(10)]
        rows = []
        classes = {}
        per_bucket = n // 10
        for b, (age_base, stem) in enumerate(buckets):
            label_age = '%d-%d' % (age_base, min(120, age_base + 9))
            label_postal = stem + '**'
            for k in range(per_bucket):
                rows.append({'age': label_age, 'postal': label_postal,
                             'category': 'cat'})
            classes[(label_age, label_postal)] = Counter({'cat': per_bucket})
        report = {'schema_version': 1, 'source_sha256': 'b' * 64,
                  'result': {
                      'candidates': [],
                      'equivalence_classes': [
                          {'age': age, 'postal': postal, 'size': sum(c.values()),
                           'distinct_categories': 1, 'category_counts': dict(c)}
                          for (age, postal), c in sorted(classes.items())],
                      'feasible': True, 'input_rows': n, 'k': 2,
                      'privacy_scope': 'x', 'released_count': n,
                      'released_rows': rows,
                      'selected': {'age_level': 1, 'postal_level': 1,
                                   'ordinal_generalization_cost': '1/2'},
                      'suppressed_rows': 0}}
        helpers = [{'id': 'H%04d' % i, 'age_min': 0, 'age_max': 120,
                    'postal_prefix': ''} for i in range(n)]
        result = analyze_linkage(report, helpers, 'r', 'h')
        self.assertEqual(result['status'], 'consistent')
        self.assertEqual(result['edge_count'], MAX_EDGES)
        self.assertEqual(result['maxflow'], n)

    def test_beyond_edge_limit_is_rejected(self):
        n = MAX_IDENTITIES
        report = self._n_star_report(n)
        # Wildcard bucket: every helper reaches every slot; distinct triples
        # make one slot per row -> n*n edges, far beyond MAX_EDGES.
        report['result']['equivalence_classes'] = [
            {'age': '30-39', 'postal': '100**', 'size': n,
             'distinct_categories': n,
             'category_counts': {'c%d' % i: 1 for i in range(n)}}]
        report['result']['released_rows'] = [
            {'age': '30-39', 'postal': '100**', 'category': 'c%d' % i}
            for i in range(n)]
        helpers = [{'id': 'H%04d' % i, 'age_min': 30, 'age_max': 39,
                    'postal_prefix': '100'} for i in range(n)]
        with self.assertRaises(LinkageError):
            analyze_linkage(report, helpers, 'r', 'h')

    def test_beyond_identity_limit_is_rejected(self):
        too_many = [{'id': 'I%d' % i, 'age_min': 0, 'age_max': 120,
                     'postal_prefix': ''} for i in range(MAX_IDENTITIES + 1)]
        with self.assertRaises(LinkageError):
            parse_helpers(too_many)


if __name__ == '__main__':
    unittest.main()
