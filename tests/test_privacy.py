import json,unittest
from pathlib import Path
from table_privacy.model import analyze
ROOT=Path(__file__).resolve().parents[1]
class PrivacyTests(unittest.TestCase):
    def setUp(self):self.d=json.loads((ROOT/'fixtures/input.json').read_text())
    def test_known_generalization_and_suppression(self):
        r=analyze(self.d);self.assertTrue(r['feasible']);self.assertEqual(r['selected'],{'age_level':1,'postal_level':1,'ordinal_generalization_cost':'1/2'})
        self.assertEqual((r['released_count'],r['suppressed_rows']),(4,1))
    def test_release_has_no_source_ids_and_every_class_meets_k(self):
        r=analyze(self.d);self.assertTrue(all(set(x)=={'age','postal','category'} for x in r['released_rows']))
        self.assertTrue(all(g['size']>=2 for g in r['equivalence_classes']));self.assertEqual(r['equivalence_classes'][1]['distinct_categories'],1)
    def test_no_suppression_budget_selects_full_generalization(self):
        self.d['max_suppressed']=0;r=analyze(self.d)
        self.assertTrue(r['feasible']);self.assertEqual(r['selected']['age_level'],2);self.assertEqual(r['selected']['postal_level'],2)
        self.assertEqual(r['released_count'],5)
    def test_impossible_k_never_returns_empty_success(self):
        self.d['k']=6;self.d['max_suppressed']=5;r=analyze(self.d);self.assertFalse(r['feasible'])
    def test_postal_zero_and_age_120_boundaries(self):
        self.d['records']=[{'id':str(i),'age':120,'postal':'00123','category':'x'} for i in range(2)]
        r=analyze(self.d);self.assertEqual(r['released_rows'][0]['postal'],'00123');self.assertEqual(r['selected']['age_level'],0)
    def test_invalid_postal_age_and_duplicate_id(self):
        self.d['records'][0]['postal']='１２３４５'
        with self.assertRaises(ValueError):analyze(self.d)
        self.setUp();self.d['records'][0]['age']=True
        with self.assertRaises(ValueError):analyze(self.d)
    def test_order_invariance_and_counts_preserved(self):
        r=analyze(self.d);self.d['records'].reverse();self.assertEqual(r,analyze(self.d))
        self.assertEqual(sum(g['size'] for g in r['equivalence_classes']),r['released_count'])
if __name__=='__main__':unittest.main()
