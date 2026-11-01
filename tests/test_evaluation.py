"""Grouped evaluation, data curation, and artifact compatibility checks."""
import unittest

import numpy as np
import pandas as pd

from src.evaluation import (classification_metrics, curated_rf_training,
                            rf_session_key, scenario_b_split_indices,
                            seen_feature_vectors, session_holdout)
from src.model_utils import PROJECT_ROOT, prepare_features
from src.predict import load_model, predict_with_model
from src.predict_xgboost import load_xgboost_model
from src.scenario_b import DATASET_ZIP, FEATURE_NAMES, load_scenario_b


class EvaluationTests(unittest.TestCase):
    def test_related_pcap_segments_share_a_session(self):
        self.assertEqual(rf_session_key('email2a.pcap'), rf_session_key('email2b.pcap'))
        self.assertEqual(rf_session_key('facebook_audio1a.pcap'),
                         rf_session_key('facebook_audio1b.pcapng'))
        self.assertNotEqual(rf_session_key('facebookchat1.pcapng'),
                            rf_session_key('facebookchat2.pcapng'))

    def test_session_holdout_is_deterministic_and_disjoint(self):
        frame = pd.DataFrame({
            'source_pcap': ['email1a.pcap', 'email1b.pcap', 'email2a.pcap', 'email2b.pcap',
                            'facebookchat1.pcapng', 'facebookchat2.pcapng'],
            'label': ['Email'] * 4 + ['Chat'] * 2,
        })
        first_train, first_test, first_selected = session_holdout(frame)
        second_train, second_test, second_selected = session_holdout(frame)
        self.assertEqual(first_selected, second_selected)
        self.assertEqual(first_test.index.tolist(), second_test.index.tolist())
        self.assertFalse(set(first_train.source_pcap.map(rf_session_key)) &
                         set(first_test.source_pcap.map(rf_session_key)))
        self.assertEqual(set(first_train.label), {'Email', 'Chat'})
        self.assertEqual(set(first_test.label), {'Email', 'Chat'})
        with self.assertRaisesRegex(ValueError, 'multiple labels'):
            session_holdout(pd.concat([frame, pd.DataFrame({
                'source_pcap': ['email1a.pcap'], 'label': ['Chat']})], ignore_index=True))

    def test_curation_drops_conflicts_and_caps_source_without_test_data(self):
        frame = pd.DataFrame({
            'source_pcap': ['a.pcap'] * 5 + ['b.pcap'] * 3,
            'label': ['A'] * 5 + ['B'] * 3,
            'f': [1, 1, 2, 3, 4, 2, 8, 9],
        })
        curated = curated_rf_training(frame, ['f'], max_rows_per_source=2, seed=42)
        self.assertEqual(len(curated), 4)
        self.assertNotIn(2, curated.f.tolist())
        self.assertLessEqual(curated.groupby('source_pcap').size().max(), 2)
        self.assertEqual(curated_rf_training(frame, ['f'], 2, 42).f.tolist(),
                         curated.f.tolist())

    def test_exact_vector_overlap_respects_order_and_validation(self):
        train = prepare_features(pd.DataFrame({'a': [1, np.inf], 'b': [2, 3]}), ['a', 'b'])
        test = prepare_features(pd.DataFrame({'a': [1, 0, 2], 'b': [2, 3, 3]}), ['a', 'b'])
        np.testing.assert_array_equal(seen_feature_vectors(train, test), [True, True, False])
        with self.assertRaisesRegex(ValueError, 'identical'):
            seen_feature_vectors(train, test[['b', 'a']])

    def test_metrics_have_stable_class_support_and_confusion(self):
        metrics = classification_metrics(['A', 'A', 'B'], ['A', 'B', 'B'], ['A', 'B'])
        self.assertEqual(metrics['confusion_matrix'], [[1, 1], [0, 1]])
        self.assertEqual(metrics['per_class']['A']['support'], 2)
        self.assertAlmostEqual(metrics['accuracy'], 2 / 3)
        with self.assertRaisesRegex(ValueError, 'class list'):
            classification_metrics(['A'], ['C'], ['A', 'B'])

    def test_scenario_b_split_reproducible(self):
        labels = pd.Series(['A'] * 50 + ['B'] * 50)
        first_train, first_test = scenario_b_split_indices(labels)
        second_train, second_test = scenario_b_split_indices(labels)
        np.testing.assert_array_equal(first_train, second_train)
        np.testing.assert_array_equal(first_test, second_test)
        self.assertEqual(pd.Series(labels.iloc[first_test]).value_counts().to_dict(),
                         {'A': 10, 'B': 10})

    @unittest.skipUnless(DATASET_ZIP.is_file(), 'Scenario B archive is not installed locally')
    def test_saved_scenario_b_accuracy_reproduces(self):
        data = load_scenario_b()
        _, test_idx = scenario_b_split_indices(data.label)
        xgb, feature_names, encoder = load_xgboost_model()
        predictions = encoder.inverse_transform(xgb.predict(
            prepare_features(data.iloc[test_idx], feature_names)).astype(int))
        metrics = classification_metrics(data.label.iloc[test_idx], predictions, encoder.classes_)
        self.assertEqual(metrics['rows'], 3752)
        self.assertAlmostEqual(metrics['accuracy'], 0.912046908315565)

    def test_real_rf_grouped_holdout_has_no_session_overlap(self):
        columns = ['source_pcap', 'label']
        data = pd.read_csv(PROJECT_ROOT / 'data' / 'training_flows.csv', usecols=columns)
        train, test, selected = session_holdout(data)
        self.assertEqual(len(selected), 5)
        self.assertEqual(set(train.label), set(test.label))
        self.assertFalse(set(train.source_pcap.map(rf_session_key)) &
                         set(test.source_pcap.map(rf_session_key)))

    def test_saved_model_feature_schema_and_label_decoding(self):
        rf_bundle = load_model()
        rf_frame = pd.read_csv(PROJECT_ROOT / 'data' / 'test_flows.csv', nrows=1)
        self.assertEqual(len(rf_bundle[2]), 61)
        self.assertTrue(set(rf_bundle[2]).issubset(rf_frame.columns))
        rf_result = predict_with_model(rf_frame, rf_bundle)
        self.assertIn(rf_result.pred_label.iloc[0], rf_bundle[0].classes_)
        xgb, xgb_features, encoder = load_xgboost_model()
        self.assertEqual(xgb_features, FEATURE_NAMES)
        self.assertEqual(len(xgb_features), 23)
        sample = pd.DataFrame(1.0, index=[0], columns=FEATURE_NAMES)
        encoded = xgb.predict(prepare_features(sample, xgb_features)).astype(int)
        self.assertIn(encoder.inverse_transform(encoded)[0], encoder.classes_)


if __name__ == '__main__':
    unittest.main()
