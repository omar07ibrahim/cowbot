from __future__ import annotations

import unittest

from cowbot.contracts import ValidationError
from cowbot.scenario import (
    DeterministicNoise,
    queue_saturation,
    queue_saturation_control,
)


class ScenarioTests(unittest.TestCase):
    def test_noise_sequence_is_seeded_and_bounded(self) -> None:
        first = DeterministicNoise(42)
        second = DeterministicNoise(42)

        left = [first.normalish() for _ in range(20)]
        right = [second.normalish() for _ in range(20)]

        self.assertEqual(left, right)
        self.assertTrue(all(-6.0 <= value < 6.0 for value in left))

    def test_scenario_is_reproducible_and_localizes_truth(self) -> None:
        first_schema, first_samples, first_truth = queue_saturation(
            samples=96,
            onset_index=64,
            seed=7,
        )
        second_schema, second_samples, second_truth = queue_saturation(
            samples=96,
            onset_index=64,
            seed=7,
        )

        self.assertEqual(first_schema, second_schema)
        self.assertEqual(list(first_samples), list(second_samples))
        self.assertEqual(first_truth, second_truth)
        self.assertEqual(first_truth.root_metric, "worker_cpu")

    def test_incident_changes_root_before_downstream_response(self) -> None:
        _, samples, truth = queue_saturation(
            samples=96,
            onset_index=64,
            seed=11,
        )
        rows = list(samples)

        cpu_jump = (
            rows[truth.onset_index].values["worker_cpu"]
            - rows[truth.onset_index - 1].values["worker_cpu"]
        )
        self.assertGreater(cpu_jump, 0.15)
        self.assertLess(
            rows[truth.onset_index].values["queue_depth"],
            rows[truth.onset_index + 4].values["queue_depth"],
        )

    def test_paired_control_is_reproducible_and_truth_repr_redacts_seed(
        self,
    ) -> None:
        for seed in (13, 20260725):
            with self.subTest(seed=seed):
                first_schema, first_samples, first_truth = queue_saturation_control(
                    samples=96,
                    seed=seed,
                )
                second_schema, second_samples, second_truth = queue_saturation_control(
                    samples=96,
                    seed=seed,
                )
                _, _, incident_truth = queue_saturation(
                    samples=96,
                    onset_index=64,
                    seed=seed,
                )

                self.assertEqual(first_schema, second_schema)
                self.assertEqual(list(first_samples), list(second_samples))
                self.assertEqual(first_truth, second_truth)
                self.assertEqual(first_truth.scenario, "queue-saturation-control")
                self.assertNotIn(str(seed), repr(first_truth))
                self.assertNotIn(str(seed), repr(incident_truth))
                self.assertIn("seed='<redacted>'", repr(first_truth))
                self.assertIn("seed='<redacted>'", repr(incident_truth))

    def test_paired_arms_share_every_pre_injection_sample(self) -> None:
        incident_schema, incident_samples, _ = queue_saturation(
            samples=96,
            onset_index=64,
            seed=13,
        )
        control_schema, control_samples, _ = queue_saturation_control(
            samples=96,
            seed=13,
        )
        incident_rows = list(incident_samples)
        control_rows = list(control_samples)

        self.assertEqual(incident_schema, control_schema)
        self.assertEqual(incident_rows[:64], control_rows[:64])
        self.assertAlmostEqual(
            incident_rows[64].values["worker_cpu"]
            - control_rows[64].values["worker_cpu"],
            0.235,
        )
        self.assertNotEqual(incident_rows[64:], control_rows[64:])

    def test_invalid_control_inputs_are_rejected(self) -> None:
        for arguments in (
            {"samples": 31},
            {"samples": True},
            {"samples": 40, "seed": -1},
            {"samples": 40, "seed": True},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValidationError):
                queue_saturation_control(**arguments)

    def test_invalid_boundaries_are_rejected(self) -> None:
        for arguments in (
            {"samples": 31, "onset_index": 16},
            {"samples": 40, "onset_index": 15},
            {"samples": 40, "onset_index": 40},
            {"samples": 40, "onset_index": 20, "seed": -1},
            {"samples": 40, "onset_index": 20, "seed": True},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValidationError):
                queue_saturation(**arguments)


if __name__ == "__main__":
    unittest.main()
