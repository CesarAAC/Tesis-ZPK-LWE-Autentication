import unittest

from benchmarking.assessment import ProtocolAssessment


class BenchmarkAssessmentTests(unittest.TestCase):
    def test_assessment_records_keep_dimension_criterion_value_and_evidence(self) -> None:
        assessment = ProtocolAssessment.model_validate(
            {
                "protocol_id": "ecdsa",
                "implementation": {
                    "specialized_arithmetic_required": {
                        "value": True,
                        "evidence": "test evidence",
                    }
                },
            }
        )
        self.assertEqual(
            list(assessment.records()),
            [
                (
                    "implementation",
                    "specialized_arithmetic_required",
                    True,
                    "test evidence",
                )
            ],
        )


if __name__ == "__main__":
    unittest.main()
