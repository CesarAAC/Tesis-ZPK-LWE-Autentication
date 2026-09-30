import unittest

from pydantic import ValidationError

from benchmarking.security import SecurityAssessment


class BenchmarkSecurityAssessmentTests(unittest.TestCase):
    def test_security_assessment_requires_a_numeric_result(self) -> None:
        with self.assertRaises(ValidationError):
            SecurityAssessment(
                protocol_id="standard_lwe",
                assessment_type="estimator",
                tool_or_source="example-estimator",
            )

    def test_security_assessment_preserves_evidence(self) -> None:
        assessment = SecurityAssessment(
            protocol_id="standard_lwe",
            assessment_type="estimator",
            tool_or_source="example-estimator",
            tool_version="1.0",
            classical_security_bits=128.0,
            assumptions={"cost_model": "example"},
            evidence={"raw_output_file": "result.txt"},
        )
        self.assertEqual(assessment.classical_security_bits, 128.0)
        self.assertEqual(assessment.evidence["raw_output_file"], "result.txt")


if __name__ == "__main__":
    unittest.main()
