import unittest

from benchmarking.serialization import canonical_json_bytes, serialized_size_bytes


class BenchmarkSerializationTests(unittest.TestCase):
    def test_canonical_serialization_is_independent_of_dict_order(self) -> None:
        left = {"b": 2, "a": 1}
        right = {"a": 1, "b": 2}
        self.assertEqual(canonical_json_bytes(left), canonical_json_bytes(right))

    def test_size_is_utf8_wire_size(self) -> None:
        value = {"text": "á"}
        self.assertEqual(serialized_size_bytes(value), len(canonical_json_bytes(value)))


if __name__ == "__main__":
    unittest.main()
