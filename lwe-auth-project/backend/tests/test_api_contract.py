import unittest

from fastapi.testclient import TestClient

from main import app


class ApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def test_catalog_exposes_all_candidates_but_only_ecdsa_is_available(self) -> None:
        methods = self.client.get('/api/v1/methods')
        self.assertEqual(methods.status_code, 200)
        self.assertEqual(methods.json(), {'available_methods': ['ecdsa']})

        catalog = self.client.get('/api/v1/protocols')
        self.assertEqual(catalog.status_code, 200)
        entries = catalog.json()['protocols']
        self.assertEqual(len(entries), 6)
        self.assertEqual(
            [entry['protocol_id'] for entry in entries],
            ['ecdsa', 'standard_lwe', 'binary_lwe', 'ring_lwe', 'lwr', 'proposed_lwe'],
        )

    def test_ecdsa_http_round_trip_carries_system_parameters(self) -> None:
        key_response = self.client.post(
            '/api/v1/generate_keys',
            json={'protocol_name': 'ecdsa', 'parameters': {}},
        )
        self.assertEqual(key_response.status_code, 200)
        material = key_response.json()
        self.assertEqual(material['system_parameters'], {})

        challenge_response = self.client.post(
            '/api/v1/challenge',
            json={
                'protocol_name': 'ecdsa',
                'system_parameters': material['system_parameters'],
                'public_key': material['public_key'],
            },
        )
        self.assertEqual(challenge_response.status_code, 200)
        challenge = challenge_response.json()['challenge']

        solve_response = self.client.post(
            '/api/v1/solve',
            json={
                'protocol_name': 'ecdsa',
                'system_parameters': material['system_parameters'],
                'private_key': material['private_key'],
                'challenge': challenge,
            },
        )
        self.assertEqual(solve_response.status_code, 200)
        response = solve_response.json()['response']

        verify_response = self.client.post(
            '/api/v1/verify',
            json={
                'protocol_name': 'ecdsa',
                'system_parameters': material['system_parameters'],
                'public_key': material['public_key'],
                'challenge': challenge,
                'response': response,
            },
        )
        self.assertEqual(verify_response.status_code, 200)
        self.assertEqual(verify_response.json(), {'is_valid': True})


if __name__ == '__main__':
    unittest.main()
