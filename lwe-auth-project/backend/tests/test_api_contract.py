import unittest

from fastapi.testclient import TestClient

from main import app


class ApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def test_catalog_exposes_all_candidates_and_only_complete_ones_are_available(self) -> None:
        methods = self.client.get('/api/v1/methods')
        self.assertEqual(methods.status_code, 200)
        self.assertEqual(methods.json(), {'available_methods': ['ecdsa', 'standard_lwe', 'binary_lwe', 'ring_lwe', 'lwr']})

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

    def test_lattice_http_round_trip_uses_effective_parameters(self) -> None:
        small_parameters = {
            'standard_lwe': {'n': 128, 'm': 128},
            'binary_lwe': {'n': 128, 'm': 128},
            'lwr': {'n': 128, 'm': 128},
            'ring_lwe': {'n': 256, 'kappa': 23},
        }
        for protocol_name, parameters in small_parameters.items():
            with self.subTest(protocol_name=protocol_name):
                key_response = self.client.post(
                    '/api/v1/generate_keys',
                    json={'protocol_name': protocol_name, 'parameters': parameters},
                )
                self.assertEqual(key_response.status_code, 200)
                material = key_response.json()
                self.assertEqual(
                    material['system_parameters']['parameters'],
                    material['effective_parameters'],
                )
                self.assertEqual(
                    material['effective_parameters']['proof_system'],
                    'fiat_shamir_with_aborts',
                )

                challenge = self.client.post(
                    '/api/v1/challenge',
                    json={
                        'protocol_name': protocol_name,
                        'system_parameters': material['system_parameters'],
                        'public_key': material['public_key'],
                    },
                ).json()['challenge']
                response = self.client.post(
                    '/api/v1/solve',
                    json={
                        'protocol_name': protocol_name,
                        'system_parameters': material['system_parameters'],
                        'private_key': material['private_key'],
                        'challenge': challenge,
                    },
                ).json()['response']
                verify_response = self.client.post(
                    '/api/v1/verify',
                    json={
                        'protocol_name': protocol_name,
                        'system_parameters': material['system_parameters'],
                        'public_key': material['public_key'],
                        'challenge': challenge,
                        'response': response,
                    },
                )
                self.assertEqual(verify_response.json(), {'is_valid': True})

    def test_lattice_rejects_small_challenge_space_with_400(self) -> None:
        key_response = self.client.post(
            '/api/v1/generate_keys',
            json={'protocol_name': 'standard_lwe', 'parameters': {'kappa': 5}},
        )
        self.assertEqual(key_response.status_code, 400)

if __name__ == '__main__':
    unittest.main()
