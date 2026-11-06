import unittest
from app import app


class CyberGuardTests(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_empty_request_is_rejected(self):
        response = self.client.post("/api/scan", json={})
        self.assertEqual(response.status_code, 400)

    def test_safe_structural_url(self):
        response = self.client.post(
            "/api/scan",
            json={"url": "https://example.com/login"}
        )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["score"], 0)
        self.assertEqual(data["risk"], "Low")
        self.assertIsNone(data["ml_analysis"])

    def test_suspicious_ip_url(self):
        response = self.client.post(
            "/api/scan",
            json={"url": "http://192.168.1.100/login"}
        )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["risk"], "Medium")
        self.assertGreater(len(data["findings"]), 0)

    def test_strong_phishing_message(self):
        response = self.client.post(
            "/api/scan",
            json={
                "message": (
                    "URGENT! Your bank account is suspended. "
                    "Verify your OTP immediately."
                )
            }
        )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["risk"], "High")
        self.assertEqual(data["ml_analysis"]["prediction"], "smishing")

    def test_legitimate_message_does_not_override_url_warning(self):
        response = self.client.post(
            "/api/scan",
            json={
                "message": (
                    "Hello, your appointment is confirmed "
                    "for tomorrow at 10 AM."
                ),
                "url": "http://192.168.1.100/login"
            }
        )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["ml_analysis"]["prediction"], "ham")
        self.assertEqual(data["risk"], "Medium")

    def test_input_length_limit(self):
        response = self.client.post(
            "/api/scan",
            json={"message": "A" * 5001}
        )

        self.assertEqual(response.status_code, 400)

    def test_deceptive_url_with_at_symbol(self):
        response = self.client.post(
            "/api/scan",
            json={
                "url": "https://google.com@evil.example/login"
            }
        )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["risk"], "Medium")
        self.assertTrue(
            any(
                "@ symbol" in finding["reason"]
                for finding in data["findings"]
            )
        )
        self.assertIsNone(data["ml_analysis"])
        
if __name__ == "__main__":
    unittest.main()
