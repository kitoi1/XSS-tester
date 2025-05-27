import unittest
from xss_tester.payloads import load_payloads

class TestPayloads(unittest.TestCase):
    def test_load_payloads(self):
        payloads = load_payloads("xss_tester/payloads/base_payloads.json")
        self.assertTrue(len(payloads) > 0)
        self.assertIn("<script>alert('XSS')</script>", payloads)

if __name__ == '__main__':
    unittest.main()

