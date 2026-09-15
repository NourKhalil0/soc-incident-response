import unittest
from scripts.check_ip_reputation import check_ip_reputation

class TestIPReputation(unittest.TestCase):
    def test_missing_api_key(self):
        res = check_ip_reputation("198.51.100.1", api_key=None)
        # When no env var is set, function returns error dict
        self.assertIn("error", res)

if __name__ == '__main__':
    unittest.main()
