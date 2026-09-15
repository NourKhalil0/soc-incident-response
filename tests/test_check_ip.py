import unittest
import unittest.mock
from scripts.check_ip_reputation import check_ip_reputation

class TestIPReputation(unittest.TestCase):
    def test_missing_api_key(self):
        res = check_ip_reputation("198.51.100.1", api_key=None)
        self.assertIn("error", res)

    @unittest.mock.patch("urllib.request.urlopen")
    def test_mock_api(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection timed out")
        res = check_ip_reputation("198.51.100.1", api_key="dummy_token")
        self.assertIn("error", res)
        self.assertIn("Connection timed out", res["error"])

if __name__ == '__main__':
    unittest.main()
