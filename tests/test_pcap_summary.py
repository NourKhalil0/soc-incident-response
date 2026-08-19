import unittest
from scripts.summarize_pcap_conversations import calculate_shannon_entropy, is_suspicious_domain

class TestDGAAnalyzer(unittest.TestCase):
    def test_legitimate_domain(self):
        self.assertFalse(is_suspicious_domain("google.com"))
        self.assertFalse(is_suspicious_domain("microsoft.com"))

    def test_high_entropy_dga_domain(self):
        dga = "xkw98a7zp1q2b4c8m3.evilcorp.biz"
        self.assertTrue(is_suspicious_domain(dga, threshold=3.2))

    def test_short_domain_not_flagged(self):
        self.assertFalse(is_suspicious_domain("abc.com"))

if __name__ == '__main__':
    unittest.main()
