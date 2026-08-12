import unittest
from scripts.extract_iocs import extract_iocs_from_text, defang, is_private_ip

class TestIOCExtractor(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(defang("198.51.100.22"), "198[.]51[.]100[.]22")

    def test_private_ip_filter(self):
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.0.5"))
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertFalse(is_private_ip("198.51.100.45"))

    def test_extraction(self):
        sample = "Malware contacted 198.51.100.45 and internal gateway 192.168.1.1. SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res = extract_iocs_from_text(sample, do_defang=True)
        self.assertIn("198[.]51[.]100[.]45", res["ipv4"])
        self.assertNotIn("192.168.1.1", res["ipv4"])
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", res["sha256"])

    def test_domain_filtering(self):
        sample = "Adversary beacon connected to c2-panel.xyz and malicious-domain.top"
        res = extract_iocs_from_text(sample, do_defang=True)
        self.assertIn("c2-panel[.]xyz", res["domains"])
        self.assertIn("malicious-domain[.]top", res["domains"])

if __name__ == '__main__':
    unittest.main()
