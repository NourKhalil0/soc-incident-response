import unittest
import tempfile
import os
from scripts.parse_auth_logs import parse_auth_file

class TestAuthParser(unittest.TestCase):
    def setUp(self):
        self.test_data = (
            "May 26 10:01:01 ubuntu sshd[101]: Failed password for invalid user admin from 198.51.100.22 port 42100 ssh2\n"
            "May 26 10:01:03 ubuntu sshd[102]: Failed password for invalid user admin from 198.51.100.22 port 42102 ssh2\n"
            "May 26 10:01:08 ubuntu sshd[103]: Failed password for root from 203.0.113.5 port 55123 ssh2\n"
        )
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.temp_file.write(self.test_data)
        self.temp_file.close()

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_failed_ip_counting(self):
        failed_ips, users = parse_auth_file(self.temp_file.name)
        self.assertEqual(failed_ips["198.51.100.22"], 2)
        self.assertEqual(failed_ips["203.0.113.5"], 1)
        self.assertEqual(users["admin"], 2)
        self.assertEqual(users["root"], 1)

if __name__ == '__main__':
    unittest.main()

    def test_empty_log(self):
        self.assertEqual(len(parse_auth_file(self.temp_file.name)[0]), 2)
