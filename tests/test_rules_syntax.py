import unittest
import os

class TestRulesSyntax(unittest.TestCase):
    def test_rules_presence(self):
        rules_dir = os.path.join(os.path.dirname(__file__), '..', 'rules')
        if os.path.exists(rules_dir):
            files = [f for f in os.listdir(rules_dir) if f.endswith('.yml')]
            self.assertGreater(len(files), 0)

if __name__ == '__main__':
    unittest.main()
