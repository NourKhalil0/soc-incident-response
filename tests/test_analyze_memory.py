import unittest
from scripts.analyze_memory_dump import parse_malfind_output

class TestMalfindParser(unittest.TestCase):
    def test_parsing(self):
        sample = (
            "Process: svchost.exe Pid: 1044 Address: 0x21a0000 Protection: PAGE_EXECUTE_READWRITE\n"
            "Process: explorer.exe Pid: 2420 Address: 0x7fa0000 Protection: PAGE_EXECUTE_READWRITE\n"
        )
        procs = parse_malfind_output(sample)
        self.assertEqual(len(procs), 2)
        self.assertEqual(procs[0]["process"], "svchost.exe")
        self.assertEqual(procs[0]["pid"], 1044)
        self.assertEqual(procs[1]["address"], "0x7fa0000")

if __name__ == '__main__':
    unittest.main()

    def test_empty_input(self):
        self.assertEqual(len(parse_malfind_output('')), 0)
