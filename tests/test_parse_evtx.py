import unittest
from scripts.parse_evtx_events import parse_events_xml, summarize_events

class TestEvtxParser(unittest.TestCase):
    def test_parse_events(self):
        sample_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <EventID>4625</EventID>
                <TimeCreated SystemTime="2026-08-05T10:00:00Z"/>
            </System>
        </Event>"""
        events = parse_events_xml(sample_xml)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], "4625")
        self.assertEqual(events[0]["description"], "Failed Logon")

    def test_summarize_events(self):
        sample_xml = """<Event><System><EventID>4624</EventID></System></Event>
                        <Event><System><EventID>4624</EventID></System></Event>
                        <Event><System><EventID>7045</EventID></System></Event>"""
        events = parse_events_xml(sample_xml)
        summary = summarize_events(events)
        self.assertEqual(summary["4624"][0], 2)
        self.assertEqual(summary["7045"][0], 1)

if __name__ == '__main__':
    unittest.main()

    def test_invalid_xml(self):
        self.assertEqual(len(parse_events_xml('invalid xml')), 0)
