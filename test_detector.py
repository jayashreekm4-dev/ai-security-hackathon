import unittest
from detector import parse_line, naive_minute, sliding_rule, robust_z, read_events

def burst(ip, start, n, gap=1):
    return [(start + i * gap, ip, False) for i in range(n)]

class Tests(unittest.TestCase):
    def test_parse_rejects_malformed(self):
        for bad in ["", "garbage", "2026-10-26 10:00:00 1.2.3.4 LOGIN MAYBE",
                    "2026-13-99 10:00:00 1.2.3.4 LOGIN FAILED"]:
            self.assertIsNone(parse_line(bad))
        self.assertIsNotNone(parse_line("2026-10-26 10:00:01 192.168.1.8 LOGIN FAILED"))

    def test_boundary_split_missed_by_naive_caught_by_sliding(self):
        ev = burst("9.9.9.9", 60 * 100 + 50, 20)   # 10 failures each side of a minute edge
        self.assertEqual(naive_minute(ev), set())
        self.assertEqual(sliding_rule(ev), {"9.9.9.9"})

    def test_normal_noise_not_flagged(self):
        ev = [(i * 3.0, f"10.1.1.{i % 5}", i % 10 == 0) for i in range(300)]
        self.assertEqual(sliding_rule(ev), set())
        self.assertEqual(robust_z(ev), set())

    def test_robust_z_catches_burst(self):
        ev = [(i * 3.0, f"10.1.1.{i % 5}", i % 10 != 0) for i in range(300)] + burst("6.6.6.6", 100, 30)
        self.assertEqual(robust_z(ev), {"6.6.6.6"})

    def test_malformed_file_does_not_crash(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as f:
            f.write("junk\n\n2026-10-26 10:00:01 1.1.1.1 LOGIN FAILED\n")
        events, bad = read_events(f.name)
        os.unlink(f.name)
        self.assertEqual((len(events), bad), (1, 1))

if __name__ == "__main__":
    unittest.main()
