import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("bench_compare", os.path.join(HERE, "bench_compare.py"))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def write(home, name, change, lower, upper):
    folder = os.path.join(home, *name.split("/"), "change")
    os.makedirs(folder)
    with open(os.path.join(folder, "estimates.json"), "w", encoding="utf-8") as f:
        json.dump({"mean": {"point_estimate": change,
                            "confidence_interval": {"lower_bound": lower, "upper_bound": upper}}}, f)


class BenchCompare(unittest.TestCase):
    def test_only_a_significant_slowdown_above_the_threshold_is_a_regression(self):
        with tempfile.TemporaryDirectory() as home:
            write(home, "pcap/parse", 0.30, 0.25, 0.35)       # 30% slower, clearly
            write(home, "diff", 0.40, -0.05, 0.85)            # 40% but the interval includes 0: noise
            write(home, "risk", 0.10, 0.05, 0.15)             # slower but under the threshold
            write(home, "targets", -0.30, -0.35, -0.25)       # faster
            rows, regressions = bench.judge(bench.collect(home), 15)
            verdict = {r[0]: r[4] for r in rows}
            self.assertEqual(verdict["pcap/parse"], "REGRESSION")
            self.assertEqual(verdict["diff"], "slower, within noise")
            self.assertEqual(verdict["risk"], "ok")
            self.assertEqual(verdict["targets"], "ok")
            self.assertEqual(len(regressions), 1)
            self.assertIn("pcap/parse", regressions[0])

    def test_no_comparison_is_not_a_failure(self):
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, "pcap", "parse", "base"))
            self.assertEqual(bench.collect(home), {})


if __name__ == "__main__":
    unittest.main()
