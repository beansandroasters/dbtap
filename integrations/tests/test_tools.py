import io
import json
from pathlib import Path
import tempfile
import unittest

from dbtap_tools import Stream, iter_samples, jmeter, k6


def records():
    return [
        {"type": "start", "schema": 1, "run_id": "test", "worker": 0, "workers": 1},
        {"type": "sample", "seq": 1, "conn": 1, "shape_id": "0123456789abcdef",
         "status": "ran", "request_success": False, "comparison": "Match",
         "error_code": "23505", "observed": {"duration": False},
         "timing": {"started_unix_ns": 1_500_000_000, "latency_ns": 2_000_000,
                    "lag_ns": 1_000_000, "waited_ns": 0}},
        {"type": "sample", "seq": 2, "conn": 1, "shape_id": "0123456789abcdef",
         "status": "skipped", "request_success": None, "comparison": None,
         "error_code": None, "observed": {"duration": False}, "timing": None},
        {"type": "end", "samples": 2},
    ]


class ToolsTests(unittest.TestCase):
    def test_stream_requires_complete_ordered_run(self):
        s = Stream()
        s.feed(records()[0])
        with self.assertRaises(ValueError):
            s.feed(records()[2])  # Sequence 1 is missing.
        with self.assertRaises(ValueError):
            s.finish()
        s = Stream()
        for r in records():
            s.feed(r)
        s.finish()
        with self.assertRaises(ValueError):
            s.feed(records()[-1])

    def test_formats_keep_actual_time_and_actual_error(self):
        out = io.StringIO()
        jmeter([(records()[0], r) for r in records()[1:-1]], out)
        rows = out.getvalue().splitlines()
        self.assertEqual(len(rows), 2)  # Skips are not request samples.
        self.assertIn("1500,2,", rows[1])
        self.assertIn("23505", rows[1])
        self.assertIn("false", rows[1])  # A matching comparison can still be a DB error.
        out = io.StringIO()
        k6([(records()[0], r) for r in records()[1:-1]], out)
        points = [json.loads(x) for x in out.getvalue().splitlines()]
        failure = next(x for x in points if x["type"] == "Point" and x["metric"] == "dbtap_failed")
        self.assertEqual(failure["data"]["value"], 1)
        self.assertEqual(failure["data"]["time"], "1970-01-01T00:00:01.502000000Z")
        self.assertTrue(any(x["metric"] == "dbtap_skipped" for x in points))

    def test_input_rejects_labels_and_nonfinite_times(self):
        for key, value in [("shape_id", "=CMD()"), ("timing", {"latency_ns": float("inf")})]:
            s = Stream()
            s.feed(records()[0])
            r = records()[1]
            r[key] = value
            with self.assertRaises(ValueError):
                s.feed(r)

    def test_merge_rejects_missing_or_duplicate_workers_and_truncated_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.jsonl"
            rs = records()
            rs[0]["workers"] = 2
            path.write_text("".join(json.dumps(r) + "\n" for r in rs))
            with self.assertRaisesRegex(ValueError, "missing shard"):
                list(iter_samples([path]))
            with self.assertRaisesRegex(ValueError, "duplicate shard"):
                list(iter_samples([path, path]))
            rs[0]["worker"] = 1
            second = Path(directory) / "b.jsonl"
            second.write_text("".join(json.dumps(r) + "\n" for r in rs))
            self.assertEqual(len(list(iter_samples([path, second]))), 4)
            second.write_text("".join(json.dumps(r) + "\n" for r in rs[:-1]))
            with self.assertRaisesRegex(ValueError, "incomplete"):
                list(iter_samples([path, second]))


if __name__ == "__main__":
    unittest.main()
