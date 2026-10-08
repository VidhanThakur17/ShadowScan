import json
import logging
import tempfile
import unittest
from pathlib import Path

from shadow_scan.ops.logging_setup import JsonFormatter, configure
from shadow_scan.ops.scheduler import generate, render


class SchedulerTests(unittest.TestCase):
    def test_windows_first_class(self):
        ex = generate("acme", python="py", base="C:/ws")
        joined = "\n".join(ex.windows)
        self.assertIn("schtasks /Create", joined)
        self.assertIn("acme", joined)
        self.assertIn("--resume", joined)    # incremental schedule resumes
        self.assertTrue(ex.cron and ex.systemd)

    def test_render_contains_all_platforms(self):
        out = render("acme")
        self.assertIn("Windows Task Scheduler", out)
        self.assertIn("cron", out)
        self.assertIn("systemd", out)


class StructuredLoggingTests(unittest.TestCase):
    def test_json_formatter_fields(self):
        rec = logging.LogRecord("x", logging.INFO, __file__, 1, "hello", None, None)
        rec.program = "acme"; rec.run_id = 7; rec.event = "run_completed"
        payload = json.loads(JsonFormatter().format(rec))
        self.assertEqual(payload["message"], "hello")
        self.assertEqual(payload["program"], "acme")
        self.assertEqual(payload["event"], "run_completed")

    def test_json_formatter_omits_absent_fields(self):
        rec = logging.LogRecord("x", logging.INFO, __file__, 1, "m", None, None)
        payload = json.loads(JsonFormatter().format(rec))
        self.assertNotIn("program", payload)

    def test_rotating_file_handler_writes_json(self):
        d = tempfile.mkdtemp()
        log = Path(d) / "logs" / "ops.jsonl"
        configure(json_output=False, log_file=log)
        logging.getLogger("shadow_scan.test").info("structured line")
        # Detach handlers so the file is closed/readable on Windows.
        for h in logging.getLogger().handlers:
            h.close()
        logging.getLogger().handlers[:] = []
        self.assertTrue(log.exists())
        line = log.read_text(encoding="utf-8").strip().splitlines()[-1]
        self.assertEqual(json.loads(line)["message"], "structured line")


if __name__ == "__main__":
    unittest.main()
