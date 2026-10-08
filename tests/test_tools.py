import unittest

from shadow_scan.recon.tools import Naabu, Nmap, Subfinder, Waybackurls
from shadow_scan.recon.tools.base import ToolResult


class FakeRunner:
    """Records invocations and returns canned output; never spawns a process."""

    def __init__(self, result: ToolResult, available: bool = True) -> None:
        self.result = result
        self.available = available
        self.calls: list[tuple[list[str], float]] = []

    def __call__(self, args, timeout):
        self.calls.append((args, timeout))
        return self.result


def adapter(cls, result, available=True, **kw):
    inst = cls(runner=FakeRunner(result), **kw)
    inst.available = lambda: available  # type: ignore[method-assign]
    return inst


class ToolAdapterTests(unittest.TestCase):
    def test_subfinder_builds_arg_array_and_parses_lines(self) -> None:
        tool = adapter(Subfinder, ToolResult(0, "api.example.com\nadmin.example.com\napi.example.com\n", ""))
        out = tool.run(["example.com", "test.com"])
        self.assertEqual(out, ["api.example.com", "admin.example.com"])  # deduped, order preserved
        args = tool._runner.calls[0][0]
        self.assertEqual(args[0], "subfinder")
        self.assertIn("-d", args)
        self.assertIn("example.com", args)

    def test_no_shell_metacharacters_are_interpreted(self) -> None:
        # A hostile "target" is passed as a single argv element, never a shell string.
        tool = adapter(Subfinder, ToolResult(0, "", ""))
        tool.run(["example.com; rm -rf /"])
        args = tool._runner.calls[0][0]
        self.assertIn("example.com; rm -rf /", args)  # intact, not split or interpreted

    def test_missing_tool_returns_empty_without_running(self) -> None:
        tool = adapter(Subfinder, ToolResult(0, "x.example.com", ""), available=False)
        self.assertEqual(tool.run(["example.com"]), [])
        self.assertEqual(tool._runner.calls, [])

    def test_timed_out_tool_uses_partial_output(self) -> None:
        tool = adapter(Subfinder, ToolResult(-1, "partial.example.com\n", "", timed_out=True))
        self.assertEqual(tool.run(["example.com"]), ["partial.example.com"])

    def test_empty_targets_short_circuits(self) -> None:
        tool = adapter(Subfinder, ToolResult(0, "x", ""))
        self.assertEqual(tool.run([]), [])
        self.assertEqual(tool._runner.calls, [])

    def test_naabu_parses_host_port(self) -> None:
        tool = adapter(Naabu, ToolResult(0, "api.example.com:443\napi.example.com:8443\n", ""), ports="443,8443")
        self.assertEqual(tool.run(["api.example.com"]), ["api.example.com:443", "api.example.com:8443"])
        self.assertIn("443,8443", tool._runner.calls[0][0])

    def test_nmap_greppable_parse(self) -> None:
        grep = ("# Nmap\n"
                "Host: 10.0.0.1 (api.example.com)\tPorts: 80/open/tcp//http//, 443/open/tcp//https//, 22/closed/tcp//ssh//\n")
        tool = adapter(Nmap, ToolResult(0, grep, ""))
        self.assertEqual(tool.run(["api.example.com"]), ["10.0.0.1:80", "10.0.0.1:443"])

    def test_waybackurls_lines(self) -> None:
        tool = adapter(Waybackurls, ToolResult(0, "https://example.com/a\nhttps://example.com/b\n", ""))
        self.assertEqual(tool.run(["example.com"]), ["https://example.com/a", "https://example.com/b"])


if __name__ == "__main__":
    unittest.main()
