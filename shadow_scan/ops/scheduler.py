"""Generate example scheduler commands for continuous operation.

ShadowScan does not run a fragile always-on daemon. Instead it is invoked on a
schedule by the OS scheduler. This module emits ready-to-use example commands
for Windows Task Scheduler (first-class), cron, and systemd timers. Each
invocation is a single bounded ``shadowscan run`` protected by the program run
lock, so overlapping schedules cannot collide.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScheduleExamples:
    windows: list[str]
    cron: list[str]
    systemd: list[str]


def generate(program: str, *, python: str = "python", base: str | None = None) -> ScheduleExamples:
    base_arg = f" --base {base}" if base else ""
    run = f'{python} -m shadow_scan run {program}{base_arg}'
    run_resume = f'{python} -m shadow_scan run {program}{base_arg} --resume'

    windows = [
        "# Windows Task Scheduler (run as the current user; adjust /ST start time).",
        "# Monitor-style incremental run every 4 hours:",
        f'schtasks /Create /TN "ShadowScan\\{program}-monitor" /SC HOURLY /MO 4 '
        f'/TR "{run_resume}" /RL LIMITED /F',
        "# Full run daily at 03:30:",
        f'schtasks /Create /TN "ShadowScan\\{program}-daily" /SC DAILY /ST 03:30 '
        f'/TR "{run}" /RL LIMITED /F',
        "# Run once now to verify:",
        f'schtasks /Run /TN "ShadowScan\\{program}-daily"',
        "# Remove:",
        f'schtasks /Delete /TN "ShadowScan\\{program}-daily" /F',
    ]
    cron = [
        "# crontab -e  (incremental every 4h, full run daily at 03:30)",
        f'0 */4 * * *  cd /path/to/shadowscan && {run_resume} >> runtime/{program}/logs/cron.log 2>&1',
        f'30 3 * * *   cd /path/to/shadowscan && {run} >> runtime/{program}/logs/cron.log 2>&1',
    ]
    systemd = [
        f"# /etc/systemd/system/shadowscan-{program}.service",
        "[Unit]\nDescription=ShadowScan run for " + program,
        "[Service]\nType=oneshot\nWorkingDirectory=/path/to/shadowscan\n"
        f"ExecStart=/usr/bin/env {run}",
        f"# /etc/systemd/system/shadowscan-{program}.timer",
        "[Unit]\nDescription=ShadowScan schedule for " + program,
        "[Timer]\nOnCalendar=*-*-* 03:30:00\nPersistent=true\n\n[Install]\nWantedBy=timers.target",
        f"# systemctl enable --now shadowscan-{program}.timer",
    ]
    return ScheduleExamples(windows, cron, systemd)


def render(program: str, *, python: str = "python", base: str | None = None) -> str:
    ex = generate(program, python=python, base=base)
    out = ["# ShadowScan scheduling examples", "",
           "## Windows Task Scheduler (first-class)", *ex.windows, "",
           "## cron", *ex.cron, "",
           "## systemd timer", *ex.systemd]
    return "\n".join(out)
