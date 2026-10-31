import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(os.environ.get("WD_SCRIPT_UNDER_TEST", Path(__file__).resolve().parents[1] / "firmware/network-watchdog.sh"))


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "tools").mkdir()
        (self.root / "tools/mv").symlink_to(shutil.which("mv"))

    def run_shell(self, body, interval=60):
        setup = '''
            set -- --library
            . "$WD_SCRIPT_UNDER_TEST"
            WD_LOG=$WD_TEST_ROOT/watchdog.log
            if [ -n "$WD_TEST_INTERVAL" ]; then WD_FAILURE_SECONDS=$WD_TEST_INTERVAL; fi
            wd_reboot() { printf '%s\\n' "$((WD_TICK_NOW + ${WD_CLOCK_ORIGIN:-0}))" >> "$WD_TEST_ROOT/reboots"; }
            PATH=$WD_TEST_ROOT/tools
        '''
        result = subprocess.run(
            ["sh", "-c", setup + body],
            env={**os.environ, "WD_TEST_ROOT": str(self.root), "WD_SCRIPT_UNDER_TEST": str(SCRIPT),
                 "WD_TEST_INTERVAL": "" if interval is None else str(interval)},
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def reboot_times(self):
        path = self.root / "reboots"
        return [int(x) for x in path.read_text().splitlines()] if path.exists() else []

    def test_router_reboot_and_scattered_packet_loss_do_not_reboot_camera(self):
        self.run_shell('''
            wd_prepare
            wd_tick 0 up
            wd_tick 10 down
            wd_tick 40 down
            wd_tick 50 up
            wd_tick 80 down
            wd_tick 100 up
            wd_tick 130 down
            wd_tick 140 up
        ''')
        self.assertEqual(self.reboot_times(), [])

    def test_outage_retries_at_full_intervals_until_connection_returns(self):
        self.run_shell('''
            wd_prepare
            wd_tick 10 down
            wd_tick 69 down
            wd_tick 70 down
            wd_tick 71 down
            wd_tick 129 down
            wd_tick 130 down
            wd_tick 189 down
            wd_tick 190 down
            wd_tick 200 up
            wd_tick 260 up
            wd_tick 1000 up
        ''')
        self.assertEqual(self.reboot_times(), [70, 130, 190])

    def test_production_defaults_require_ten_minutes_between_requests(self):
        self.run_shell('''
            wd_prepare
            wd_tick 0 down
            wd_tick 599 down
            wd_tick 600 down
            wd_tick 1199 down
            wd_tick 1200 down
        ''', interval=None)
        self.assertEqual(self.reboot_times(), [600, 1200])

    def test_restart_waits_a_complete_new_failure_interval(self):
        self.run_shell('''
            wd_prepare
            wd_tick 10 down
            wd_tick 70 down
        ''')
        self.run_shell('''
            WD_CLOCK_ORIGIN=75
            wd_prepare
            wd_tick 0 down
            wd_tick 59 down
            wd_tick 60 down
        ''')
        self.assertEqual(self.reboot_times(), [70, 135])

    def test_new_outage_after_recovery_gets_a_fresh_failure_timer(self):
        self.run_shell('''
            wd_prepare
            wd_tick 0 down
            wd_tick 60 down
            wd_tick 61 up
            wd_tick 62 down
            wd_tick 121 down
            wd_tick 122 down
        ''')
        self.assertEqual(self.reboot_times(), [60, 122])

    def test_failed_reboot_requests_remain_rate_limited_and_retry(self):
        self.run_shell('''
            wd_prepare
            wd_reboot() { printf '%s\\n' "$WD_TICK_NOW" >> "$WD_TEST_ROOT/reboots"; return 1; }
            wd_tick 0 down
            wd_tick 60 down
            wd_tick 61 down
            wd_tick 119 down
            wd_tick 120 down
        ''')
        self.assertEqual(self.reboot_times(), [60, 120])

    def test_main_checks_immediately_and_retries_until_a_late_reconnection(self):
        self.run_shell('''
            WD_INTERVAL=10
            now=0
            wd_now() { printf '%s\\n' "$now"; }
            wd_pause() { now=$((now + $1)); test "$now" -le 250; }
            wd_probe() {
                printf '%s\\n' "$now" >> "$WD_TEST_ROOT/probes"
                test "$now" -ge 190
            }
            wd_main
            test "$now" -eq 260
        ''')
        probes = [int(x) for x in (self.root / "probes").read_text().splitlines()]
        self.assertEqual(probes[0], 0)
        self.assertEqual(probes[-1], 250)
        self.assertEqual(self.reboot_times(), [60, 120, 180])

    def test_invalid_monotonic_clock_prevents_reboot(self):
        self.run_shell('''
            wd_now() { printf 'invalid\\n'; }
            wd_probe() { return 1; }
            if wd_main; then exit 1; fi
        ''')
        self.assertEqual(self.reboot_times(), [])

    def test_log_rotation_works_with_the_firmware_command_set(self):
        self.run_shell('''
            i=0
            while [ "$i" -lt 130 ]; do
                wd_log "event $i" || exit 1
                i=$((i + 1))
            done
        ''')
        self.assertEqual(len((self.root / "watchdog.log").read_text().splitlines()), 2)
        self.assertEqual(len((self.root / "watchdog.log.previous").read_text().splitlines()), 64)


if __name__ == "__main__":
    unittest.main()
