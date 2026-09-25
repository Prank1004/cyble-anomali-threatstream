"""Persistence and concurrency regressions with synthetic checkpoint data."""

import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "source"
sys.path.insert(0, str(SOURCE))

from cyble_state import CheckpointState, STATE_KEY, poll_lock


UTC = timezone.utc
INITIAL = datetime(2024, 1, 1, tzinfo=UTC)
NOW = INITIAL + timedelta(days=2)


def state(config, **overrides):
    args = dict(config=config, scope="synthetic-scope", initial_start=INITIAL,
                window_seconds=3600, overlap_seconds=300)
    args.update(overrides)
    return CheckpointState(**args)


class CheckpointTests(unittest.TestCase):
    def test_bounded_window_is_persisted_before_completion(self):
        config = {"unrelated": {"keep": True}, "cyble_last_poll_time": "2025-01-01T00:00:00Z"}
        checkpoint = state(config)
        start, end = checkpoint.window("iocs", "created_at", NOW)
        self.assertEqual(start, "2023-12-31T23:55:00.000000Z")
        self.assertEqual(end, "2024-01-01T01:00:00.000000Z")
        self.assertEqual(checkpoint.cursor("iocs", "created_at"), INITIAL)
        self.assertEqual(config[STATE_KEY]["streams"]["iocs"]["created_at"]["pending"],
                         {"start": start, "end": end})
        self.assertEqual(config["unrelated"], {"keep": True})
        self.assertEqual(config["cyble_last_poll_time"], "2025-01-01T00:00:00Z")

    def test_restart_replays_exact_window_even_when_cutoff_and_settings_change(self):
        config = {}
        original = state(config).window("iocs", "updated_at", NOW)
        # Model a feed-config roundtrip, without holding object references.
        reloaded = json.loads(json.dumps(config))
        resumed = state(reloaded, window_seconds=7200, overlap_seconds=60)
        self.assertEqual(resumed.window("iocs", "updated_at", NOW + timedelta(days=1)), original)
        self.assertEqual(resumed.cursor("iocs", "updated_at"), INITIAL)

    def test_completion_advances_only_matching_window(self):
        config = {}
        checkpoint = state(config)
        window = checkpoint.window("iocs", "created_at", NOW)
        before = copy.deepcopy(config)
        with self.assertRaises(ValueError):
            checkpoint.complete("iocs", "created_at", "2024-01-01T02:00:00Z")
        self.assertEqual(config, before)
        checkpoint.complete("iocs", "created_at", window[1])
        self.assertEqual(checkpoint.cursor("iocs", "created_at"), INITIAL + timedelta(hours=1))
        self.assertNotIn("pending", config[STATE_KEY]["streams"]["iocs"]["created_at"])
        with self.assertRaises(ValueError):
            checkpoint.complete("iocs", "created_at", window[1])

    def test_new_services_and_date_streams_backfill_independently(self):
        config = {}
        checkpoint = state(config)
        end = checkpoint.window("iocs", "created_at", NOW)[1]
        checkpoint.complete("iocs", "created_at", end)
        self.assertEqual(checkpoint.cursor("github", "created_at"), INITIAL)
        self.assertEqual(checkpoint.cursor("iocs", "updated_at"), INITIAL)
        self.assertEqual(checkpoint.cursor("iocs", "created_at"), INITIAL + timedelta(hours=1))

    def test_shrink_preserves_cursor_start_and_replays_smaller_window(self):
        config = {}
        checkpoint = state(config)
        start, original_end = checkpoint.window("iocs", "created_at", NOW)
        self.assertTrue(checkpoint.shrink_window("iocs", "created_at"))
        smaller = checkpoint.window("iocs", "created_at", NOW)
        self.assertEqual(smaller, (start, "2024-01-01T00:30:00.000000Z"))
        self.assertEqual(checkpoint.cursor("iocs", "created_at"), INITIAL)
        with self.assertRaises(ValueError):
            checkpoint.complete("iocs", "created_at", original_end)
        self.assertEqual(state(json.loads(json.dumps(config))).window("iocs", "created_at", NOW), smaller)
        while checkpoint.shrink_window("iocs", "created_at", min_seconds=60):
            self.assertEqual(checkpoint.cursor("iocs", "created_at"), INITIAL)
        self.assertEqual(checkpoint.window("iocs", "created_at", NOW),
                         (start, "2024-01-01T00:01:00.000000Z"))
        checkpoint.complete("iocs", "created_at", "2024-01-01T00:01:00Z")
        self.assertFalse(checkpoint.shrink_window("iocs", "created_at"))

    def test_last_partial_window_ends_at_cutoff(self):
        checkpoint = state({})
        cutoff = INITIAL + timedelta(minutes=20)
        window = checkpoint.window("iocs", "created_at", cutoff)
        self.assertEqual(window[1], "2024-01-01T00:20:00.000000Z")
        checkpoint.complete("iocs", "created_at", window[1])
        self.assertIsNone(checkpoint.window("iocs", "created_at", cutoff))

    def test_scope_mismatch_does_not_mutate_configuration(self):
        config = {}
        state(config).window("iocs", "created_at", NOW)
        before = copy.deepcopy(config)
        with self.assertRaises(ValueError):
            state(config, scope="another-synthetic-scope")
        self.assertEqual(config, before)

    def test_rejects_invalid_stored_state_shapes(self):
        good = {}
        state(good).window("iocs", "created_at", NOW)
        variants = [None, [], {"version": True, "scope": "synthetic-scope", "streams": {}},
                    {"version": 1, "scope": "synthetic-scope", "streams": []}]
        for bad_stream in ({"cursor": "not-a-date"}, {"cursor": "2024-01-01T00:00:00"},
                           {"cursor": "2024-01-01T04:00:00+04:00"},
                           {"cursor": "2024-01-01T00:00:00Z", "pending": None}):
            variant = copy.deepcopy(good[STATE_KEY])
            variant["streams"]["iocs"]["created_at"] = bad_stream
            variants.append(variant)
        for variant in variants:
            config = {STATE_KEY: variant}
            before = copy.deepcopy(config)
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                state(config)
            self.assertEqual(config, before)

    def test_rejects_pending_window_out_of_order(self):
        for start, end in (("2024-01-01T00:05:00Z", "2024-01-01T01:00:00Z"),
                           ("2023-12-31T23:55:00Z", "2024-01-01T00:00:00Z"),
                           ("2020-01-01T00:00:00Z", "2024-01-01T01:00:00Z")):
            config = {}
            state(config).window("iocs", "created_at", NOW)
            config[STATE_KEY]["streams"]["iocs"]["created_at"]["pending"] = {"start": start, "end": end}
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                state(config)

    def test_rejects_future_cursor_and_cutoff(self):
        future = datetime.now(UTC) + timedelta(days=1)
        with self.assertRaises(ValueError):
            state({}, initial_start=future)
        checkpoint = state({})
        with self.assertRaises(ValueError):
            checkpoint.window("iocs", "created_at", future)
        config = {}
        state(config).cursor("iocs", "created_at")
        config[STATE_KEY]["streams"]["iocs"]["created_at"]["cursor"] = future.isoformat()
        with self.assertRaises(ValueError):
            state(config)

    def test_rejects_clock_regression_and_invalid_input_settings(self):
        checkpoint = state({})
        with self.assertRaises(ValueError):
            checkpoint.window("iocs", "created_at", INITIAL - timedelta(seconds=1))
        checkpoint.window("iocs", "created_at", NOW)
        with self.assertRaises(ValueError):
            checkpoint.window("iocs", "created_at", INITIAL + timedelta(minutes=10))
        for changes in ({"window_seconds": 0}, {"window_seconds": True},
                        {"overlap_seconds": -1}, {"overlap_seconds": 367 * 86400},
                        {"initial_start": datetime(2024, 1, 1)}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                state({}, **changes)


@unittest.skipUnless(os.name == "posix", "POSIX flock is required")
class PollLockTests(unittest.TestCase):
    def test_rejects_concurrent_lock_and_releases_without_unlink(self):
        with tempfile.TemporaryDirectory() as directory:
            with poll_lock("synthetic-feed", directory):
                paths = list(Path(directory).iterdir())
                self.assertEqual(len(paths), 1)
                inode = paths[0].stat().st_ino
                self.assertEqual(stat.S_IMODE(paths[0].stat().st_mode), 0o600)
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    with poll_lock("synthetic-feed", directory):
                        self.fail("Concurrent lock was acquired")
            self.assertEqual(paths[0].stat().st_ino, inode)
            with poll_lock("synthetic-feed", directory):
                self.assertEqual(paths[0].stat().st_ino, inode)

    def test_lock_is_exclusive_across_processes(self):
        child_code = (
            "import sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from cyble_state import poll_lock\n"
            "try:\n"
            "    with poll_lock('synthetic-feed', sys.argv[2]):\n"
            "        sys.exit(2)\n"
            "except RuntimeError:\n"
            "    sys.exit(0)\n"
        )
        with tempfile.TemporaryDirectory() as directory, poll_lock("synthetic-feed", directory):
            result = subprocess.run([sys.executable, "-c", child_code, str(SOURCE), directory],
                                    check=False, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_distinct_feeds_can_run_and_body_exceptions_propagate(self):
        with tempfile.TemporaryDirectory() as directory:
            with poll_lock("first-synthetic-feed", directory), poll_lock("second-synthetic-feed", directory):
                self.assertEqual(len(list(Path(directory).iterdir())), 2)
            with self.assertRaisesRegex(OSError, "synthetic-poll-failure"):
                with poll_lock("first-synthetic-feed", directory):
                    raise OSError("synthetic-poll-failure")
            with poll_lock("first-synthetic-feed", directory):
                pass

    def test_environment_override_creates_private_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = str(Path(parent) / "locks")
            with patch.dict(os.environ, {"CYBLE_LOCK_DIR": directory}), poll_lock("synthetic-feed"):
                self.assertEqual(stat.S_IMODE(os.stat(directory).st_mode), 0o700)

    def test_rejects_symlink_directory_and_lockfile(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent) / "locks"
            directory.mkdir(mode=0o700)
            link = Path(parent) / "link"
            link.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                with poll_lock("synthetic-feed", str(link)):
                    pass
            target = Path(parent) / "target"
            target.write_text("unchanged", encoding="utf-8")
            name = hashlib.sha256(b"synthetic-feed").hexdigest() + ".lock"
            (directory / name).symlink_to(target)
            with self.assertRaises(RuntimeError):
                with poll_lock("synthetic-feed", str(directory)):
                    pass
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")

    def test_rejects_nonprivate_directory_without_leaking_path(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o755)
            with self.assertRaises(RuntimeError) as caught:
                with poll_lock("synthetic-feed", directory):
                    pass
            self.assertNotIn(directory, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
