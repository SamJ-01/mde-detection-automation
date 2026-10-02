"""Tests for the isolation script's safety gates. No network calls are made."""

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "automation"))
import isolate_device  # noqa: E402

SAMPLE = Path(__file__).resolve().parent.parent / "automation" / "sample_alert.json"


def write_alert(tmp_path, **changes):
    alert = json.loads(SAMPLE.read_text())
    alert.update(changes)
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(alert))
    return str(path)


def test_dry_run_is_the_default(tmp_path):
    with mock.patch.object(isolate_device, "isolate") as isolate:
        assert isolate_device.main(["--alert", write_alert(tmp_path), "--approved-by", "a"]) == 0
    isolate.assert_not_called()


def test_refuses_without_an_approver(tmp_path):
    assert isolate_device.main(["--alert", write_alert(tmp_path), "--execute"]) == 1


@pytest.mark.parametrize("severity", ["Medium", "Low", "Informational"])
def test_refuses_below_high_severity(tmp_path, severity):
    alert = write_alert(tmp_path, severity=severity)
    assert isolate_device.main(["--alert", alert, "--approved-by", "a", "--execute"]) == 1


def test_refuses_alert_missing_machine_id(tmp_path):
    alert = write_alert(tmp_path, machineId="")
    assert isolate_device.main(["--alert", alert, "--approved-by", "a"]) == 1


def test_execute_calls_the_api_when_all_gates_pass(tmp_path):
    with mock.patch.object(isolate_device, "get_token", return_value="t"), \
         mock.patch.object(isolate_device, "isolate", return_value={"id": "1", "status": "Pending"}) as isolate:
        alert = write_alert(tmp_path)
        assert isolate_device.main(["--alert", alert, "--approved-by", "a", "--execute"]) == 0
    machine_id, comment, token = isolate.call_args.args
    assert token == "t" and "approved by a" in comment
