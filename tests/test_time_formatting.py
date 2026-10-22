from datetime import datetime, timezone

from lanwatch.time_formatting import format_timestamp, format_timestamp_record, parse_timestamp


def test_utc_datetime_and_iso_formats_convert_to_ist_and_preserve_instant():
    utc = datetime(2026, 10, 22, 14, 54, 51, tzinfo=timezone.utc)
    expected = datetime(2026, 10, 22, 20, 24, 51)

    converted_datetime = parse_timestamp(utc)
    converted_z = parse_timestamp("2026-10-22T14:54:51Z")
    converted_offset = parse_timestamp("2026-10-22T14:54:51+00:00")

    assert converted_datetime.replace(tzinfo=None) == expected
    assert converted_z == converted_datetime == converted_offset
    assert converted_datetime.utcoffset().total_seconds() == 5.5 * 60 * 60
    assert format_timestamp("2026-10-22T14:54:51Z") == "22 Oct 2026, 08:24:51 PM IST"


def test_kolkata_offset_does_not_change_between_winter_and_summer():
    winter = parse_timestamp("2026-01-15T12:00:00Z")
    summer = parse_timestamp("2026-07-15T12:00:00Z")
    assert winter.utcoffset() == summer.utcoffset()
    assert format_timestamp("2026-01-15T12:00:00Z").endswith("05:30:00 PM IST")
    assert format_timestamp("2026-07-15T12:00:00Z").endswith("05:30:00 PM IST")


def test_naive_legacy_values_are_interpreted_as_utc():
    parsed = parse_timestamp("2026-10-22T14:54:51")
    assert parsed.isoformat() == "2026-10-22T20:24:51+05:30"


def test_missing_and_invalid_timestamp_values_are_safe():
    for value in (None, "", "not a timestamp", object()):
        assert parse_timestamp(value) is None
        assert format_timestamp(value) == "Unavailable"


def test_monitoring_and_history_record_formatting_is_non_mutating():
    monitor_event = {"time": "2026-10-22T14:54:51+00:00", "kind": "newly_observed"}
    history = {"started": "2026-10-22T14:00:00Z", "finished": None, "status": "success"}

    display_event = format_timestamp_record(monitor_event, ("time",))
    display_history = format_timestamp_record(history, ("started", "finished"))

    assert display_event["time"] == "22 Oct 2026, 08:24:51 PM IST"
    assert monitor_event["time"].endswith("+00:00")
    assert display_history["started"] == "22 Oct 2026, 07:30:00 PM IST"
    assert display_history["finished"] == "Unavailable"
    assert history["started"].endswith("Z")
