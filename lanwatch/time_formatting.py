"""Presentation helpers for timestamps stored as UTC instants."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


IST = ZoneInfo("Asia/Kolkata")
_DISPLAY_FORMAT = "%d %b %Y, %I:%M:%S %p %Z"


def parse_timestamp(value):
    """Parse a timestamp, treating naive legacy values consistently as UTC.

    Existing SQLite values with an explicit offset retain that instant. Older
    naive ISO values are interpreted as UTC, matching the historical writer.
    Invalid or absent values return None.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(IST)


def format_timestamp(value):
    """Format a UTC/offset timestamp for people, explicitly labelled IST."""
    parsed = parse_timestamp(value)
    return parsed.strftime(_DISPLAY_FORMAT) if parsed else "Unavailable"


def format_timestamp_record(record, fields):
    """Return a copy of a record with selected timestamp fields formatted."""
    formatted = dict(record)
    for field in fields:
        if field in formatted:
            formatted[field] = format_timestamp(formatted[field])
    return formatted
