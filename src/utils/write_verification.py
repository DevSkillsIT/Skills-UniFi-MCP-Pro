"""Report, per field, what a write actually changed on the controller.

The UniFi controller accepts a key it does not recognise, answers
`{"meta": {"rc": "ok"}}`, and stores nothing. This has been measured on several
objects: a port forward sent with `protocol` instead of `proto` is created with
no protocol; one sent with `fwd_ip` instead of `fwd` is created with no
destination. Nothing in the response separates that from a write that landed.

The objects this server updates are large -- a WLAN carries 67 fields -- and
only a handful are named in any schema. A caller working from the schema alone
cannot know the rest are settable, and a caller guessing a field name gets
`rc: "ok"` either way. So the response has to say which of the requested fields
the controller is now actually holding.

This compares the object before and after by the keys the caller asked for.
It reads the controller rather than trusting the request, which is the only way
to tell a silent drop from a successful write.
"""

from typing import Any, Dict, Iterable, Optional

VERIFICATION_NOTE = (
    "The controller accepts unrecognised field names and answers rc=ok without storing them, "
    "so `ignored` lists fields whose value did not change after the write. A name in `ignored` "
    "is usually misspelled or not settable on this object."
)


def _comparable(value: Any) -> Any:
    """Normalise for comparison across the JSON round trip.

    Numbers frequently come back as strings (`"18091"` for a port), and lists
    can come back reordered, so a strict equality check would report a
    successful write as ignored.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        try:
            return sorted(_comparable(v) for v in value)
        except TypeError:
            return [_comparable(v) for v in value]
    if isinstance(value, dict):
        return {k: _comparable(v) for k, v in sorted(value.items())}
    return value


def verify_write(
    requested: Dict[str, Any],
    after: Optional[Dict[str, Any]],
    before: Optional[Dict[str, Any]] = None,
    ignore_keys: Iterable[str] = (),
) -> Dict[str, Any]:
    """Compare what was asked for against what the controller now holds.

    Args:
        requested: The fields the caller asked to set.
        after: The object re-read from the controller once the write returned.
        before: The object as it was, used to report what each field changed
            from. Optional; without it only the resulting value is reported.
        ignore_keys: Fields not worth reporting on, such as an id echoed back
            in the payload.

    Returns:
        `applied` maps each field the controller is holding to its value, with
        the previous value when `before` was given. `ignored` lists the fields
        the controller is not holding. `verified` is False when the object could
        not be re-read, so a caller never reads a missing check as a pass.
    """
    skip = set(ignore_keys) | {"_id", "site_id"}
    if after is None:
        return {
            "verified": False,
            "reason": "The object could not be read back, so the write could not be confirmed.",
            "applied": {},
            "ignored": [],
        }

    applied: Dict[str, Any] = {}
    ignored = []
    for field, wanted in requested.items():
        if field in skip:
            continue
        stored = after.get(field)
        if _comparable(stored) == _comparable(wanted):
            entry: Dict[str, Any] = {"value": stored}
            if before is not None and _comparable(before.get(field)) != _comparable(stored):
                entry["from"] = before.get(field)
            applied[field] = entry
        else:
            ignored.append({"field": field, "requested": wanted, "stored": stored})

    result: Dict[str, Any] = {"verified": True, "applied": applied, "ignored": ignored}
    if ignored:
        result["note"] = VERIFICATION_NOTE
    return result
