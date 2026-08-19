"""A dependency-free structural check of decision_evidence.json.

Step 6 of the procedure asks the reader to confirm the record is structurally
what it claims to be. That check has to run on a machine with nothing
installed but a Python interpreter, so this implements the subset of JSON
Schema the bundled schema actually uses rather than pulling in `jsonschema`.

The subset is named in `SUPPORTED_KEYWORDS` and reported in the verifier's
output, because a validator that silently ignores a keyword it does not
implement will pass a document the schema rejects — and an auditor reading
"schema: PASS" has no way to know which keywords were consulted. If the
schema ever grows a keyword outside this set, `unsupported_keywords()` names
it and the verifier says so on the page instead of quietly under-checking.
"""

from __future__ import annotations

from typing import Any

SUPPORTED_KEYWORDS = frozenset(
    {"type", "required", "properties", "items", "enum", "description"}
)

# Keywords that are metadata for humans and carry no validation obligation.
IGNORED_KEYWORDS = frozenset(
    {"$schema", "$id", "title", "description", "x_schema_version", "x_produced_by",
     "x_every_key_is_required"}
)

_TYPES: dict[str, Any] = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "integer":
        # `bool` is an `int` in Python and `true` is not an integer in JSON.
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    python_type = _TYPES.get(expected)
    if python_type is None:
        return True  # a type this validator does not know; reported separately
    if expected == "boolean":
        return isinstance(value, bool)
    return isinstance(value, python_type)


def unsupported_keywords(schema: Any, seen: set[str] | None = None) -> set[str]:
    """Every schema keyword this validator will not enforce."""
    found = set() if seen is None else seen
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key in ("properties",):
                for sub in value.values():
                    unsupported_keywords(sub, found)
                continue
            if key == "items":
                unsupported_keywords(value, found)
                continue
            if key not in SUPPORTED_KEYWORDS and key not in IGNORED_KEYWORDS:
                found.add(key)
    return found


def validate(instance: Any, schema: dict, path: str = "$") -> list[str]:
    """Return a list of human-readable structural errors. Empty means it matched."""
    errors: list[str] = []

    expected = schema.get("type")
    if expected is not None:
        options = expected if isinstance(expected, list) else [expected]
        if not any(_type_matches(instance, option) for option in options):
            actual = "null" if instance is None else type(instance).__name__
            errors.append(f"{path}: expected {' or '.join(options)}, found {actual}")
            return errors  # every further check would be noise

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} is not one of {schema['enum']!r}")

    if isinstance(instance, dict):
        for name in schema.get("required", []):
            if name not in instance:
                errors.append(f"{path}: missing required property {name!r}")
        for name, subschema in schema.get("properties", {}).items():
            if name in instance:
                errors.extend(validate(instance[name], subschema, f"{path}.{name}"))

    if isinstance(instance, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(instance):
            errors.extend(validate(item, schema["items"], f"{path}[{index}]"))

    return errors
