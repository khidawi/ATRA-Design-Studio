"""
The behavioural contract schema of the ASTRA specification (Appendix A, JSON Schema draft 2020-12), and a validator for exactly the keywords it uses.

The schema is kept word for word in schemas/behavioural-contract-0.1.json. The validator is small on purpose: it supports type, properties, required, additionalProperties,
items, enum, pattern, minItems, minLength and format (email, date), and it REFUSES a schema that uses any other keyword, so a change to the schema cannot be silently ignored.
No dependency is added for this.

    errors = validate(document)        # [] when the document is a valid behavioural contract; otherwise one readable line per problem, with the path
"""
import json
import re
from datetime import date
from pathlib import Path
from typing import Any, Dict, List

SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "behavioural-contract-0.1.json"
IGNORED = {"$schema", "$id", "title"}
KNOWN = IGNORED | {"type", "properties", "required", "additionalProperties", "items", "enum", "pattern", "minItems", "minLength", "format"}
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def load_schema() -> Dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _type_ok(value: Any, t: str) -> bool:
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise ValueError(f"unsupported type {t!r} in the schema")


def _check(value: Any, schema: Dict[str, Any], path: str, out: List[str]) -> None:
    unknown = set(schema) - KNOWN
    if unknown:
        raise ValueError(f"the validator does not support schema keyword(s) {sorted(unknown)} at {path or '/'}")
    here = path or "/"
    if "type" in schema and not _type_ok(value, schema["type"]):
        out.append(f"{here}: must be {schema['type']}")
        return
    if "enum" in schema and value not in schema["enum"]:
        out.append(f"{here}: must be one of {', '.join(map(str, schema['enum']))}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            out.append(f"{here}: must not be empty" if schema["minLength"] == 1 else f"{here}: must have at least {schema['minLength']} characters")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            out.append(f"{here}: {value!r} does not match {schema['pattern']}")
        fmt = schema.get("format")
        if fmt == "email" and not EMAIL.match(value):
            out.append(f"{here}: {value!r} is not an email address")
        elif fmt == "date":
            try:
                date.fromisoformat(value)
            except ValueError:
                out.append(f"{here}: {value!r} is not a date (YYYY-MM-DD)")
        elif fmt not in (None, "email", "date"):
            raise ValueError(f"unsupported format {fmt!r} in the schema")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            out.append(f"{here}: needs at least {schema['minItems']} item(s)")
        if "items" in schema:
            for i, v in enumerate(value):
                _check(v, schema["items"], f"{path}/{i}", out)
    if isinstance(value, dict):
        for k in schema.get("required", []):
            if k not in value:
                out.append(f"{here}: missing required field {k!r}")
        props = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for k, v in value.items():
            if k in props:
                _check(v, props[k], f"{path}/{k}", out)
            elif extra is False:
                out.append(f"{path}/{k}: not allowed here")
            elif isinstance(extra, dict):
                _check(v, extra, f"{path}/{k}", out)


def validate(document: Any, schema: Dict[str, Any] = None) -> List[str]:
    out: List[str] = []
    _check(document, schema or load_schema(), "", out)
    return out
