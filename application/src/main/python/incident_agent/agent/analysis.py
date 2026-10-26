"""Post-investigation analysis: typed fields the user defines on the agent, filled by
the fast model after the investigation ends — like post-call analysis on a call transcript.

The "transcript" is the finished investigation: question, scope, verdict, hypotheses and
evidence summaries. The model only extracts; it cannot query anything. Values are
validated against the field definitions here, in code, and shown in the report as
"model-extracted" — separate from the verified sections.

Field definition (stored on the agent):
    {"name": "severity", "type": "enum", "values": ["SEV1", "SEV2"], "description": "..."}
    type: text | enum | boolean | number | list
"""

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, create_model

FIELD_TYPES = ("text", "enum", "boolean", "number", "list")
MAX_FIELDS = 15
NAME = re.compile(r"^[a-z][a-z0-9_]{0,39}$")


def fields_values(data: list | None) -> list[dict]:
    """Validate the agent form's analysis fields. Raises ValueError."""
    out, seen = [], set()
    for i, f in enumerate(data or [], 1):
        name = (f.get("name") or "").strip().lower()
        if not NAME.match(name):
            raise ValueError(f"analysis field {i}: name must be lowercase letters, digits and _ (max 40), e.g. 'severity'")
        if name in seen:
            raise ValueError(f"analysis field {name!r} is defined twice")
        seen.add(name)
        ftype = f.get("type") or "text"
        if ftype not in FIELD_TYPES:
            raise ValueError(f"analysis field {name!r}: type must be one of {', '.join(FIELD_TYPES)}")
        description = (f.get("description") or "").strip()
        if not description:
            raise ValueError(f"analysis field {name!r}: a description is required — it tells the model what to extract")
        if len(description) > 500:
            raise ValueError(f"analysis field {name!r}: description is longer than 500 characters")
        field = {"name": name, "type": ftype, "description": description}
        if ftype == "enum":
            values = f.get("values") or []
            if isinstance(values, str):
                values = values.split(",")
            values = list(dict.fromkeys(v.strip() for v in values if str(v).strip()))
            if not 2 <= len(values) <= 20:
                raise ValueError(f"analysis field {name!r}: an enum needs 2–20 values")
            field["values"] = values
        out.append(field)
    if len(out) > MAX_FIELDS:
        raise ValueError(f"at most {MAX_FIELDS} analysis fields")
    return out


def _value_type(f: dict):
    return {"text": str, "boolean": bool, "number": float, "list": list[str]}.get(f["type"]) or \
        Literal[tuple(f["values"])]  # type: ignore[misc]


def output_model(fields: list[dict]) -> type[BaseModel]:
    """Pydantic model the fast model must return: one {value, evidence_ids} object per field."""
    members = {}
    for f in fields:
        item = create_model(
            f"Field_{f['name']}",
            value=(_value_type(f) | None, Field(None, description="The value. null only if the investigation gives no basis at all")),
            evidence_ids=(list[str], Field(default_factory=list, description="Evidence ids that support the value")),
        )
        members[f["name"]] = (item, Field(..., description=f["description"]))
    model = create_model("InvestigationAnalysis", **members)
    model.__doc__ = "Fill every field from the investigation below. Use only what the evidence shows."
    return model


def transcript(state: dict) -> str:
    """The finished investigation as text: what the analysis model reads."""
    v, scope = state["verdict"], state["scope"]
    c = v.conclusion
    lines = [f"QUESTION: {state['question']}",
             f"SCOPE: service={scope.service} symptom={scope.symptom} since={scope.since}"
             + (f" until={scope.until}" if scope.until else ""),
             f"RESULT: {v.status} · confidence {v.confidence}"]
    if c:
        lines += [f"CONCLUSION ({c.kind}): {c.summary}", f"IMPACT: {c.impact or '-'}",
                  "RECOMMENDATIONS: " + (" | ".join(c.recommendations) or "-"),
                  f"CITED EVIDENCE: {', '.join(c.evidence_ids)}"]
    lines += [f"PROBLEMS: {p}" for p in v.problems]
    hyps = [f"  {h.id} [{h.status}] {h.statement}" for h in (state.get("hypotheses") or {}).values()]
    lines += ["", "HYPOTHESES:"] + (hyps or ["  (none)"])
    lines += ["", "EVIDENCE:"] + [f"  {e.id} {e.capability} ({e.args.get('service')}): {e.summary}"
                                  for e in state.get("evidence", [])]
    return "\n".join(lines)


def check(raw: dict, fields: list[dict], evidence_ids: set[str]) -> list[dict]:
    """Model output → report rows. Wrong types and unknown evidence ids are flagged, not trusted."""
    rows = []
    for f in fields:
        item = raw.get(f["name"]) or {}
        if not isinstance(item, dict):
            item = {"value": item}
        value: Any = item.get("value")
        cited = [str(i) for i in item.get("evidence_ids") or []]
        problems = []
        if value is not None:
            ok = {"text": isinstance(value, str), "boolean": isinstance(value, bool),
                  "number": isinstance(value, (int, float)) and not isinstance(value, bool),
                  "list": isinstance(value, list) and all(isinstance(x, str) for x in value),
                  "enum": value in f.get("values", [])}[f["type"]]
            if not ok:
                problems.append(f"invalid {f['type']} value {value!r}")
                value = None
        unknown = [i for i in cited if i not in evidence_ids]
        if unknown:
            problems.append(f"cites unknown evidence {', '.join(unknown)}")
        rows.append({"name": f["name"], "type": f["type"], "value": value,
                     "evidence_ids": [i for i in cited if i in evidence_ids], "problems": problems})
    return rows
