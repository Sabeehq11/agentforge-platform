#!/usr/bin/env python3
"""Recompute X-6 projections and compare Docs/cost/unit-costs.json to the local spend ledger.

The checker opens the ledger read-only. It does not insert, update, or delete a row, and it does not
call a provider. ledger_state and ledger_usd must match agent_spend. provider_charge_usd is a verified
provider bill and may be null. A reservation written as incurred, and an inferred settle_orphan, stay
out of the verified-charge sum. The $0.05 target projection stays reservation-based.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "Docs" / "cost" / "unit-costs.json"
LEDGER = ROOT / "data" / "agentforge.sqlite3"
SCALES = (100, 1_000, 10_000, 100_000)
LEDGER_INCURRED = 0.1522038
VERIFIED_PROVIDER = 0.0019128
INFERRED = 0.000291
RESERVATION_WRITTEN_AS_INCURRED = 0.1500
ROUNDED = 0.1522


def load() -> dict[str, object]:
    return json.loads(PATH.read_text(encoding="utf-8"))


def ledger_rows() -> list[tuple[str, str, float]]:
    """Read every spend row. mode=ro refuses a write if one is attempted."""
    if not LEDGER.is_file():
        raise FileNotFoundError(LEDGER)
    uri = f"file:{LEDGER}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        return [
            (str(call_id), str(state), float(incurred))
            for call_id, state, incurred in conn.execute(
                "SELECT call_id, state, incurred_usd FROM agent_spend ORDER BY rowid"
            )
        ]


def reconcile(data: dict[str, object], stored: list[tuple[str, str, float]]) -> list[str]:
    problems: list[str] = []
    rows = data.get("rows")
    if not isinstance(rows, list):
        return ["rows missing"]
    ids = [row.get("call_id") for row in rows if isinstance(row, dict)]
    if len(ids) != len(set(ids)):
        problems.append("a call_id is repeated")
    if [row[0] for row in stored] != ids:
        problems.append("analysis call ids do not match the ledger, in order")
    ledger_sum = 0.0
    verified = 0.0
    inferred = 0.0
    reserved_as_incurred = 0.0
    for row, stored_row in zip(rows, stored):
        if not isinstance(row, dict):
            problems.append("a row is not an object")
            continue
        call_id, state, incurred = stored_row
        if row.get("call_id") != call_id or row.get("ledger_state") != state:
            problems.append(f"{call_id} state does not match the ledger")
        if abs(float(row.get("ledger_usd", -1)) - incurred) > 1e-9:
            problems.append(f"{call_id} amount does not match the ledger")
        charge = row.get("provider_charge_usd")
        basis = row.get("projection_basis")
        ledger_sum += float(row.get("ledger_usd", 0))
        if charge is None:
            if basis == "reservation":
                reserved_as_incurred += float(row["ledger_usd"])
            elif basis == "inferred":
                inferred += float(row["ledger_usd"])
            else:
                problems.append(f"{call_id} has no verified charge and no reservation or inferred basis")
        else:
            if abs(float(charge) - incurred) > 1e-9:
                problems.append(f"{call_id} verified charge does not match the ledger amount")
            verified += float(charge)
            if basis == "inferred":
                problems.append(f"{call_id} is both verified and inferred")
    if abs(ledger_sum - LEDGER_INCURRED) > 1e-9:
        problems.append(f"ledger incurred {ledger_sum} != {LEDGER_INCURRED}")
    if abs(verified - VERIFIED_PROVIDER) > 1e-9:
        problems.append(f"verified provider {verified} != {VERIFIED_PROVIDER}")
    if abs(inferred - INFERRED) > 1e-9:
        problems.append(f"inferred {inferred} != {INFERRED}")
    if abs(reserved_as_incurred - RESERVATION_WRITTEN_AS_INCURRED) > 1e-9:
        problems.append("reservation written as incurred does not equal 0.1500")
    if abs(verified + inferred + reserved_as_incurred - ledger_sum) > 1e-9:
        problems.append("verified, inferred, and reservation amounts do not add to the ledger once")
    if data.get("log_total_rounded_usd") != ROUNDED:
        problems.append("rounded log total was changed")
    units = data.get("units")
    if not isinstance(units, dict):
        problems.append("units missing")
        return problems
    target = units.get("target_chat")
    if not isinstance(target, dict) or target.get("basis") != "reservation" or target.get("usd") != 0.05:
        problems.append("target unit is not a 0.05 reservation")
    if units.get("red_team_call", {}).get("basis") != "incurred_sample":
        problems.append("red team unit is not an incurred sample")
    if units.get("judge_call", {}).get("basis") != "incurred_sample":
        problems.append("judge unit is not an incurred sample")
    if any(
        row.get("call_id") == "probe-judge-a6b9e5ffc3f3" and row.get("projection_basis") != "inferred"
        for row in rows
        if isinstance(row, dict)
    ):
        problems.append("orphan is not inferred exactly once")
    return problems


def project(data: dict[str, object]) -> dict[str, object]:
    units = data["units"]
    assert isinstance(units, dict)
    target = float(units["target_chat"]["usd"])
    red = float(units["red_team_call"]["usd"])
    judge = float(units["judge_call"]["usd"])
    shapes: dict[str, dict[str, float]] = {}
    for scale in SCALES:
        shapes[str(scale)] = {
            "reservation_based_target_usd": round(target * scale, 6),
            "verified_provider_sample_usd": round((red + judge) * scale, 6),
        }
    return {
        "basis": "reservation-based target; verified provider samples kept separate; inferred orphan excluded",
        "scales": shapes,
    }


def main() -> int:
    try:
        stored = ledger_rows()
    except (FileNotFoundError, sqlite3.Error) as exc:
        print(f"ledger unreadable: {exc}")
        return 1
    problems = reconcile(load(), stored)
    if problems:
        print("\n".join(problems))
        return 1
    print(json.dumps(project(load()), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
