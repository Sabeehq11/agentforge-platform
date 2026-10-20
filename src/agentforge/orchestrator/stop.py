"""Cost-aware stop and redirect. Reads persisted counters and the ledger only, and never calls Ledger.combined.

Per segment (the first run on a category, then the one allowed redirect), the campaign stops or redirects when
zero validated signals were found and either N sequences completed or incurred plus outstanding reserved reached
the configured fraction of the effective cap. Incurred and reserved are read as two separate sums over the whole
campaign and added only for this threshold test. After the allowed redirect the same condition halts with
no_findings_in_window, retryable=false. A halt for no signal is not a pass. A $0 run still stops on the attack count.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from agentforge.orchestrator.policy import StopPolicy
from agentforge.orchestrator.state import now_iso, require_campaign
from agentforge.safety.ledger import SHARED_CEILING_USD, committed_usd


@dataclass(frozen=True)
class Spend:
    incurred_usd: float
    reserved_usd: float


@dataclass(frozen=True)
class StopDecision:
    action: str  # continue | redirect | halt
    reason: str


def campaign_spend(conn: sqlite3.Connection, correlation_id: str) -> Spend:
    """Incurred and outstanding reserved spend of this campaign, from agent_spend rows the journal opened."""
    row = conn.execute(
        """
        SELECT COALESCE(SUM(CASE WHEN s.state = 'incurred' THEN s.incurred_usd ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN s.state = 'reserved' THEN s.reserved_usd ELSE 0 END), 0)
        FROM dispatch_journal j JOIN agent_spend s ON s.call_id = j.call_id
        WHERE j.correlation_id = ?
        """,
        (correlation_id,),
    ).fetchone()
    return Spend(float(row[0]), float(row[1]))


def effective_cap(conn: sqlite3.Connection, correlation_id: str, request_cap: float) -> float:
    """The lower of the request cap and the shared ceiling left after other campaigns. The ceiling is never raised."""
    mine = campaign_spend(conn, correlation_id)
    others = committed_usd(conn) - mine.incurred_usd - mine.reserved_usd
    return max(0.0, min(request_cap, SHARED_CEILING_USD - others))


def decide(conn: sqlite3.Connection, correlation_id: str, policy: StopPolicy, request_cap: float) -> StopDecision:
    campaign = require_campaign(conn, correlation_id)
    attacks = int(campaign["attacks_done"]) - int(campaign["segment_attacks_base"])
    signals = int(campaign["signal_count"]) - int(campaign["segment_signal_base"])
    if signals > 0:
        return StopDecision("continue", "signal found")
    spend = campaign_spend(conn, correlation_id)
    used = spend.incurred_usd + spend.reserved_usd - float(campaign["segment_spend_base"])
    cap = effective_cap(conn, correlation_id, request_cap)
    by_attacks = attacks >= policy.after_attacks
    by_spend = used >= policy.spend_fraction * cap
    if not (by_attacks or by_spend):
        return StopDecision("continue", "below thresholds")
    why = f"no validated signal after {attacks} sequences and ${used:.4f} of ${cap:.4f}"
    if int(campaign["redirects"]) < policy.max_redirects:
        return StopDecision("redirect", why)
    return StopDecision("halt", why)


def apply_redirect(conn: sqlite3.Connection, correlation_id: str, category: str) -> None:
    """Move to the next category and start a fresh segment. Counts one redirect. Persisted, so a resume keeps it."""
    spend = campaign_spend(conn, correlation_id)
    with conn:
        conn.execute(
            """
            UPDATE campaigns SET current_category = ?, redirects = redirects + 1, segment_attacks_base = attacks_done,
                segment_signal_base = signal_count, segment_spend_base = ?, updated_at = ?
            WHERE correlation_id = ?
            """,
            (category, spend.incurred_usd + spend.reserved_usd, now_iso(), correlation_id),
        )
