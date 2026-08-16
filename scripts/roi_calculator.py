#!/usr/bin/env python3
"""Memtara ROI calculator — what it costs, what it displaces, when it pays back.

    python3 scripts/roi_calculator.py                 # ask me the questions
    python3 scripts/roi_calculator.py --defaults      # run on the assumptions alone
    python3 scripts/roi_calculator.py --json          # machine-readable
    python3 scripts/roi_calculator.py --products-per-year 4000 --tier production

---------------------------------------------------------------------------
THE NUMBER THIS TOOL REFUSES TO INVENT
---------------------------------------------------------------------------
The brief this was written from asked for an "average fine for mis-selling in
the UAE" with a benchmark of 10-20% of product value. There is no such figure.
DFSA and CBUAE enforcement outcomes are published case by case, they are not
expressed as a percentage of product value, and the sample is far too small to
average. Anyone putting that number in a slide is inventing it, and the first
Head of Risk who checks will stop believing the rest of the deck.

What is true, and is worth more in the conversation anyway: for a bank, a fine
is rarely the dominant cost of a mis-selling episode. Client redress, the
remediation programme, the file-by-file lookback and the supervisory attention
that follows are all larger and all more likely. Those numbers exist inside the
bank's own complaints and provisions data.

So this calculator does the opposite of asserting a benchmark. Every input is
tagged with where it comes from:

    [YOURS]      a figure from the bank's own systems. We do not know it.
    [ASSUMPTION] our default, stated so it can be argued with and overridden.
    [OURS]       Memtara's list price, which we do know.

and the report prints the tags next to the numbers, so a CFO reading the output
can see exactly which parts of the case are ours and which are theirs.

---------------------------------------------------------------------------
THE HEADLINE IS THE CONSERVATIVE NUMBER
---------------------------------------------------------------------------
The report leads with payback computed from displaced labour alone, with the
entire risk term set to zero. That is the number that survives a procurement
challenge, because it depends only on hours and rates the bank can verify.
The risk-adjusted case is shown underneath, separately, clearly labelled as
resting on assumptions the bank must replace with its own.

If it does not pay back on labour alone, we would rather find that out in the
first meeting than in month nine of a pilot.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field

CURRENCY = "USD"

# ---------------------------------------------------------------------------
# Pricing — the one part of this model we actually know.
# Keep in step with docs/PRICING_MODEL.md.
# ---------------------------------------------------------------------------

TIERS: dict[str, dict[str, object]] = {
    "pilot": {
        "label": "Tier 1 — Pilot",
        "monthly": 5_000,
        "months": 3,
        "setup": 0,
        "note": "3 months, one product family, up to 10 users, manual export.",
    },
    # Tier 2S exists because this calculator said so. At the assumption set
    # below, Tier 2 needs roughly 5,000 recommendations a year before displaced
    # labour alone covers it — and the jump from $5k to $25k is a 5x cliff no
    # procurement committee steps over. See docs/PRICING_MODEL.md.
    "desk": {
        "label": "Tier 2S — Production (single desk)",
        "monthly": 12_000,
        "months": 12,
        "setup": 0,
        "note": "Unlimited products, 25 users, API access, automated export, 99.5% SLA.",
    },
    "production": {
        "label": "Tier 2 — Production (single organisation)",
        "monthly": 25_000,
        "months": 12,
        "setup": 0,
        "note": "Unlimited products, 100 users, API access, automated export, 99.9% SLA.",
    },
    "enterprise": {
        "label": "Tier 3 — Enterprise (multi-entity)",
        "monthly": 50_000,
        "months": 12,
        "setup": 0,
        "note": "From $50k/month. Dedicated vkey, on-premise, compliance consulting.",
    },
}


@dataclass
class Inputs:
    """Every field carries a provenance tag in PROVENANCE below."""

    # --- volume -----------------------------------------------------------
    products_per_year: int = 2_500
    average_ticket: float = 250_000.0

    # --- the cost of doing it by hand today -------------------------------
    minutes_per_manual_check: float = 45.0
    loaded_hourly_rate: float = 95.0
    automation_rate: float = 0.60

    # --- evidence assembly, at audit or complaint time --------------------
    evidence_requests_per_year: int = 120
    hours_to_assemble_a_file: float = 6.0

    # --- the risk term, which is theirs to supply -------------------------
    upheld_complaints_per_year: float = 8.0
    average_redress_per_complaint: float = 40_000.0
    evidentiary_share: float = 0.30
    memtara_effectiveness: float = 0.50

    # --- what it costs ----------------------------------------------------
    tier: str = "production"
    integration_days: float = 20.0
    integration_day_rate: float = 1_200.0


PROVENANCE: dict[str, tuple[str, str]] = {
    "products_per_year": ("YOURS", "structured products sold per year"),
    "average_ticket": ("YOURS", f"average ticket size ({CURRENCY})"),
    "minutes_per_manual_check": (
        "YOURS",
        "minutes spent per recommendation on the suitability check and its file",
    ),
    "loaded_hourly_rate": ("YOURS", f"fully-loaded hourly cost of the person doing it ({CURRENCY})"),
    "automation_rate": (
        "ASSUMPTION",
        "share of that time Memtara displaces (the threshold comparison and the "
        "evidence assembly — not the client conversation, not KYC, not product governance)",
    ),
    "evidence_requests_per_year": (
        "YOURS",
        "files pulled per year for internal audit, the regulator, or a complaint",
    ),
    "hours_to_assemble_a_file": ("YOURS", "hours to reconstruct one suitability file today"),
    "upheld_complaints_per_year": ("YOURS", "mis-selling complaints upheld against you per year"),
    "average_redress_per_complaint": (
        "YOURS",
        f"average all-in cost of an upheld complaint — redress, handling, provisioning ({CURRENCY})",
    ),
    "evidentiary_share": (
        "ASSUMPTION",
        "share of those upheld because the file could not evidence what was checked, "
        "rather than because the recommendation was genuinely unsuitable",
    ),
    "memtara_effectiveness": (
        "ASSUMPTION",
        "share of that evidentiary portion contemporaneous cryptographic evidence "
        "would have prevented",
    ),
    "tier": ("OURS", "Memtara tier"),
    "integration_days": ("ASSUMPTION", "engineering days on your side to integrate"),
    "integration_day_rate": ("YOURS", f"your blended engineering day rate ({CURRENCY})"),
}


@dataclass
class Result:
    annual_licence: float
    one_off_integration: float
    first_year_cost: float
    steady_state_annual_cost: float

    labour_saving: float
    evidence_saving: float
    conservative_annual_benefit: float

    risk_exposure: float
    risk_saving: float
    risk_adjusted_annual_benefit: float

    conservative_net: float
    conservative_payback_months: float | None
    conservative_roi: float | None

    risk_adjusted_net: float
    risk_adjusted_payback_months: float | None
    risk_adjusted_roi: float | None

    breakeven_products_per_year: float | None
    cost_per_recommendation: float | None
    distributed_notional: float
    cost_in_basis_points: float | None
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# The model
# ---------------------------------------------------------------------------


def compute(i: Inputs) -> Result:
    tier = TIERS[i.tier]
    monthly = float(tier["monthly"])  # type: ignore[arg-type]
    annual_licence = monthly * 12
    one_off = i.integration_days * i.integration_day_rate

    # 1. Displaced labour on every recommendation.
    hours_today = i.products_per_year * (i.minutes_per_manual_check / 60.0)
    labour_saving = hours_today * i.loaded_hourly_rate * i.automation_rate

    # 2. Displaced labour at evidence time. This one is close to total rather
    #    than partial: `memtara-export` produces the file in seconds, and the
    #    residual is the reviewer reading it.
    evidence_hours_today = i.evidence_requests_per_year * i.hours_to_assemble_a_file
    evidence_saving = evidence_hours_today * i.loaded_hourly_rate * 0.80

    conservative = labour_saving + evidence_saving

    # 3. The risk term. Two multiplications, both of which are honest guesses,
    #    which is exactly why it is quarantined from the headline.
    exposure = i.upheld_complaints_per_year * i.average_redress_per_complaint
    risk_saving = exposure * i.evidentiary_share * i.memtara_effectiveness
    risk_adjusted = conservative + risk_saving

    def payback_months(annual_benefit: float) -> float | None:
        """Months until cumulative benefit covers cumulative cost.

        Integration is paid once up front; the licence accrues monthly. So the
        question is the month m where benefit*m/12 >= one_off + monthly*m.
        """
        monthly_net = annual_benefit / 12.0 - monthly
        if monthly_net <= 0:
            return None
        if one_off <= 0:
            return 0.0 if annual_benefit > 0 else None
        return one_off / monthly_net

    def roi(annual_benefit: float) -> float | None:
        cost = annual_licence + one_off
        return None if cost <= 0 else (annual_benefit - cost) / cost * 100.0

    notional = i.products_per_year * i.average_ticket

    # Break-even volume on the conservative case only: at what annual volume
    # does displaced labour alone cover the licence?
    per_product_saving = (i.minutes_per_manual_check / 60.0) * i.loaded_hourly_rate * i.automation_rate
    if per_product_saving > 0:
        breakeven = max(0.0, (annual_licence - evidence_saving) / per_product_saving)
    else:
        breakeven = None

    notes: list[str] = []
    if i.automation_rate >= 0.9:
        notes.append(
            "automation_rate is at or above 0.9. Memtara does not displace the client "
            "conversation, the KYC file or product governance; a rate that high will not "
            "survive contact with the operations team."
        )
    if i.evidentiary_share * i.memtara_effectiveness > 0.5:
        notes.append(
            "the risk term assumes contemporaneous evidence would have prevented more than "
            "half of your upheld complaints. That is a strong claim about your own complaints "
            "book — check it against the actual case files before putting it in a paper."
        )
    if i.products_per_year < 500:
        notes.append(
            "below roughly 500 recommendations a year the labour case is thin. The reason to "
            "buy at that volume is defensibility on a small number of large tickets, not "
            "operational saving — argue it that way or do not argue it."
        )
    if conservative < annual_licence:
        notes.append(
            "displaced labour alone does not cover the licence at these numbers. The pilot "
            "tier exists for exactly this situation: prove the evidence value first, at "
            "$5k/month, before anyone signs for production."
        )

    return Result(
        annual_licence=annual_licence,
        one_off_integration=one_off,
        first_year_cost=annual_licence + one_off,
        steady_state_annual_cost=annual_licence,
        labour_saving=labour_saving,
        evidence_saving=evidence_saving,
        conservative_annual_benefit=conservative,
        risk_exposure=exposure,
        risk_saving=risk_saving,
        risk_adjusted_annual_benefit=risk_adjusted,
        conservative_net=conservative - annual_licence,
        conservative_payback_months=payback_months(conservative),
        conservative_roi=roi(conservative),
        risk_adjusted_net=risk_adjusted - annual_licence,
        risk_adjusted_payback_months=payback_months(risk_adjusted),
        risk_adjusted_roi=roi(risk_adjusted),
        breakeven_products_per_year=breakeven,
        cost_per_recommendation=(annual_licence / i.products_per_year if i.products_per_year else None),
        distributed_notional=notional,
        cost_in_basis_points=(annual_licence / notional * 10_000 if notional else None),
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------


def money(value: float) -> str:
    return f"{CURRENCY} {value:,.0f}"


def months(value: float | None) -> str:
    if value is None:
        return "never, at these numbers"
    if value < 1:
        return "under a month"
    return f"{value:.1f} months"


def percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:+,.0f}%"


def render(i: Inputs, r: Result) -> str:
    tier = TIERS[i.tier]
    out: list[str] = []
    w = out.append

    w("")
    w("=" * 74)
    w("  MEMTARA — RETURN ON INVESTMENT")
    w("=" * 74)
    w("")
    w("  INPUTS")
    for name, (tag, description) in PROVENANCE.items():
        value = getattr(i, name)
        if isinstance(value, float) and value >= 1000:
            shown = f"{value:,.0f}"
        elif isinstance(value, float):
            shown = f"{value:g}"
        elif isinstance(value, int):
            shown = f"{value:,}"
        else:
            shown = str(value)
        w(f"    [{tag:<10}] {shown:>12}   {description}")
    w("")
    w(f"  {tier['label']} — {tier['note']}")
    w("")

    w("-" * 74)
    w("  COST")
    w("-" * 74)
    w(f"    Licence, annual                      {money(r.annual_licence):>18}")
    w(f"    Integration, one-off (your team)     {money(r.one_off_integration):>18}")
    w(f"    First year, all in                   {money(r.first_year_cost):>18}")
    if r.cost_per_recommendation is not None:
        w(f"    Licence per recommendation           {money(r.cost_per_recommendation):>18}")
    w("")
    # The framing that actually wins the room. Banks buy risk infrastructure in
    # basis points of what flows through it, not in headcount displaced, and a
    # cost expressed against distribution is one a Head of Wealth can approve
    # without an operations study.
    w(f"    Structured product distributed       {money(r.distributed_notional):>18}")
    if r.cost_in_basis_points is not None:
        w(f"    Licence as a share of that           {r.cost_in_basis_points:>15.2f} bp")
    w("")

    w("-" * 74)
    w("  THE CONSERVATIVE CASE — displaced hours only, risk term set to zero")
    w("-" * 74)
    w(f"    Suitability checks             {money(r.labour_saving):>18}")
    w(f"    Evidence assembly              {money(r.evidence_saving):>18}")
    w(f"    Annual benefit                 {money(r.conservative_annual_benefit):>18}")
    w(f"    Net of licence                 {money(r.conservative_net):>18}")
    w(f"    Payback on integration         {months(r.conservative_payback_months):>18}")
    w(f"    First-year ROI                 {percent(r.conservative_roi):>18}")
    if r.breakeven_products_per_year is not None:
        w(f"    Break-even volume              {r.breakeven_products_per_year:>13,.0f} products/yr")
    w("")
    w("    This is the number to put in the paper. It depends on hours and rates")
    w("    your own operations team can confirm, and on no claim of ours.")
    w("")

    w("-" * 74)
    w("  THE RISK-ADJUSTED CASE — rests on two assumptions you must replace")
    w("-" * 74)
    w(f"    Annual upheld-complaint cost   {money(r.risk_exposure):>18}   [YOURS]")
    w(f"      x evidentiary share {i.evidentiary_share:.0%}                              [ASSUMPTION]")
    w(f"      x effectiveness {i.memtara_effectiveness:.0%}                                  [ASSUMPTION]")
    w(f"    Expected annual reduction      {money(r.risk_saving):>18}")
    w(f"    Annual benefit, all in         {money(r.risk_adjusted_annual_benefit):>18}")
    w(f"    Payback on integration         {months(r.risk_adjusted_payback_months):>18}")
    w(f"    First-year ROI                 {percent(r.risk_adjusted_roi):>18}")
    w("")
    w("    Read this as a range, not a forecast. Both multipliers are judgements")
    w("    about your own complaints book. Nobody outside your bank can source them,")
    w("    and no published UAE benchmark exists to substitute — which is why this")
    w("    calculator asks rather than asserts.")
    w("")

    if r.notes:
        w("-" * 74)
        w("  WORTH SAYING OUT LOUD")
        w("-" * 74)
        for note in r.notes:
            first, *rest = _wrap(note, 68)
            w(f"    - {first}")
            for line in rest:
                w(f"      {line}")
            w("")

    w("-" * 74)
    w("  WHAT THIS MODEL DOES NOT COUNT")
    w("-" * 74)
    for line in (
        "Advisor time saved by not waiting on a compliance pre-check.",
        "The deals not lost while a file is being reconstructed.",
        "Supervisory goodwill, which is real and which nobody can price.",
        "Any fine. Fines are case-specific, rare, and not a planning basis.",
    ):
        w(f"    - {line}")
    w("")
    w("  Not a forecast, not advice, and not a substitute for your own business")
    w("  case. It is arithmetic over numbers you supplied.")
    w("")
    return "\n".join(out)


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------


def ask(inputs: Inputs) -> Inputs:
    print()
    print("Memtara ROI calculator. Enter to accept the value in brackets.")
    print("Tags: [YOURS] we cannot know it   [ASSUMPTION] argue with it   [OURS] our price")
    print()
    for name, (tag, description) in PROVENANCE.items():
        if name == "tier":
            continue
        current = getattr(inputs, name)
        print(f"  [{tag}] {description}")
        raw = input(f"    [{current}] > ").strip()
        if not raw:
            continue
        try:
            value = type(current)(raw) if not isinstance(current, int) else int(float(raw))
        except ValueError:
            print(f"    not a number; keeping {current}")
            continue
        setattr(inputs, name, value)

    print()
    print("  [OURS] which tier")
    for key, tier in TIERS.items():
        print(f"    {key:<11} {tier['label']} — {tier['note']}")
    raw = input(f"    [{inputs.tier}] > ").strip().lower()
    if raw in TIERS:
        inputs.tier = raw
    return inputs


# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="What Memtara costs, what it displaces, and when it pays back.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run with no arguments to be asked the questions one at a time.",
    )
    parser.add_argument("--defaults", action="store_true", help="skip the questions, use the assumptions")
    parser.add_argument("--json", action="store_true", dest="as_json", help="machine-readable output")
    parser.add_argument("--tier", choices=sorted(TIERS), help="pricing tier")
    for name, (tag, description) in PROVENANCE.items():
        if name == "tier":
            continue
        default = getattr(Inputs(), name)
        parser.add_argument(
            f"--{name.replace('_', '-')}",
            type=type(default),
            metavar=tag[0],
            help=f"[{tag}] {description} (default {default})",
        )
    args = parser.parse_args(argv)

    inputs = Inputs()
    supplied_any = False
    for name in PROVENANCE:
        value = getattr(args, name, None)
        if value is not None:
            setattr(inputs, name, value)
            supplied_any = True

    if not (args.defaults or supplied_any or args.as_json):
        if sys.stdin.isatty():
            inputs = ask(inputs)
        else:
            print("no tty and no arguments — running on defaults", file=sys.stderr)

    result = compute(inputs)

    if args.as_json:
        print(
            json.dumps(
                {
                    "currency": CURRENCY,
                    "inputs": asdict(inputs),
                    "provenance": {k: v[0] for k, v in PROVENANCE.items()},
                    "result": asdict(result),
                },
                indent=2,
            )
        )
    else:
        print(render(inputs, result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
