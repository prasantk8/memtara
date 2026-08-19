# Buyer map — revised for discovery

`marketing/LEAD_LIST.md` names three buyer roles (CRO/Head of Compliance,
Head of Digital Wealth, CTO) built around a *product pitch*. This map is
built around *who actually has to say yes for a deal to happen*, which is a
different question and has five roles, not three. It does not edit
`LEAD_LIST.md` — that file stays as-is per the current freeze on marketing
copy — but it should govern who you actually call.

**The single most important correction in this document:** the CRO was our
previous first-call target, and it was the wrong one. A CRO is the economic
buyer — the person who eventually signs — but is rarely the person who feels
the pain of assembling evidence by hand, and is almost never the first
person willing to give a pre-revenue vendor 25 minutes. Lead with the
champion, not the signer.

---

## The five roles

### Primary champion — Head of Compliance / AI Governance / Model Risk

The person who personally feels Q4 and Q5 in `INTERVIEW_GUIDE.md` — the
hours spent assembling a file, whether it was their whole week. This is your
first call target, every time. They cannot always sign a $12–25k/month line
alone, but they can get you to the person who can, and they are the one who
will actually use what you build.

### Economic buyer — CRO / COO / CIO

Signs the budget line. Cares about basis points and renewal risk more than
workflow detail — see `docs/PRICING_MODEL.md`'s basis-point framing. Will
ask what happens if we disappear as a vendor. Do not open here. Arrive here
once the champion has already agreed the pain is real and has agreed to
bring you to their boss.

### Validator — Internal Audit

Tests whatever the champion proposes. This is the role most often
misunderstood: **Internal Audit validates, but frequently holds no budget of
its own.** They can kill a deal by finding a gap (see Q7 in the interview
guide) but they cannot usually fund one. Treat an enthusiastic Internal
Audit contact as a strong validator and a weak buyer signal — do not let
their enthusiasm substitute for a named economic buyer in your notes.

### Security gate — CISO

Does not care about the evidence problem at all. Cares about what data
leaves the firm, what runs where, and vendor risk posture — no SOC 2, no pen
test, no container image, as `marketing/LEAD_LIST.md:59-61` and
`docs/PRICING_MODEL.md:183-201` already concede. A CISO cannot say yes on
their own but can produce a hard no late in the cycle if engaged too late or
not at all. Loop them in once a pilot is being discussed seriously, not
before — engaging security review before there is a real deal wastes their
time and yours.

### Executive sponsor — Board

Rarely in the room. Matters when the ask crosses a threshold that needs
board-level risk appetite sign-off, or when the firm's own board has asked
management "what is our AI governance posture" — which is itself a useful
thing to ask a champion about (it's a good proxy question for Q11's "what
happens if evidence is missing," asked one level up).

---

## Two columns: role count is not fixed by title, it is fixed by firm size

Use whichever column matches the firm on the call. Getting this wrong is the
single most common way a discovery call goes nowhere — you ask a person
playing three roles a question meant for someone playing one.

| | **Large enterprise (all five roles filled)** | **Flat DIFC firm (one person, three roles)** |
|---|---|---|
| **Typical firm shape** | Local retail bank with a private-banking arm, universal bank, large DIFC/ADGM private bank | Independent wealth manager, boutique DIFC/ADGM manager, small private bank |
| **Champion** | Head of AI Governance or Model Risk — a role that may not have existed two years ago | Same person as economic buyer and often as validator too — frequently titled Head of Compliance or COO |
| **Economic buyer** | CRO, separate person, separate meeting | Often the same individual as the champion |
| **Validator** | Internal Audit, a separate department with its own reporting line to the board | Often outsourced or part-time; may be the same individual again, or an external auditor engaged annually |
| **Security gate** | CISO, a separate function, engaged formally with a vendor-risk questionnaire | Often IT is one contractor or a small team; "security review" may be an informal conversation with the same person |
| **Executive sponsor** | Board risk committee, a real, distinct body | The principal or managing partner — may literally be the person on the call |
| **Which column is more common in our target list** | Less common. Per `marketing/LEAD_LIST.md`'s segmentation, these firms have "vendor-risk machinery that will stop the big names" and 6–9 month cycles | **More common at our current size of target.** Independent wealth managers are rated "medium-high, best odds of an actual pilot" in `marketing/LEAD_LIST.md:93-106` — precisely because the role count collapses |
| **Sequence** | Champion → economic buyer → validator (parallel or slightly after) → security gate (once pilot is real) → executive sponsor (only if threshold crossed) | Champion/economic-buyer/validator conversation **is one meeting, not four** — do not schedule four separate calls with the same person under different pretexts. Security gate is still worth a distinct, lighter conversation even if it's the same individual, because the questions are different in kind (Q7-Q9 pain questions vs. vendor-risk questions) |

### What this means for how you run the call

- At a **flat firm**, do not assume a weak answer to Q13 ("who owns the
  budget") means there is no budget owner. It may mean the person in front
  of you already is the budget owner and is being modest about it — ask
  directly: "is that decision yours, or does it go above you?"
- At a **large enterprise**, do not assume the champion can answer Q13
  precisely. They may genuinely not know which committee ultimately signs.
  That is a legitimate answer, not evasion — log it as "budget owner:
  unknown to champion" rather than "no."
- Internal Audit contacts, at either firm size, are worth interviewing for
  the pain data (Q6, Q7 especially) even when you already know they hold no
  budget. A validator who confirms the pain independently of the champion is
  stronger triangulation than the champion's word alone.
