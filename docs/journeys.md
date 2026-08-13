# Memtara — UAE-Resident Journeys

Eight real disclosure journeys, each mapped to what actually exists:
one of the four circuits under `circuits/`, one of the three login paths
under `backend/api/src/auth/`, and a `POST /disclosure-requests` call shaped
by that circuit's `circuit_type`. Two are already wireframed
(`web/reference/memtara_wireframes.tsx`); the other six are new — four for
tech-savvy HNWI users, two for people the passkey-first flow doesn't serve
well.

Format per journey: **actor → trigger → disclosed predicate → circuit → auth
path → UI touchpoint.**

---

## Already wireframed

### Bank AML/STR compliance clearance
- **Actor**: a bank compliance analyst (`EnterpriseBankView` in the
  wireframe), acting on behalf of an `organizations` row with
  `org_type = 'bank'`.
- **Trigger**: routine KYC refresh or a transaction-monitoring flag that
  needs an STR (Suspicious Transaction Report) narrative resolved.
- **Disclosed predicate**: PEP status (negative), sanctions match (none),
  risk score band — never the underlying source-of-funds documents or
  90-day transaction history unless the analyst separately requests those
  categories.
- **Circuit**: `identity_session` (attribute disclosure, no numeric range
  needed — these are boolean/categorical facts).
- **Auth path**: the *user* authenticates however they normally do
  (passkey primary); the *bank* authenticates via `OrgAuth` (API key,
  `backend/api/src/orgs/mod.rs`).
- **UI touchpoint**: `EnterpriseBankView`'s policy builder + "Generate
  Local Proof & Start Session," then the ZK-verified AI assistant panel.

### Mortgage pre-approval
- **Actor**: a consumer (`MobileAppView` in the wireframe) with a request
  from a developer/lender.
- **Trigger**: Emaar Properties (or similar) requests residency + income-tier
  verification for a pre-approval decision.
- **Disclosed predicate**: residency verified (boolean), income tier ≥ a
  threshold — never exact salary, employer name, passport copy, or bank
  statements (the wireframe's "What Stays Private" panel is literally this
  list).
- **Circuit**: `tax_session` (income range predicate).
- **Auth path**: passkey.
- **UI touchpoint**: the "Review Disclosure" screen's What-They-Receive /
  What-Stays-Private split, expiry-timer picker, "Generate Local Proof."

---

## Tech-savvy HNWI

### 1. Golden Visa / investor compliance proof
- **Actor**: a Golden Visa holder (the wireframe's "UAE Golden Visa" vault
  card) opening a DIFC or ADGM wealth-management relationship.
- **Trigger**: the wealth manager's onboarding flow needs investor-category
  and compliance-clean confirmation before a relationship-manager call.
- **Disclosed predicate**: investor category + visa validity (boolean/
  categorical) and a clean compliance flag — never net worth, portfolio
  composition, or the visa application file itself.
- **Circuit**: `identity_session`.
- **Auth path**: passkey, with UAE Pass as an alternative first-login route
  (`backend/api/src/auth/uae_pass.rs`) since a Golden Visa holder is by
  definition already a UAE digital-identity holder — this journey is the
  natural home for UAE Pass login, more than the mass-market journeys below.
- **UI touchpoint**: a new "Share Credential" action off the existing vault
  card (`MobileAppView`'s Golden Visa card already has an unwired "Share
  Proof" button — this journey is what it should do).

### 2. Real-estate proof-of-funds
- **Actor**: a buyer working with a developer's escrow process (Emaar,
  DAMAC, or similar).
- **Trigger**: reservation of a unit above a price threshold requires
  proof-of-funds before escrow will hold it.
- **Disclosed predicate**: funds ≥ unit price (a range/threshold check
  against the specific price quoted, not a static bracket) — never the
  account balance itself or which bank(s) it's spread across.
- **Circuit**: `tax_session` (same range-predicate shape as mortgage
  pre-approval, different `min_income`/threshold semantics — the circuit
  doesn't care what the number represents, only that it's a bounded value).
- **Auth path**: passkey.
- **UI touchpoint**: same disclosure-review pattern as mortgage
  pre-approval, with the developer's escrow reference number surfaced
  instead of a lender's.

### 3. Accredited-investor certification
- **Actor**: an investor applying for a DIFC-regulated fund or structured
  product that requires accredited-investor status.
- **Trigger**: the fund's subscription flow gates access behind a
  certification check.
- **Disclosed predicate**: a single boolean — "meets the accredited-investor
  asset/income threshold" — the narrowest possible disclosure in this whole
  set; nothing else about the applicant's finances crosses at all.
- **Circuit**: `tax_session`, used in its narrowest mode (one threshold,
  one boolean result, no deduction list).
- **Auth path**: passkey.
- **UI touchpoint**: a single-screen "Certify & Continue" step embedded in
  the fund platform's own subscription flow (not a Memtara-branded screen —
  this is the journey most likely to be embedded via SDK inside someone
  else's product, since a fund platform isn't going to send an investor
  away to a separate app for one checkbox).

### 4. Family-office succession disclosure
- **Actor**: the principal of a family office, sharing specific holdings
  information with a named lawyer or executor.
- **Trigger**: estate planning, a succession event, or a scheduled periodic
  disclosure to a fiduciary.
- **Disclosed predicate**: existence and category of specific holdings
  (e.g. "a UAE real-estate holding exists," "a specific trust structure is
  active") — never full portfolio valuation, and critically, scoped to
  exactly one named recipient rather than an organization's whole compliance
  team the way the bank journey is.
- **Circuit**: `identity_session`, with a tighter `disclosure_requests.ttl`
  than any other journey here (this is the one place "time-boxed" really
  means days-to-weeks of validity for a single named human, not an
  org-wide relationship) and a policy that names the specific recipient
  rather than an org — this is a real product gap worth flagging: today's
  schema authenticates the *org*, not a specific individual recipient
  within it; a family office sharing with "this one lawyer" rather than
  "this law firm's whole compliance API key" needs either a
  recipient-scoped sub-key on the org or a person-to-person disclosure
  primitive that doesn't exist yet.
- **UI touchpoint**: new — nothing in the current wireframe covers
  single-recipient sharing; closest analog is the mobile app's disclosure-
  review screen, but addressed to a named person instead of an
  organization logo.

---

## Non-tech-savvy

### 5. Assisted emergency card
- **Actor**: an elderly or low-digital-literacy resident, set up with help
  from a family member, pharmacist, or clinic staff.
- **Trigger**: a paramedic or ER intake scans a physical NFC card or QR
  code carried in a wallet — the person doesn't unlock a phone or interact
  with an app at the moment of use at all.
- **Disclosed predicate**: blood type, key medications, allergies — exactly
  what `circuits/emergency_session` already proves, nothing more, for a
  strict 1-hour window (`EMERGENCY_MAX_DURATION_SECONDS` in the circuit).
- **Circuit**: `emergency_session`.
- **Auth path**: none at time of use, by design — the card is a bootstrap
  token set up once during a supervised setup session (passkey or OTP,
  whichever the assisting family member/pharmacist has on hand), which
  provisions the card. The card itself carries just enough to trigger a
  pre-authorized proof, not a live login.
- **UI touchpoint**: a one-time "Set Up Emergency Card" wizard, run by
  the assisting person on the resident's behalf — large touch targets, a
  printable/NFC-writable confirmation screen, no ongoing app interaction
  required afterward. This is the journey where the assisting person is
  the actual UI user, not the resident.

### 6. Government-counter-assisted proof (Amer/Tasheel-style center)
- **Actor**: a resident applying for a government service in person, with
  a counter staff member operating the interface.
- **Trigger**: a service application (e.g., a residency-category renewal)
  needs a specific verified attribute rather than a full document bundle.
- **Disclosed predicate**: depends on the service — most commonly
  residency-category validity or an identity attribute, deliberately kept
  to whatever single fact the specific counter service requires.
- **Circuit**: `identity_session`.
- **Auth path**: UAE Pass, initiated by the counter staff member on a
  kiosk device, with the resident confirming via biometric/OTP on their
  own phone when prompted — staff operate the flow, the resident only
  confirms consent at the one moment it matters.
- **UI touchpoint**: new — a kiosk-mode variant needed here: Arabic-first
  (RTL), icon-led rather than text-led, large touch targets, and a spoken
  confirmation prompt ("Share your residency status with [service name]?")
  rather than dense text like the mortgage-journey's What-They-Receive
  panel. Same underlying disclosure-review concept as the consumer app,
  simplified to one screen and one decision.

---

## What this reveals about the backend as built

Every journey above maps cleanly onto the existing four `circuit_type`
values (`emergency_session`, `ai_session`, `tax_session`,
`identity_session`) and the existing `POST /disclosure-requests` shape —
no journey here needed a fifth circuit. The one real gap surfaced is
**journey 4**: `organizations`/`OrgAuth` authenticates an organization, not
an individual recipient within one, and family-office-style
person-to-person disclosure doesn't fit that shape today. Worth a decision
before frontend work depends on it, not a blocker for anything already
built.
