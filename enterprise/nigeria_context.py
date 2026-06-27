"""
ShieldIQ Enterprise — Nigerian Fraud Context Intelligence
───────────────────────────────────────────────────────────
Regional fraud intelligence built specifically for Nigeria.
Injected into Pass 2 before deep analysis begins.

This context — the specific patterns, institutions, and cultural
signals — is what separates ShieldIQ from a generic LLM deployment.
"""

# ── Core Nigerian context ─────────────────────────────────────────────────────

NIGERIA_BASE_CONTEXT = """
You are analysing a message received by a user in Nigeria.
Apply the following Nigerian-specific knowledge to your analysis.

LEGITIMATE NIGERIAN INSTITUTIONS (messages from these should not be flagged
as suspicious purely because of the institution name):
- Banks: GTBank, Access Bank, Zenith Bank, First Bank, UBA, Fidelity Bank,
  Stanbic IBTC, Sterling Bank, FCMB, Polaris Bank, Keystone Bank, Unity Bank
- Mobile money: OPay, PalmPay, Moniepoint, Kuda, Carbon, FairMoney, Piggyvest
- Telecoms: MTN, Airtel, Glo, 9mobile (Etisalat)
- Government: FIRS, FRSC, NAFDAC, EFCC, INEC, CBN, NBS, NCC, NIMC

COMMON NIGERIAN FRAUD PATTERNS TO FLAG:
1. Bank impersonation: Messages claiming account suspension, BVN issues,
   NIN linkage requirements, or transaction alerts with suspicious links
2. OTP harvesting: Requests for one-time passwords, PINs, or token codes
3. Investment fraud: Promises of high returns, cryptocurrency schemes,
   forex signals, Ponzi-style referral bonuses
4. Job scams: Unsolicited job offers requiring upfront payment
5. Scholarship scams: Fake scholarships requiring processing fees
6. Government impersonation: Fake CBN alerts, EFCC investigation notices,
   fake palliative/relief fund disbursements
7. Prize/lottery scams: Winning messages for competitions never entered
8. Vendor fraud: Fake supplier invoices to businesses
9. WhatsApp impersonation: Messages from a contact's "new number"
10. POS/Agent banking fraud: Fake transaction reversal requests

NIGERIAN COMMUNICATION NORMS (do NOT flag these as suspicious):
- Informal greetings: "Bros", "Oga", "My guy", "Sister"
- Direct requests for help without extensive preamble
- References to family obligations, school fees, rent, emergencies
- Code-switching between English and Pidgin within a message
- Informal spelling and abbreviations in casual messages
- Religious references in everyday communication
"""

# ── Nigerian Pidgin context ───────────────────────────────────────────────────

PIDGIN_CONTEXT = """
NIGERIAN PIDGIN LANGUAGE NOTES:
The message may contain Nigerian Pidgin English. Key indicators of
legitimate Pidgin communication (not fraud signals):
- "How far", "How now", "E don do", "Wetin dey happen"
- "Make I", "I wan", "No vex", "E be like say"
- "Abi", "Sha", "Sef", "Ehen", "Wahala"
- Numbers written informally: "5k" = ₦5,000, "1m" = ₦1,000,000

Pidgin fraud signals to watch for:
- Urgency: "E don do o!", "Do am now now!", "Time don reach"
- Authority impersonation: "Na bank send me", "Government say make I"
- Prize claims: "You don win!", "Your name don come out"
"""

# ── Yoruba context ────────────────────────────────────────────────────────────

YORUBA_CONTEXT = """
YORUBA-INFLECTED COMMUNICATION NOTES:
Normal Yoruba-influenced communication patterns:
- Respectful address: "Baba", "Mama", "Egbon" (elder), "Aburo" (younger)
- Common expressions: "E kaaro" (good morning), "E kaasan" (good afternoon)
- Code-switching to Yoruba words mid-sentence is normal

Yoruba-context fraud patterns:
- Impersonation of respected community figures or traditional rulers
- Fake cooperative society or "ajo" (contribution) schemes
- Religious organisation impersonation
"""

# ── Hausa context ─────────────────────────────────────────────────────────────

HAUSA_CONTEXT = """
HAUSA-INFLECTED COMMUNICATION NOTES:
Normal Hausa-influenced communication patterns:
- Respectful greetings: "Sannu", "Barka da safiya" (good morning)
- References to Islamic greetings: "As-salamu alaykum" is normal
- Deferential tone and formal address styles are common

Hausa-context fraud patterns:
- Cattle or agricultural investment scams
- Fake government agricultural support schemes
- Religious charity impersonation
"""

# ── Igbo context ──────────────────────────────────────────────────────────────

IGBO_CONTEXT = """
IGBO-INFLECTED COMMUNICATION NOTES:
Normal Igbo-influenced communication patterns:
- Warm, direct communication style
- References to "Nna" (father), "Nne" (mother)
- Business-oriented communication is culturally normal

Igbo-context fraud patterns:
- Fake trade partnership or business investment schemes
- Impersonation of Igbo community associations abroad
- Market trading scams targeting Onitsha/Aba merchants
"""


# ── Language detection and context selection ──────────────────────────────────

def get_context_for_language(detected_language: str) -> str:
    """
    Return the appropriate regional context based on detected language.
    Always includes the base Nigerian context plus language-specific additions.
    """
    base = NIGERIA_BASE_CONTEXT
    language_map = {
        "pidgin": PIDGIN_CONTEXT,
        "yo": YORUBA_CONTEXT,
        "yoruba": YORUBA_CONTEXT,
        "ha": HAUSA_CONTEXT,
        "hausa": HAUSA_CONTEXT,
        "ig": IGBO_CONTEXT,
        "igbo": IGBO_CONTEXT,
    }
    additional = language_map.get(detected_language.lower(), "")
    return base + additional


def detect_nigerian_language(message: str) -> str:
    """
    Detect the specific Nigerian language variant in a message.
    Uses simple keyword detection as a fast first pass.
    """
    message_lower = message.lower()

    pidgin_markers = [
        "wetin", "dey", "wahala", "abeg", "make i", "no be",
        "e don", "bros", "abi", "sha", "sef", "wey", "na im"
    ]
    yoruba_markers = [
        "ekaaro", "kaaro", "kaasan", "egbon", "aburo", "baba ni",
        "jowo", "nibo", "dupe"
    ]
    hausa_markers = [
        "sannu", "yauwa", "lafiya", "nagode", "ina kwana",
        "barka", "yanzu"
    ]
    igbo_markers = [
        "nna", "nne", "kedu", "daalu", "biko", "oga m",
        "ihe", "onye", "nnoo", "obi"
    ]

    scores = {
        "pidgin": sum(1 for m in pidgin_markers if m in message_lower),
        "yoruba": sum(1 for m in yoruba_markers if m in message_lower),
        "hausa":  sum(1 for m in hausa_markers  if m in message_lower),
        "igbo":   sum(1 for m in igbo_markers   if m in message_lower),
    }

    best = max(scores, key=scores.get)
    if scores[best] > 0:
        return best

    return "en"
