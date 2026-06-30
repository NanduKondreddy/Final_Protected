import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from models import ScanResult


@dataclass
class RuleSignal:
    name: str
    weight: int
    reason: str
    fraud_type: Optional[str] = None


@dataclass
class RuleVerdict:
    score: int
    reasons: list[str]
    signals: list[str] = field(default_factory=list)
    fraud_type: Optional[str] = None
    safe_reasons: list[str] = field(default_factory=list)
    force_high: bool = False
    force_low: bool = False


KNOWN_FRAUD_DOMAINS = {
    "gtbank-secure-verify.ng.co",
    "gtbank-secure-verify.com",
    "gtbank-alert.com",
    "gtbank-alert.ng",
    "access-bank-ng.verify.com",
    "accessbank-secure.com",
    "opay-verify.com",
    "opay-alert.ng.co",
    "opay-support.ng",
    "moniepoint-alert.ng",
    "moniepoint-verify.com",
    "zenithbank-alert.com",
    "kuda-verify.com",
    "cbn-grant-portal.com",
    "efcc-investigation.com",
    "mtn-promo-winner.ng",
}

LEGITIMATE_DOMAINS = {
    "realpython.com",
    "python.org",
    "google.com",
    "gmail.com",
    "microsoft.com",
    "linkedin.com",
    "indeed.com",
    "github.com",
    "amazon.com",
    "apple.com",
    "netflix.com",
    "zoom.us",
    "slack.com",
    "whatsapp.com",
    "gtbank.com",
    "accessbankplc.com",
    "zenithbank.com",
    "firstbanknigeria.com",
    "ubagroup.com",
    "opayweb.com",
    "opay.com",
    "moniepoint.com",
    "kuda.com",
}

BRAND_IMPERSONATION_HINTS = {
    "gtbank": ["gt-bank", "gtb-ank", "gtbank-secure", "gtbank-verify", "gtbank-alert"],
    "opay": ["0pay", "o-pay", "opay-verify", "opay-alert", "opay-support"],
    "moniepoint": ["moniepo1nt", "monie-point", "moniepoint-alert", "moniepoint-verify"],
    "access bank": ["access-bank", "accessbank-secure", "access-bank-ng"],
    "zenith": ["zenith-bank", "zenithbank-alert", "zenith-secure"],
    "kuda": ["kuda-bank", "kuda-verify"],
}

SAFE_NEWSLETTER_HINTS = [
    "unsubscribe",
    "newsletter",
    "podcast",
    "episode",
    "view in browser",
    "manage preferences",
    "educational content",
    "read on linkedin",
    "newsletters-noreply@linkedin.com",
    "via linkedin",
    "join the conversation",
]


def scan_message_rules(message: str) -> RuleVerdict:
    text = (message or "").strip()
    lower = text.lower()
    domains = _extract_domains(lower)
    signals: list[RuleSignal] = []
    safe_reasons: list[str] = []
    real_bank_alert = _looks_like_real_bank_alert(lower)

    if not text:
        return RuleVerdict(score=0, reasons=["No message content was provided."])

    for domain in domains:
        if domain in KNOWN_FRAUD_DOMAINS or any(domain.endswith("." + d) for d in KNOWN_FRAUD_DOMAINS):
            signals.append(RuleSignal(
                "known_fraud_domain",
                70,
                f"Contains a known fake or impersonation domain: {domain}",
                "phishing",
            ))
        elif _is_suspicious_domain(domain):
            signals.append(RuleSignal(
                "suspicious_domain",
                25,
                f"Uses a suspicious link domain that does not clearly match the claimed brand: {domain}",
                "phishing",
            ))
        elif domain in LEGITIMATE_DOMAINS or any(domain.endswith("." + d) for d in LEGITIMATE_DOMAINS):
            safe_reasons.append(f"Link domain appears to match a known legitimate service: {domain}")

    for brand, hints in BRAND_IMPERSONATION_HINTS.items():
        if any(hint in lower for hint in hints):
            signals.append(RuleSignal(
                "brand_impersonation",
                45,
                f"Uses a lookalike spelling or domain pattern for {brand}",
                "brand_impersonation",
            ))

    pattern_checks = [
        (r"\b(urgent|within\s+\d+\s*(minutes?|hours?|days?)|deadline|final warning|act now|quick quick|time dey run)\b|\b(immediately|now)\b.{0,35}\b(verify|confirm|pay|send|transfer|click|open|call|reply|login|update)\b",
         "urgency", 18, "Creates urgency to pressure a quick decision", None),
        (r"\b(account|card|bvn|nin|profile).{0,45}(flagged|suspended|blocked|restricted|closed|compromised|unusual|suspicious)\b",
         "account_threat", 35, "Claims an account problem or suspicious activity", "bank_phishing"),
        (r"\b(verify|validate|confirm|update|restore).{0,45}(identity|account|bvn|nin|details|login|password|pin|otp)\b",
         "credential_request", 35, "Asks the user to verify or provide sensitive account details", "credential_theft"),
        (r"\b(otp|one[- ]?time password|pin|token|password).{0,35}(send|share|provide|give|reply)\b",
         "otp_request", 80, "Requests an OTP, PIN, password, or token code", "credential_theft"),
        (r"\b(click|tap|open|visit|follow).{0,25}(link|url|http|www)\b",
         "link_push", 18, "Pushes the user toward a link", "phishing"),
        (r"\b(send|transfer|pay|deposit|wire).{0,35}(money|naira|ngn|n\d|\d+k|\d{2,},\d{3}|account)\b",
         "payment_request", 35, "Requests a payment or bank transfer", "payment_fraud"),
        (r"\b(processing|registration|activation|clearance|verification|release|documentation).{0,15}fee\b",
         "fee_request", 55, "Requests an upfront fee", "advance_fee_fraud"),
        (r"\b(do not tell|don't tell|keep this between us|confidential|do not discuss|secret)\b",
         "secrecy", 35, "Asks for secrecy, which is common in social engineering", "social_engineering"),
        (r"\b(md|ceo|boss|chairman|director).{0,80}(meeting|cannot take calls|busy).{0,120}(urgent|payment|transfer|supplier)\b",
         "ceo_fraud", 75, "Impersonates an authority figure while requesting urgent action", "ceo_fraud"),
        (r"\b(new number|changed my number|save this number|delete the old)\b",
         "number_change", 28, "Claims to be a known contact using a new number", "impersonation"),
        (r"\b(congratulations|congrats|you\s+(have\s+)?won|u\s+(have\s+)?won|winner|selected|chosen).{0,100}(prize|promo|grant|scholarship|award|reward|cash|phone|dollars?|usd|million|money)\b|\b(claim|collect|redeem).{0,40}(prize|reward|cash|money|dollars?|award)\b",
         "prize_claim", 60, "Claims an unsolicited prize, grant, or award", "prize_scam"),
        (r"\b(invest|investment|returns?|profit).{0,40}(\d{2,}%|double|triple|daily|weekly|7 days|24 hours)\b",
         "investment_fraud", 70, "Promises unusually high or fast investment returns", "investment_fraud"),
        (r"\b(confirm receipt|confirm to release|payment on hold|funds pending|before.*pick up|pick up.*goods)\b",
         "fake_transfer", 80, "Matches a fake transfer alert pattern that asks for confirmation", "fake_transfer_alert"),
        (r"\b(efcc|police|cbn|firs|court|government).{0,80}(arrest|warrant|investigation|summon|grant|palliative|loan)\b",
         "authority_impersonation", 60, "Uses government or law-enforcement authority to pressure the recipient", "government_impersonation"),
    ]

    for regex, name, weight, reason, fraud_type in pattern_checks:
        if re.search(regex, lower, re.IGNORECASE | re.DOTALL):
            if real_bank_alert and name in {"payment_request"}:
                continue
            signals.append(RuleSignal(name, weight, reason, fraud_type))

    if real_bank_alert:
        safe_reasons.append("Looks like a standard bank credit alert with no link or verification request")

    if any(hint in lower for hint in SAFE_NEWSLETTER_HINTS) and not _has_sensitive_or_payment_ask(lower):
        safe_reasons.append("Looks like a normal newsletter or educational email with no sensitive request")

    unique_signals = _dedupe_signals(signals)
    score = _score(unique_signals, safe_reasons, lower)
    force_high = any(s.weight >= 70 for s in unique_signals) or (
        _has_account_takeover_combo(unique_signals) and bool(domains)
    )
    force_low = bool(safe_reasons) and not unique_signals

    return RuleVerdict(
        score=score,
        reasons=[s.reason for s in unique_signals],
        signals=[s.name for s in unique_signals],
        fraud_type=next((s.fraud_type for s in unique_signals if s.fraud_type), None),
        safe_reasons=safe_reasons,
        force_high=force_high,
        force_low=force_low,
    )


def apply_rule_validation(ai_result: ScanResult, message: str) -> ScanResult:
    rules = scan_message_rules(message)
    result = ai_result.model_copy(deep=True)

    if rules.force_high and result.risk_score < 70:
        result.risk_score = max(88, rules.score)
        result.summary = _summary_for_rules(rules, "HIGH")
        result.reasons = _top_reasons(rules.reasons, result.reasons)
        result.what_to_do = _action_for_level("HIGH", rules.fraud_type)
    elif rules.score >= 70 and result.risk_score < 70:
        result.risk_score = max(75, rules.score)
        result.reasons = _top_reasons(rules.reasons, result.reasons)
    elif result.risk_score >= 70 and rules.force_low:
        result.risk_score = min(20, rules.score)
        result.summary = "This appears to be a legitimate message with no clear fraud request."
        result.reasons = _top_reasons(rules.safe_reasons, result.reasons)
        result.what_to_do = "This looks safe, but use the official website if you decide to click anything."
    elif rules.score > result.risk_score + 20:
        result.risk_score = min(100, max(result.risk_score, rules.score))
        result.reasons = _top_reasons(rules.reasons, result.reasons)
    elif rules.force_low and result.risk_score <= 40:
        result.risk_score = min(result.risk_score, 20)
        result.reasons = _top_reasons(rules.safe_reasons, result.reasons)

    result.risk_level = _level_for_score(result.risk_score)
    result.action = _action_for_score(result.risk_score)
    result.reasons = _normalize_reasons(result.reasons, result.risk_level)
    result.fraud_type = rules.fraud_type or result.fraud_type

    if not result.summary:
        result.summary = _summary_for_rules(rules, result.risk_level)
    if not result.what_to_do:
        result.what_to_do = _action_for_level(result.risk_level, rules.fraud_type)

    return result


def heuristic_result(message: str) -> ScanResult:
    rules = scan_message_rules(message)
    score = rules.score
    level = _level_for_score(score)
    reasons = rules.reasons if level != "LOW" else (rules.safe_reasons or [
        "No urgent threat or payment demand detected",
        "No suspicious link or sensitive information request detected",
        "Message does not match known fraud patterns",
    ])

    return ScanResult(
        risk_score=score,
        risk_level=level,
        summary=_summary_for_rules(rules, level),
        reasons=_normalize_reasons(reasons, level),
        action=_action_for_score(score),
        what_to_do=_action_for_level(level, rules.fraud_type),
        pass1_blocked=False,
        fraud_type=rules.fraud_type,
    )


def normalize_ai_result(data: dict) -> ScanResult:
    score = int(data.get("risk_score", 50))
    score = max(0, min(100, score))
    level = data.get("risk_level") or data.get("risk_band") or _level_for_score(score)
    level = _normalize_level(level, score)
    return ScanResult(
        risk_score=score,
        risk_level=level,
        summary=str(data.get("summary") or data.get("verdict_summary") or "").strip(),
        reasons=_normalize_reasons(data.get("reasons") or [], level),
        action=_normalize_action(data.get("action"), score),
        what_to_do=str(data.get("what_to_do") or data.get("recommendation") or "").strip(),
        pass1_blocked=bool(data.get("pass1_blocked", False)),
        fraud_type=data.get("fraud_type") or data.get("scam_type") or None,
    )


def _extract_domains(text: str) -> set[str]:
    domains = set()
    for match in re.findall(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", text):
        url = match if match.startswith("http") else "https://" + match
        parsed = urlparse(url)
        domain = parsed.netloc.lower().strip(".")
        if domain.startswith("www."):
            domain = domain[4:]
        if domain:
            domains.add(domain)
    for domain in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\.[a-z]{2,})?\b", text):
        domain = domain.lower().strip(".")
        if domain.startswith("www."):
            domain = domain[4:]
        domains.add(domain)
    return domains


def _is_suspicious_domain(domain: str) -> bool:
    suspicious_tlds = (".xyz", ".top", ".click", ".loan", ".biz", ".site", ".online", ".ng.co")
    suspicious_words = ("verify", "secure", "alert", "update", "confirm", "login", "support")
    if domain.endswith(suspicious_tlds):
        return True
    if any(word in domain for word in suspicious_words):
        return not any(domain == legit or domain.endswith("." + legit) for legit in LEGITIMATE_DOMAINS)
    return False


def _looks_like_real_bank_alert(lower: str) -> bool:
    has_bank = any(bank in lower for bank in ["gtbank", "accessbank", "zenith", "firstbank", "uba"])
    has_credit_format = bool(re.search(r"\bacct:?.{0,20}\bcr:?\s*n?[\d,]+", lower))
    has_balance = "avail bal" in lower or "available balance" in lower
    return has_bank and has_credit_format and has_balance and not _has_sensitive_or_payment_ask(lower)


def _has_sensitive_or_payment_ask(lower: str) -> bool:
    return bool(re.search(
        r"\b(otp|pin|password|bvn|nin|verify|confirm|validate|send money|pay now|deposit now|processing fee|registration fee)\b",
        lower,
    ))


def _has_account_takeover_combo(signals: list[RuleSignal]) -> bool:
    names = {s.name for s in signals}
    return "account_threat" in names and ("credential_request" in names or "link_push" in names)


def _dedupe_signals(signals: list[RuleSignal]) -> list[RuleSignal]:
    seen = set()
    unique = []
    for signal in sorted(signals, key=lambda s: s.weight, reverse=True):
        if signal.name not in seen:
            unique.append(signal)
            seen.add(signal.name)
    return unique


def _score(signals: list[RuleSignal], safe_reasons: list[str], lower: str) -> int:
    if not signals:
        if safe_reasons:
            return 12 if any("newsletter" in r.lower() for r in safe_reasons) else 6
        return 15 if len(lower) > 120 else 5

    weak_signal_names = {"urgency", "link_push"}
    if safe_reasons and all(s.name in weak_signal_names for s in signals):
        return 15

    score = min(100, sum(s.weight for s in signals[:5]))
    if len(signals) >= 3:
        score = min(100, score + 10)
    if safe_reasons and score < 70:
        score = max(0, score - 15)
    if score < 31 and signals:
        score = 35
    return score


def _level_for_score(score: int) -> str:
    if score <= 30:
        return "LOW"
    if score <= 69:
        return "MEDIUM"
    return "HIGH"


def _action_for_score(score: int) -> str:
    if score <= 30:
        return "TRUST"
    if score <= 69:
        return "CAUTION"
    return "BLOCK"


def _normalize_level(level: str, score: int) -> str:
    level = str(level or "").upper().replace("SAFE", "LOW").replace("CAUTION", "MEDIUM").replace("HIGH_RISK", "HIGH")
    return level if level in {"LOW", "MEDIUM", "HIGH"} else _level_for_score(score)


def _normalize_action(action: Optional[str], score: int) -> str:
    action = str(action or "").upper()
    return action if action in {"TRUST", "CAUTION", "BLOCK"} else _action_for_score(score)


def _normalize_reasons(reasons: list, level: str) -> list[str]:
    cleaned = [str(r).strip() for r in reasons if str(r).strip()]
    fallback = {
        "LOW": [
            "No urgent threat or payment demand detected",
            "No suspicious link or sensitive information request detected",
            "Message does not match known fraud patterns",
        ],
        "MEDIUM": [
            "Some details are ambiguous and should be verified",
            "The message contains a request that could be misused",
            "Independent confirmation is recommended before acting",
        ],
        "HIGH": [
            "Strong fraud signals were detected",
            "The message pressures the user to act quickly",
            "The message could lead to account or money loss",
        ],
    }[level]
    cleaned = cleaned + [r for r in fallback if r not in cleaned]
    return cleaned[:3]


def _top_reasons(primary: list[str], secondary: list[str]) -> list[str]:
    combined = []
    for reason in primary + secondary:
        reason = str(reason).strip()
        if reason and reason not in combined:
            combined.append(reason)
    return combined[:3]


def _summary_for_rules(rules: RuleVerdict, level: str) -> str:
    if level == "HIGH":
        fraud = (rules.fraud_type or "fraud").replace("_", " ")
        return f"This is a likely {fraud} attempt with strong warning signs."
    if level == "MEDIUM":
        return "This message has suspicious elements and should be verified before you act."
    if rules.safe_reasons:
        return "This appears to be a legitimate message with no clear fraud request."
    return "This appears to be a normal message with no clear fraud indicators."


def _action_for_level(level: str, fraud_type: Optional[str] = None) -> str:
    if level == "HIGH":
        if fraud_type in {"bank_phishing", "credential_theft", "phishing"}:
            return "Do not click the link or share details; contact the company only through its official app, website, or phone number."
        return "Do not act on this message; verify through a trusted channel and block or report the sender if needed."
    if level == "MEDIUM":
        return "Pause and verify the sender through a separate trusted channel before clicking links, sharing details, or sending money."
    return "This looks safe, but keep using official websites or apps for any sensitive action."
