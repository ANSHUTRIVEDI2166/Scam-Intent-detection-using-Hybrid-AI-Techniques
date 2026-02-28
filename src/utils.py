"""
Utility functions for the Scammer Detector Honeypot System.
"""

import re
import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from src.config import config


def extract_bank_accounts(text: str) -> List[str]:
    """Extract potential bank account numbers from text.
    Bank accounts are typically 9-18 digits, but we must NOT confuse them with phone numbers.
    Phone numbers: exactly 10 digits starting with 6-9 (Indian) or prefixed with +91.
    """
    # First, find all phone numbers so we can exclude them
    phone_patterns = [
        r'\+91[-\s]?\d{10}',
        r'\b[6-9]\d{9}\b',
        r'\b\d{5}[-\s]\d{5}\b',
    ]
    phone_numbers = set()
    for pp in phone_patterns:
        for m in re.finditer(pp, text):
            # Store the raw digits
            phone_numbers.add(re.sub(r'[^\d]', '', m.group()))
    
    # Bank account patterns
    patterns = [
        r'\b\d{11,18}\b',  # 11-18 digit account numbers (above phone length)
        r'\b\d{9,10}\b',   # 9-10 digit accounts (need to filter phones)
        r'\b\d{4}[-\s]\d{4}[-\s]\d{4,10}\b',  # Formatted: 1234-5678-9012
    ]
    
    # Context keywords that suggest a bank account
    account_context = re.compile(
        r'(?:account|a/c|acct|transfer|deposit|bank|neft|imps|rtgs|ifsc)',
        re.IGNORECASE
    )
    
    accounts = []
    for pattern in patterns:
        for m in re.finditer(pattern, text):
            raw_digits = re.sub(r'[^\d]', '', m.group())
            
            # Skip if it matches a known phone number
            if raw_digits in phone_numbers:
                continue
            # Skip if it's a 10-digit number starting with 6-9 (likely a phone)
            if len(raw_digits) == 10 and raw_digits[0] in '6789':
                continue
            # For 9-10 digit numbers, require context keywords nearby
            if len(raw_digits) <= 10:
                start = max(0, m.start() - 80)
                end = min(len(text), m.end() + 80)
                context = text[start:end]
                if not account_context.search(context):
                    continue
            accounts.append(m.group().strip())
    
    return list(set(accounts))


def extract_upi_ids(text: str) -> List[str]:
    """Extract UPI IDs from text. Filter out regular email addresses."""
    # UPI ID pattern: user@bank
    pattern = r'\b[\w\.\-]+@[\w]+\b'
    matches = re.findall(pattern, text)
    
    # Also find all email addresses (user@domain.tld) to exclude them
    email_pattern = r'\b[\w\.\-\+]+@[\w\-]+\.[\w\.\-]+\b'
    email_matches = set(m.lower() for m in re.findall(email_pattern, text))
    
    # Known UPI handles/providers
    upi_handles = [
        'paytm', 'phonepe', 'gpay', 'ybl', 'okhdfcbank', 'okicici',
        'okaxis', 'oksbi', 'upi', 'apl', 'axl', 'ibl', 'sbi',
        'hdfcbank', 'icici', 'axisbank', 'kotak', 'boi', 'pnb',
        'canarabank', 'unionbank', 'indianbank', 'idfcbank',
        'freecharge', 'mobikwik', 'airtel', 'jio', 'slice',
        'jupiteraxis', 'rbl', 'federalbank', 'indus', 'dbs',
        'hsbc', 'citi', 'sc', 'barodampay', 'mahb',
        'abfspay', 'waaxis', 'wahdfcbank', 'waicici', 'wasbi',
        'yesbankltd', 'aubank', 'dlb', 'kbl', 'kvb',
        'fakebank', 'fakeupi',
    ]
    
    # Known email domains to EXCLUDE
    email_domains = [
        'gmail', 'yahoo', 'hotmail', 'outlook', 'protonmail', 'rediffmail',
        'aol', 'icloud', 'mail', 'zoho', 'yandex', 'live', 'msn',
        'email', 'inbox', 'fastmail', 'tutanota', 'pm', 'hey',
        'proton', 'duck', 'mailfence',
    ]
    
    upi_ids = []
    for match in matches:
        match_lower = match.lower()
        handle = match_lower.split('@')[1] if '@' in match_lower else ''
        
        # Skip if this match is a substring of an email address
        is_email_part = False
        for em in email_matches:
            if match_lower in em and match_lower != em:
                is_email_part = True
                break
        if is_email_part:
            continue
        
        # Skip if it looks like an email domain
        if handle in email_domains:
            continue
        # Skip common email suffixes (has dot in domain part)
        if '.' in match_lower.split('@')[1] if '@' in match_lower else False:
            continue
        # Accept if it matches a known UPI handle
        if any(h in handle for h in upi_handles):
            upi_ids.append(match_lower)
        # Accept if handle looks like a bank abbreviation (short, no dots)
        elif len(handle) <= 12 and '.' not in handle and handle not in email_domains:
            upi_ids.append(match_lower)
    
    return list(set(upi_ids))


def extract_phone_numbers(text: str) -> List[str]:
    """Extract phone numbers from text. Indian phone numbers start with 6-9."""
    patterns = [
        r'\+91[-\s]?\d{10}',           # +91 prefix
        r'\b0\d{10}\b',                 # 0-prefixed STD
        r'\b[6-9]\d{9}\b',              # 10 digit starting with 6-9
        r'\b[6-9]\d{4}[-\s]\d{5}\b',    # 5-5 format starting with 6-9
        r'\b\d{3,5}[-\s]\d{3,5}[-\s]\d{4}\b',  # xxx-xxx-xxxx style
    ]
    
    numbers = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        numbers.extend(matches)
    
    # Normalize: strip +91, leading 0, spaces/dashes for dedup
    normalized = set()
    result = []
    for num in numbers:
        clean = re.sub(r'[^\d]', '', num)
        had_91_prefix = clean.startswith('91') and len(clean) == 12
        if had_91_prefix:
            clean = clean[2:]
        if clean.startswith('0') and len(clean) == 11:
            clean = clean[1:]
        # Accept: 10 digits starting with 6-9, OR explicitly prefixed with +91
        if len(clean) == 10 and (clean[0] in '6789' or had_91_prefix) and clean not in normalized:
            normalized.add(clean)
            result.append(num.strip())
    
    return result


def extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    # First, collect all email addresses so we can exclude their domains
    email_full_pattern = r'\b[\w\.\-\+]+@[\w\-]+(?:\.[\w\-]+)+\b'
    email_matches = re.findall(email_full_pattern, text, re.IGNORECASE)
    # Build set of email domain parts (e.g. "cyber.gov.in" from "officer@cyber.gov.in")
    email_domains = set()
    for em in email_matches:
        domain_part = em.split('@')[1].lower()
        email_domains.add(domain_part)
        # Also add sub-parts (e.g. "gov.in" from "cyber.gov.in")
        parts = domain_part.split('.')
        for i in range(len(parts) - 1):
            email_domains.add('.'.join(parts[i:]))
    
    # URL pattern - explicit http(s)
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(pattern, text)
    
    # Also catch domain-like patterns without http
    domain_pattern = r'\b(?:www\.)?[\w\-]+\.(?:com|in|net|org|co|info|xyz|tk|ml|ga|cf|gq)[^\s]*'
    domains = re.findall(domain_pattern, text.lower())
    
    # Filter out domains that are part of email addresses
    filtered_domains = []
    for d in domains:
        d_clean = d.rstrip('.,;:!?)\"\'>}')
        if d_clean in email_domains:
            continue  # This is part of an email, not a standalone URL
        # Also check if the domain is a suffix of any email domain
        is_email_domain = False
        for ed in email_domains:
            if ed.endswith(d_clean) or d_clean.endswith(ed):
                is_email_domain = True
                break
        if is_email_domain:
            continue
        filtered_domains.append(d)
    
    all_urls = urls + [f"http://{d}" if not d.startswith('http') else d for d in filtered_domains]
    
    # Strip trailing punctuation from URLs
    cleaned = []
    for url in all_urls:
        # Strip trailing periods, commas, semicolons, etc.
        url = url.rstrip('.,;:!?)\"\'>}')
        # Also strip trailing period that might be inside the URL
        while url.endswith('.'):
            url = url[:-1]
        if url and len(url) > 4:
            cleaned.append(url)
    
    return list(set(cleaned))


def extract_suspicious_keywords(text: str) -> List[str]:
    """Extract suspicious scam-related keywords from text."""
    suspicious_words = [
        # Urgency
        'urgent', 'immediately', 'now', 'today', 'expire', 'expiring', 'limited time',
        'hurry', 'fast', 'quick', 'deadline', 'last chance', 'final notice',
        'within 24 hours', 'time is running out', 'act now', 'don\'t delay',
        # Threats
        'blocked', 'suspended', 'terminated', 'deactivated', 'frozen', 'locked',
        'will be closed', 'legal action', 'arrest', 'warrant', 'penalty', 'fine',
        'seized', 'compromised', 'hacked', 'unauthorized',
        # Verification / KYC
        'verify', 'confirm', 'validate', 'authenticate', 'update',
        'kyc', 'pan card', 'aadhaar', 'identity verification',
        're-verify', 'reactivate', 'reverify',
        # Financial
        'account', 'bank', 'payment', 'transaction', 'refund', 'credit', 'debit',
        'upi', 'wallet', 'paytm', 'phonepe', 'gpay', 'neft', 'imps', 'rtgs',
        'transfer', 'deposit', 'withdraw', 'balance',
        # Sensitive data requests
        'otp', 'password', 'pin', 'cvv', 'card number', 'account number',
        'ifsc', 'atm pin', 'net banking', 'internet banking', 'login',
        'credentials', 'secret', 'security code', 'mpin',
        # Rewards / Offers / Lottery
        'prize', 'winner', 'congratulations', 'won', 'reward', 'gift', 'cashback',
        'lottery', 'lucky', 'selected', 'chosen', 'bonus', 'free', 'offer',
        'claim', 'redeem', 'coupon', 'voucher', 'discount',
        # Authority impersonation
        'police', 'government', 'officer', 'department', 'ministry',
        'rbi', 'reserve bank', 'income tax', 'customs', 'court',
        'cbi', 'cyber cell', 'narcotics', 'enforcement',
        # Actions
        'click here', 'call now', 'send', 'share', 'provide', 'enter',
        'download', 'install', 'open link', 'visit', 'tap here',
        'reply with', 'forward', 'submit',
        # Impersonation cues
        'dear customer', 'dear user', 'dear sir', 'dear madam',
        'we have noticed', 'we detected', 'your account has',
        'this is to inform', 'important notice', 'alert',
        # Money / payment
        'processing fee', 'registration fee', 'advance payment',
        'pay now', 'send money', 'money transfer',
    ]
    
    text_lower = text.lower()
    found_keywords = [word for word in suspicious_words if word in text_lower]
    
    return list(set(found_keywords))


def extract_email_addresses(text: str) -> List[str]:
    """Extract email addresses from text. Filter out UPI IDs.
    
    Email addresses have a dot in the domain (user@domain.tld).
    UPI IDs do NOT have a dot in the handle (user@bankhandle).
    """
    # Email pattern: user@domain.tld (domain MUST have a dot)
    pattern = r'\b[\w\.\-\+]+@[\w\-]+\.[\w\.\-]+\b'
    matches = re.findall(pattern, text)
    
    # Known UPI handles to EXCLUDE from email list
    upi_handles = [
        'paytm', 'phonepe', 'gpay', 'ybl', 'okhdfcbank', 'okicici',
        'okaxis', 'oksbi', 'upi', 'apl', 'axl', 'ibl', 'sbi',
        'hdfcbank', 'icici', 'axisbank', 'kotak', 'boi', 'pnb',
    ]
    
    emails = []
    for match in matches:
        match_lower = match.lower().rstrip('.')
        if '@' not in match_lower:
            continue
        domain = match_lower.split('@')[1]
        # Skip if it looks like a UPI handle
        base_domain = domain.split('.')[0] if '.' in domain else domain
        if base_domain in upi_handles:
            continue
        # Must have a valid TLD
        if '.' in domain:
            emails.append(match_lower)
    
    return list(set(emails))


def extract_all_intelligence(text: str) -> Dict[str, Any]:
    """Extract all intelligence from a text message."""
    return {
        "bankAccounts": extract_bank_accounts(text),
        "upiIds": extract_upi_ids(text),
        "phishingLinks": extract_urls(text),
        "phoneNumbers": extract_phone_numbers(text),
        "emailAddresses": extract_email_addresses(text),
        "suspiciousKeywords": extract_suspicious_keywords(text),
        "extractionConfidence": 0.8  # Default confidence
    }


def save_session_to_json(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Save extracted session intelligence to local JSON files.

    Writes two files:
    - data/sessions/{sessionId}.json  – full session record
    - data/intelligence_log.json      – running log of all sessions

    Args:
        payload: Session result payload

    Returns:
        Dict with status and file path, or error info
    """
    try:
        data_dir = config.DATA_DIR
        sessions_dir = os.path.join(data_dir, "sessions")
        os.makedirs(sessions_dir, exist_ok=True)

        session_id = payload.get("sessionId", "unknown")
        payload["savedAt"] = datetime.utcnow().isoformat()

        # 1. Individual session file
        session_file = os.path.join(sessions_dir, f"{session_id}.json")
        with open(session_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        # 2. Append to global intelligence log
        log_file = os.path.join(data_dir, "intelligence_log.json")
        log: List[Dict] = []
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    log = json.load(f)
            except (json.JSONDecodeError, IOError):
                log = []

        # Replace existing entry for this session or append new one
        updated = False
        for i, entry in enumerate(log):
            if entry.get("sessionId") == session_id:
                log[i] = payload
                updated = True
                break
        if not updated:
            log.append(payload)

        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(log, f, indent=2, ensure_ascii=False)

        print(f"[JSON STORAGE] Saved session {session_id} → {session_file}")
        return {
            "status": "success",
            "session_file": session_file,
            "log_file": log_file
        }

    except Exception as e:
        print(f"[JSON STORAGE] Error saving session: {str(e)}")
        return {
            "status": "error",
            "error": str(e)
        }


def calculate_intelligence_score(intelligence: Dict[str, List[str]]) -> int:
    """
    Calculate a score based on the amount of intelligence extracted.
    
    Args:
        intelligence: Extracted intelligence dictionary
    
    Returns:
        Score (number of non-empty intelligence categories)
    """
    score = 0
    
    if intelligence.get("bankAccounts"):
        score += 1
    if intelligence.get("upiIds"):
        score += 1
    if intelligence.get("phishingLinks"):
        score += 1
    if intelligence.get("phoneNumbers"):
        score += 1
    if intelligence.get("emailAddresses"):
        score += 1
    if intelligence.get("suspiciousKeywords"):
        score += 1
    
    return score


def parse_llm_json_response(response_text: str) -> Optional[Dict[str, Any]]:
    """
    Parse JSON from LLM response, handling markdown code blocks and extra text.
    
    Args:
        response_text: Raw LLM response
    
    Returns:
        Parsed JSON dictionary or None
    """
    # Remove markdown code blocks if present
    text = response_text.strip()
    
    # Remove ```json and ``` markers
    if text.startswith('```'):
        text = re.sub(r'^```(?:json)?\s*\n', '', text)
        text = re.sub(r'\n```\s*$', '', text)
    
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        # Try to extract JSON from the text
        # Look for the first { and last } to extract just the JSON part
        try:
            start = text.find('{')
            end = text.rfind('}') + 1
            if start != -1 and end > start:
                json_text = text[start:end]
                return json.loads(json_text)
        except:
            pass
        
        print(f"JSON parse error: {e}")
        print(f"Response text (first 500 chars): {text[:500]}")
        return None


def format_timestamp(timestamp: Optional[int] = None) -> str:
    """
    Format timestamp to ISO format.
    
    Args:
        timestamp: Unix timestamp in milliseconds
    
    Returns:
        ISO formatted timestamp string
    """
    if timestamp:
        dt = datetime.fromtimestamp(timestamp / 1000)
        return dt.isoformat()
    return datetime.utcnow().isoformat()


def is_intelligence_sufficient(intelligence: Dict[str, List[str]], min_categories: int = 5) -> bool:
    """
    Check if sufficient intelligence has been extracted.
    
    Args:
        intelligence: Extracted intelligence
        min_categories: Minimum number of intelligence categories needed
    
    Returns:
        True if intelligence is sufficient
    """
    score = calculate_intelligence_score(intelligence)
    return score >= min_categories
