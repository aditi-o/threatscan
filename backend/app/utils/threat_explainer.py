"""
Threat Explainer Module for ThreatScan.

Provides human-readable explanations for URL threats, URL decomposition,
attack pattern detection, and multilingual support.
"""

from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import re


# ========================
# Language Templates
# ========================

TRANSLATIONS = {
    "en": {
        # Attack Pattern Names
        "double_tld": "Double TLD Deception",
        "brand_impersonation": "Brand Impersonation",
        "excessive_hyphens": "Excessive Hyphens",
        "excessive_dots": "Excessive Dots",
        "ip_address": "IP Address Instead of Domain",
        "suspicious_tld": "Suspicious TLD",
        "url_too_long": "URL Obfuscation",
        "encoded_chars": "Encoded Characters",
        "subdomain_brand": "Brand in Subdomain",
        "punycode": "Punycode/Homograph Attack",
        "port_number": "Non-Standard Port",
        "data_uri": "Data URI Scheme",
        
        # Reason Templates
        "reason_double_tld": "The link contains more than one extension (like .com.com), which is commonly used in phishing",
        "reason_brand_subdomain": "The brand name appears in the subdomain, not the real domain - this is a common trick",
        "reason_excessive_hyphens": "Too many hyphens in the domain make it look suspicious",
        "reason_excessive_dots": "Excessive dots suggest an attempt to hide the real domain",
        "reason_ip_address": "Using an IP address instead of a domain name is unusual and often malicious",
        "reason_suspicious_tld": "The domain uses a top-level domain commonly associated with spam or abuse",
        "reason_url_long": "Unusually long URLs may be trying to hide malicious parts",
        "reason_encoded_chars": "Encoded characters can be used to disguise malicious URLs",
        "reason_subdomain_brand": "A legitimate brand name appears before the actual domain - this is deceptive",
        "reason_punycode": "The URL uses special characters that look like letters to trick you",
        "reason_port_number": "Non-standard port numbers are rarely used by legitimate websites",
        "reason_no_https": "The link does not use secure HTTPS - your data may not be protected",
        
        # Explanation Templates
        "explanation_malicious": "This link is designed to look like {brand} but is actually controlled by a different domain.",
        "explanation_suspicious": "This link shows some signs of being potentially misleading or unsafe.",
        "explanation_safe": "This link appears to be legitimate with no obvious signs of deception.",
        
        # Safety Tips
        "tip_double_tld": "Always check the domain extension. A real site like google.com will never be google.com.com.",
        "tip_brand_subdomain": "If a link uses a brand name but does not end with the official domain, avoid clicking it.",
        "tip_ip_address": "Legitimate websites always use domain names, not IP addresses. Be very careful.",
        "tip_general": "When in doubt, go directly to the official website by typing the address yourself.",
        "tip_verify": "Verify the URL by hovering over links before clicking, and look for the lock icon in your browser.",
        "tip_no_https": "Only enter sensitive information on websites that show a padlock icon in the browser.",
    },
    "hi": {
        # Attack Pattern Names (Hindi)
        "double_tld": "डबल TLD धोखा",
        "brand_impersonation": "ब्रांड प्रतिरूपण",
        "excessive_hyphens": "अत्यधिक हाइफ़न",
        "excessive_dots": "अत्यधिक डॉट्स",
        "ip_address": "डोमेन के बजाय IP पता",
        "suspicious_tld": "संदिग्ध TLD",
        "url_too_long": "URL भ्रम",
        "encoded_chars": "एन्कोडेड अक्षर",
        "subdomain_brand": "सबडोमेन में ब्रांड",
        "punycode": "पुनीकोड/होमोग्राफ़ हमला",
        "port_number": "गैर-मानक पोर्ट",
        "data_uri": "डेटा URI स्कीम",
        
        # Reason Templates (Hindi)
        "reason_double_tld": "इस लिंक में एक से अधिक एक्सटेंशन (.com.com जैसे) है, जो फ़िशिंग में आम है",
        "reason_brand_subdomain": "ब्रांड का नाम सबडोमेन में है, असली डोमेन में नहीं - यह एक आम चाल है",
        "reason_excessive_hyphens": "डोमेन में बहुत सारे हाइफ़न इसे संदिग्ध बनाते हैं",
        "reason_excessive_dots": "अत्यधिक डॉट्स असली डोमेन छिपाने का प्रयास दर्शाते हैं",
        "reason_ip_address": "डोमेन नाम के बजाय IP पता का उपयोग असामान्य और अक्सर दुर्भावनापूर्ण होता है",
        "reason_suspicious_tld": "यह डोमेन स्पैम या दुरुपयोग से जुड़े TLD का उपयोग करता है",
        "reason_url_long": "असामान्य रूप से लंबे URL दुर्भावनापूर्ण भागों को छिपाने की कोशिश कर सकते हैं",
        "reason_encoded_chars": "एन्कोडेड अक्षर दुर्भावनापूर्ण URL को छिपाने के लिए उपयोग किए जा सकते हैं",
        "reason_subdomain_brand": "एक वैध ब्रांड नाम वास्तविक डोमेन से पहले दिखाई देता है - यह धोखाधड़ी है",
        "reason_punycode": "URL विशेष अक्षरों का उपयोग करता है जो अक्षरों जैसे दिखते हैं",
        "reason_port_number": "गैर-मानक पोर्ट नंबर वैध वेबसाइटों द्वारा शायद ही उपयोग किए जाते हैं",
        "reason_no_https": "यह लिंक सुरक्षित HTTPS का उपयोग नहीं करता - आपका डेटा सुरक्षित नहीं हो सकता",
        
        # Explanation Templates (Hindi)
        "explanation_malicious": "यह लिंक {brand} जैसा दिखने के लिए डिज़ाइन किया गया है लेकिन वास्तव में एक अलग डोमेन द्वारा नियंत्रित है।",
        "explanation_suspicious": "यह लिंक संभावित रूप से भ्रामक या असुरक्षित होने के कुछ संकेत दिखाता है।",
        "explanation_safe": "यह लिंक वैध प्रतीत होता है और धोखे के कोई स्पष्ट संकेत नहीं हैं।",
        
        # Safety Tips (Hindi)
        "tip_double_tld": "हमेशा डोमेन एक्सटेंशन जांचें। google.com जैसी असली साइट कभी google.com.com नहीं होगी।",
        "tip_brand_subdomain": "अगर कोई लिंक ब्रांड नाम का उपयोग करता है लेकिन आधिकारिक डोमेन पर समाप्त नहीं होता, तो क्लिक न करें।",
        "tip_ip_address": "वैध वेबसाइटें हमेशा डोमेन नाम का उपयोग करती हैं, IP पते का नहीं। बहुत सावधान रहें।",
        "tip_general": "संदेह होने पर, पता खुद टाइप करके सीधे आधिकारिक वेबसाइट पर जाएं।",
        "tip_verify": "क्लिक करने से पहले लिंक पर होवर करके URL सत्यापित करें, और अपने ब्राउज़र में लॉक आइकन देखें।",
        "tip_no_https": "संवेदनशील जानकारी केवल उन वेबसाइटों पर दर्ज करें जो ब्राउज़र में पैडलॉक आइकन दिखाती हैं।",
    },
    "mr": {
        # Attack Pattern Names (Marathi)
        "double_tld": "डबल TLD फसवणूक",
        "brand_impersonation": "ब्रँड प्रतिरूपण",
        "excessive_hyphens": "जास्त हायफन",
        "excessive_dots": "जास्त डॉट्स",
        "ip_address": "डोमेन ऐवजी IP पत्ता",
        "suspicious_tld": "संशयास्पद TLD",
        "url_too_long": "URL गोंधळ",
        "encoded_chars": "एन्कोडेड अक्षरे",
        "subdomain_brand": "सबडोमेनमध्ये ब्रँड",
        "punycode": "प्युनीकोड/होमोग्राफ हल्ला",
        "port_number": "असामान्य पोर्ट",
        "data_uri": "डेटा URI स्कीम",
        
        # Reason Templates (Marathi)
        "reason_double_tld": "या लिंकमध्ये एकापेक्षा जास्त एक्स्टेंशन (.com.com सारखे) आहे, जे फिशिंगमध्ये सामान्य आहे",
        "reason_brand_subdomain": "ब्रँडचे नाव सबडोमेनमध्ये आहे, खऱ्या डोमेनमध्ये नाही - ही एक सामान्य युक्ती आहे",
        "reason_excessive_hyphens": "डोमेनमध्ये खूप जास्त हायफन ते संशयास्पद बनवतात",
        "reason_excessive_dots": "जास्त डॉट्स खरे डोमेन लपवण्याचा प्रयत्न दर्शवतात",
        "reason_ip_address": "डोमेन नावाऐवजी IP पत्ता वापरणे असामान्य आणि बहुतेक वेळा दुर्भावनापूर्ण असते",
        "reason_suspicious_tld": "हा डोमेन स्पॅम किंवा गैरवापराशी संबंधित TLD वापरतो",
        "reason_url_long": "असामान्यपणे लांब URLs दुर्भावनापूर्ण भाग लपवण्याचा प्रयत्न करू शकतात",
        "reason_encoded_chars": "एन्कोडेड अक्षरे दुर्भावनापूर्ण URLs वेष बदलण्यासाठी वापरली जाऊ शकतात",
        "reason_subdomain_brand": "एक वैध ब्रँड नाव वास्तविक डोमेन आधी दिसते - हे फसवणूक आहे",
        "reason_punycode": "URL विशेष अक्षरे वापरतो जी अक्षरांसारखी दिसतात",
        "reason_port_number": "असामान्य पोर्ट नंबर वैध वेबसाइट्स क्वचितच वापरतात",
        "reason_no_https": "हा लिंक सुरक्षित HTTPS वापरत नाही - तुमचा डेटा सुरक्षित नसू शकतो",
        
        # Explanation Templates (Marathi)
        "explanation_malicious": "हा लिंक {brand} सारखा दिसण्यासाठी डिझाइन केला आहे पण प्रत्यक्षात वेगळ्या डोमेनद्वारे नियंत्रित आहे।",
        "explanation_suspicious": "हा लिंक संभाव्य भ्रामक किंवा असुरक्षित असल्याची काही चिन्हे दर्शवतो।",
        "explanation_safe": "हा लिंक वैध दिसतो आणि फसवणुकीची कोणतीही स्पष्ट चिन्हे नाहीत।",
        
        # Safety Tips (Marathi)
        "tip_double_tld": "नेहमी डोमेन एक्स्टेंशन तपासा. google.com सारखी खरी साइट कधीही google.com.com नसेल।",
        "tip_brand_subdomain": "जर एखादा लिंक ब्रँड नाव वापरतो पण अधिकृत डोमेनवर संपत नाही, तर क्लिक करू नका।",
        "tip_ip_address": "वैध वेबसाइट्स नेहमी डोमेन नाव वापरतात, IP पत्ते नाही. खूप सावध रहा।",
        "tip_general": "शंका असल्यास, पत्ता स्वतः टाइप करून थेट अधिकृत वेबसाइटवर जा।",
        "tip_verify": "क्लिक करण्यापूर्वी लिंकवर होवर करून URL सत्यापित करा, आणि तुमच्या ब्राउझरमध्ये लॉक आयकॉन शोधा।",
        "tip_no_https": "संवेदनशील माहिती फक्त त्या वेबसाइट्सवर प्रविष्ट करा ज्या ब्राउझरमध्ये पॅडलॉक आयकॉन दाखवतात।",
    }
}

# Common brand names to detect
KNOWN_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft", "paypal", "netflix",
    "instagram", "twitter", "linkedin", "whatsapp", "youtube", "gmail", "yahoo",
    "outlook", "dropbox", "adobe", "spotify", "uber", "airbnb", "ebay",
    "walmart", "target", "costco", "chase", "wellsfargo", "bankofamerica",
    "citibank", "amex", "visa", "mastercard", "paytm", "phonepe", "gpay",
    "sbi", "hdfc", "icici", "axis", "flipkart", "myntra", "swiggy", "zomato"
]

# Suspicious TLDs
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".work", ".click", ".link", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".pw", ".cc", ".ws", ".info", ".biz", ".online", ".site", ".club"
]


def parse_url_breakdown(url: str) -> Dict[str, str]:
    """
    Parse a URL into its components: subdomain, domain, and TLD.
    
    Returns a structured breakdown of the URL.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        
        # Handle IP addresses
        ip_pattern = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
        if ip_pattern.match(hostname):
            return {
                "full_host": hostname,
                "subdomain": "",
                "domain": hostname,
                "tld": "",
                "is_ip": True,
                "registered_domain": hostname,
                "path": parsed.path or "/",
                "port": str(parsed.port) if parsed.port else ""
            }
        
        parts = hostname.lower().split(".")
        
        if len(parts) >= 2:
            # Common multi-part TLDs
            multi_tlds = ["co.uk", "co.in", "com.au", "org.uk", "co.nz", "com.br"]
            
            # Check for multi-part TLD
            if len(parts) >= 3:
                potential_multi_tld = ".".join(parts[-2:])
                if potential_multi_tld in multi_tlds:
                    tld = potential_multi_tld
                    domain = parts[-3]
                    subdomain = ".".join(parts[:-3]) if len(parts) > 3 else ""
                else:
                    tld = parts[-1]
                    domain = parts[-2]
                    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
            else:
                tld = parts[-1]
                domain = parts[-2] if len(parts) >= 2 else parts[0]
                subdomain = ""
            
            registered_domain = f"{domain}.{tld}"
            
            return {
                "full_host": hostname,
                "subdomain": subdomain,
                "domain": domain,
                "tld": tld,
                "is_ip": False,
                "registered_domain": registered_domain,
                "path": parsed.path or "/",
                "port": str(parsed.port) if parsed.port else ""
            }
        else:
            return {
                "full_host": hostname,
                "subdomain": "",
                "domain": hostname,
                "tld": "",
                "is_ip": False,
                "registered_domain": hostname,
                "path": parsed.path or "/",
                "port": str(parsed.port) if parsed.port else ""
            }
    except Exception:
        return {
            "full_host": url,
            "subdomain": "",
            "domain": url,
            "tld": "",
            "is_ip": False,
            "registered_domain": url,
            "path": "/",
            "port": ""
        }


def detect_attack_patterns(url: str, breakdown: Dict[str, str]) -> List[Dict[str, str]]:
    """
    Detect common phishing attack patterns in the URL.
    
    Returns a list of detected attack patterns with their internal keys.
    """
    patterns = []
    hostname = breakdown.get("full_host", "").lower()
    subdomain = breakdown.get("subdomain", "").lower()
    domain = breakdown.get("domain", "").lower()
    tld = breakdown.get("tld", "").lower()
    
    # 1. Double TLD Deception (e.g., google.com.tk)
    tld_extensions = [".com", ".net", ".org", ".edu", ".gov", ".co"]
    tld_count = sum(1 for ext in tld_extensions if ext[1:] in hostname.split("."))
    if tld_count >= 2:
        patterns.append({"key": "double_tld", "brand": None})
    
    # 2. Brand in Subdomain (e.g., google.com.malicious.com)
    detected_brand = None
    for brand in KNOWN_BRANDS:
        if brand in subdomain and brand not in domain:
            detected_brand = brand
            patterns.append({"key": "subdomain_brand", "brand": brand})
            break
        # Also check for brand in any part of hostname but not in registered domain
        if brand in hostname and brand not in breakdown.get("registered_domain", ""):
            detected_brand = brand
            patterns.append({"key": "brand_impersonation", "brand": brand})
            break
    
    # 3. Excessive Hyphens
    if hostname.count("-") >= 3:
        patterns.append({"key": "excessive_hyphens", "brand": None})
    
    # 4. Excessive Dots
    if hostname.count(".") >= 4:
        patterns.append({"key": "excessive_dots", "brand": None})
    
    # 5. IP Address
    if breakdown.get("is_ip"):
        patterns.append({"key": "ip_address", "brand": None})
    
    # 6. Suspicious TLD
    if f".{tld}" in SUSPICIOUS_TLDS:
        patterns.append({"key": "suspicious_tld", "brand": None})
    
    # 7. URL Too Long
    if len(url) > 100:
        patterns.append({"key": "url_too_long", "brand": None})
    
    # 8. Encoded Characters
    if "%" in url and re.search(r'%[0-9a-fA-F]{2}', url):
        patterns.append({"key": "encoded_chars", "brand": None})
    
    # 9. Punycode/Homograph
    if "xn--" in hostname:
        patterns.append({"key": "punycode", "brand": None})
    
    # 10. Non-standard Port
    port = breakdown.get("port", "")
    if port and port not in ["", "80", "443"]:
        patterns.append({"key": "port_number", "brand": None})
    
    # 11. No HTTPS
    if not url.lower().startswith("https://"):
        patterns.append({"key": "no_https", "brand": None})
    
    return patterns


def get_text(lang: str, key: str, default: str = "") -> str:
    """Get translated text for a key."""
    translations = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    return translations.get(key, TRANSLATIONS["en"].get(key, default))


def generate_reasons(
    attack_patterns: List[Dict[str, str]], 
    lang: str = "en"
) -> List[str]:
    """
    Generate human-readable reasons from detected attack patterns.
    """
    reasons = []
    reason_keys = {
        "double_tld": "reason_double_tld",
        "subdomain_brand": "reason_subdomain_brand",
        "brand_impersonation": "reason_brand_subdomain",
        "excessive_hyphens": "reason_excessive_hyphens",
        "excessive_dots": "reason_excessive_dots",
        "ip_address": "reason_ip_address",
        "suspicious_tld": "reason_suspicious_tld",
        "url_too_long": "reason_url_long",
        "encoded_chars": "reason_encoded_chars",
        "punycode": "reason_punycode",
        "port_number": "reason_port_number",
        "no_https": "reason_no_https",
    }
    
    for pattern in attack_patterns:
        key = pattern.get("key", "")
        if key in reason_keys:
            reasons.append(get_text(lang, reason_keys[key]))
    
    return reasons


def generate_explanation(
    attack_patterns: List[Dict[str, str]], 
    risk_score: int,
    lang: str = "en"
) -> str:
    """
    Generate a summary explanation based on risk level and patterns.
    """
    # Find any detected brand
    brand = None
    for pattern in attack_patterns:
        if pattern.get("brand"):
            brand = pattern["brand"].capitalize()
            break
    
    if risk_score >= 70:
        template = get_text(lang, "explanation_malicious")
        if brand:
            return template.format(brand=brand)
        return template.format(brand="a legitimate website")
    elif risk_score >= 40:
        return get_text(lang, "explanation_suspicious")
    else:
        return get_text(lang, "explanation_safe")


def generate_safety_tip(
    attack_patterns: List[Dict[str, str]], 
    lang: str = "en"
) -> str:
    """
    Generate a safety tip based on the primary attack pattern detected.
    """
    if not attack_patterns:
        return get_text(lang, "tip_verify")
    
    tip_mapping = {
        "double_tld": "tip_double_tld",
        "subdomain_brand": "tip_brand_subdomain",
        "brand_impersonation": "tip_brand_subdomain",
        "ip_address": "tip_ip_address",
        "no_https": "tip_no_https",
    }
    
    for pattern in attack_patterns:
        key = pattern.get("key", "")
        if key in tip_mapping:
            return get_text(lang, tip_mapping[key])
    
    return get_text(lang, "tip_general")


def get_attack_pattern_names(
    attack_patterns: List[Dict[str, str]], 
    lang: str = "en"
) -> List[str]:
    """
    Convert attack pattern keys to human-readable names in the specified language.
    """
    names = []
    for pattern in attack_patterns:
        key = pattern.get("key", "")
        name = get_text(lang, key)
        if name and name not in names:
            names.append(name)
    return names


def analyze_url_threats(url: str, lang: str = "en") -> Dict:
    """
    Complete threat analysis for a URL.
    
    Returns:
        - url_breakdown: Decomposed URL parts
        - attack_patterns: List of detected attack pattern names
        - reasons: Human-readable explanations
        - explanation: Summary of the threat
        - safety_tip: Educational tip for the user
    """
    # Parse URL breakdown
    breakdown = parse_url_breakdown(url)
    
    # Detect attack patterns
    patterns = detect_attack_patterns(url, breakdown)
    
    # Generate human-readable content
    attack_pattern_names = get_attack_pattern_names(patterns, lang)
    reasons = generate_reasons(patterns, lang)
    
    # We'll need risk_score from the caller, so this returns partial data
    return {
        "url_breakdown": breakdown,
        "attack_patterns": attack_pattern_names,
        "attack_pattern_keys": patterns,  # Internal use for explanation/tips
        "reasons": reasons,
    }


def get_full_threat_analysis(
    url: str, 
    risk_score: int, 
    lang: str = "en"
) -> Dict:
    """
    Get complete threat analysis including risk-score-dependent fields.
    """
    partial = analyze_url_threats(url, lang)
    patterns = partial.get("attack_pattern_keys", [])
    
    return {
        "url_breakdown": partial["url_breakdown"],
        "attack_patterns": partial["attack_patterns"],
        "reasons": partial["reasons"],
        "explanation": generate_explanation(patterns, risk_score, lang),
        "safety_tip": generate_safety_tip(patterns, lang),
    }
