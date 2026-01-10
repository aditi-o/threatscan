"""
Chat router for SafeLink Shield.
Provides AI-powered scam assistance chatbot with context-aware responses.

Features:
- Explains scan results in simple, non-technical language
- Answers questions about phishing and URL safety
- Multilingual support (English, Hindi, Marathi)
- Context-aware responses based on recent scans
"""

import uuid
import json
from typing import Optional, Dict, Any, List, Tuple

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from app.config import settings
from pydantic import BaseModel, Field
from app.config import settings

router = APIRouter(prefix="/chat", tags=["Chatbot"])


# ========================
# Schemas
# ========================

class ScanContext(BaseModel):
    """Context from a recent URL scan."""
    url: Optional[str] = None
    risk_score: Optional[int] = None
    verdict: Optional[str] = None
    attack_patterns: Optional[List[str]] = []
    reasons: Optional[List[str]] = []
    explanation: Optional[str] = None
    safety_tip: Optional[str] = None


class ChatRequest(BaseModel):
    """Schema for chatbot requests."""
    message: str = Field(..., max_length=1000)
    conversation_id: Optional[str] = None
    scan_context: Optional[ScanContext] = None
    language: str = Field("en", description="Language: en, hi, mr")


class ChatResponse(BaseModel):
    """Schema for chatbot responses."""

    response: str
    conversation_id: str
    language: str = "en"

    # Diagnostics (safe to expose)
    provider: str = "local"  # openai | huggingface | local
    request_id: str
    warnings: List[str] = Field(default_factory=list)


# ========================
# Multilingual System Prompts
# ========================

SYSTEM_PROMPTS = {
    "en": """You are SafeBot, a friendly and calm cyber safety assistant for ThreatScan.

Your role is to:
1. Explain why URLs might be dangerous in simple, non-technical terms
2. Answer questions about phishing, scams, and online safety
3. Provide clear, actionable safety advice
4. Be supportive and educational - never create fear or panic

Guidelines:
- Use simple language that anyone can understand
- Be calm, friendly, and encouraging
- Focus on education, not alarm
- Provide practical tips users can remember
- Never ask for personal or financial information
- If you're unsure, recommend verifying through official channels

Common topics you help with:
- Why double .com URLs are suspicious
- How phishing links trick users
- What makes a URL look legitimate vs fake
- Safe browsing habits
- What to do if someone clicked a suspicious link""",

    "hi": """आप SafeBot हैं, ThreatScan के लिए एक मित्रवत और शांत साइबर सुरक्षा सहायक।

आपकी भूमिका:
1. URL खतरनाक क्यों हो सकते हैं, सरल भाषा में समझाना
2. फ़िशिंग, स्कैम और ऑनलाइन सुरक्षा के बारे में सवालों के जवाब देना
3. स्पष्ट और व्यावहारिक सुरक्षा सलाह देना
4. सहायक और शैक्षिक होना - कभी डर या घबराहट पैदा न करें

दिशानिर्देश:
- सरल भाषा का उपयोग करें जिसे कोई भी समझ सके
- शांत, मित्रवत और उत्साहजनक रहें
- शिक्षा पर ध्यान दें, डर पर नहीं
- व्यावहारिक सुझाव दें जो उपयोगकर्ता याद रख सकें
- कभी भी व्यक्तिगत या वित्तीय जानकारी न मांगें""",

    "mr": """तुम्ही SafeBot आहात, ThreatScan साठी एक मैत्रीपूर्ण आणि शांत सायबर सुरक्षा सहाय्यक।

तुमची भूमिका:
1. URLs धोकादायक का असू शकतात हे सोप्या भाषेत समजावून सांगणे
2. फिशिंग, स्कॅम आणि ऑनलाइन सुरक्षिततेबद्दल प्रश्नांची उत्तरे देणे
3. स्पष्ट आणि व्यावहारिक सुरक्षा सल्ला देणे
4. सहाय्यक आणि शैक्षणिक असणे - कधीही भीती किंवा घबराट निर्माण करू नका

मार्गदर्शक तत्त्वे:
- सोप्या भाषेचा वापर करा जी कोणीही समजू शकेल
- शांत, मैत्रीपूर्ण आणि प्रोत्साहित करणारे रहा
- शिक्षणावर लक्ष केंद्रित करा, भीतीवर नाही
- व्यावहारिक टिप्स द्या ज्या वापरकर्ते लक्षात ठेवू शकतील"""
}


# ========================
# Knowledge Base (For local responses)
# ========================

SAFETY_KNOWLEDGE = {
    "en": {
        "double_tld": """A double TLD (like .com.com) is suspicious because real websites only have one extension. 
For example, google.com is real, but google.com.com is fake. 
Scammers add extra extensions to make fake URLs look more legitimate.""",

        "brand_impersonation": """Brand impersonation happens when scammers put a famous company name (like Google or PayPal) 
in the subdomain part of a URL. For example, google.fakesite.com is NOT a Google website - 
the real domain is "fakesite.com" and Google is just a label they added to trick you.""",

        "phishing_general": """Phishing is when scammers create fake websites that look like real ones to steal your information.
They might copy the design of your bank's website and trick you into entering your password.
Always check the URL carefully and type important addresses directly instead of clicking links.""",

        "clicked_suspicious": """If you clicked a suspicious link:
1. Don't enter any personal information
2. Close the page immediately
3. Run a virus scan on your device
4. Change passwords if you entered any credentials
5. Monitor your accounts for unusual activity
Don't panic - if you didn't enter information, you're likely safe.""",

        "safe_browsing": """Safe browsing tips:
• Type important URLs directly instead of clicking links
• Look for the padlock icon in your browser
• Check that the URL matches the official website
• Be suspicious of urgent requests for personal information
• When in doubt, contact the company directly through their official website"""
    },
    "hi": {
        "double_tld": """डबल TLD (जैसे .com.com) संदिग्ध है क्योंकि असली वेबसाइटों में केवल एक एक्सटेंशन होता है।
उदाहरण के लिए, google.com असली है, लेकिन google.com.com नकली है।
स्कैमर नकली URLs को वैध दिखाने के लिए अतिरिक्त एक्सटेंशन जोड़ते हैं।""",

        "phishing_general": """फ़िशिंग तब होती है जब स्कैमर आपकी जानकारी चुराने के लिए असली जैसी दिखने वाली नकली वेबसाइट बनाते हैं।
हमेशा URL को ध्यान से जांचें और लिंक पर क्लिक करने के बजाय महत्वपूर्ण पते सीधे टाइप करें।""",

        "safe_browsing": """सुरक्षित ब्राउज़िंग टिप्स:
• लिंक पर क्लिक करने के बजाय महत्वपूर्ण URLs सीधे टाइप करें
• अपने ब्राउज़र में ताले का आइकन देखें
• सुनिश्चित करें कि URL आधिकारिक वेबसाइट से मेल खाता है"""
    },
    "mr": {
        "double_tld": """डबल TLD (जसे .com.com) संशयास्पद आहे कारण खऱ्या वेबसाइट्सला फक्त एक एक्स्टेंशन असते.
उदाहरणार्थ, google.com खरे आहे, पण google.com.com बनावट आहे.""",

        "phishing_general": """फिशिंग म्हणजे जेव्हा स्कॅमर्स तुमची माहिती चोरण्यासाठी खऱ्यासारख्या दिसणाऱ्या बनावट वेबसाइट्स तयार करतात.
नेहमी URL काळजीपूर्वक तपासा आणि लिंकवर क्लिक करण्याऐवजी महत्त्वाचे पत्ते थेट टाइप करा."""
    }
}


def get_local_response(message: str, scan_context: Optional[ScanContext], lang: str) -> str:
    """
    Generate a response using local knowledge base.
    Used as fallback when API is unavailable.
    """
    message_lower = message.lower()
    knowledge = SAFETY_KNOWLEDGE.get(lang, SAFETY_KNOWLEDGE["en"])
    
    # Check for specific questions
    if any(term in message_lower for term in ["double", ".com.com", "tld", "two extensions"]):
        return knowledge.get("double_tld", knowledge.get("phishing_general", ""))
    
    if any(term in message_lower for term in ["brand", "impersonation", "subdomain", "fake name"]):
        return knowledge.get("brand_impersonation", knowledge.get("phishing_general", ""))
    
    if any(term in message_lower for term in ["clicked", "visited", "opened", "what should i do"]):
        return knowledge.get("clicked_suspicious", knowledge.get("safe_browsing", ""))
    
    if any(term in message_lower for term in ["phishing", "how", "trick", "work"]):
        return knowledge.get("phishing_general", "")
    
    if any(term in message_lower for term in ["safe", "tips", "protect", "browse"]):
        return knowledge.get("safe_browsing", "")
    
    # Context-aware response
    if scan_context and scan_context.verdict:
        if scan_context.reasons:
            reasons_text = "\n• ".join(scan_context.reasons[:3])
            if lang == "en":
                return f"""Based on the scan I performed, here's what I found:

• {reasons_text}

{scan_context.safety_tip or "Always verify URLs before clicking. When in doubt, type the address directly."}

Would you like me to explain any of these points in more detail?"""
            elif lang == "hi":
                return f"""मेरे स्कैन के आधार पर, मुझे यह मिला:

• {reasons_text}

{scan_context.safety_tip or "हमेशा क्लिक करने से पहले URLs सत्यापित करें।"}

क्या आप चाहते हैं कि मैं इनमें से किसी को विस्तार से समझाऊं?"""
    
    # Default response
    defaults = {
        "en": """I'm here to help you stay safe online! You can ask me:
• Why certain URLs are suspicious
• How phishing attacks work
• What to do if you clicked a suspicious link
• Tips for safe browsing

Feel free to ask any question about online safety!""",
        "hi": """मैं आपको ऑनलाइन सुरक्षित रहने में मदद करने के लिए यहां हूं! आप मुझसे पूछ सकते हैं:
• कुछ URLs संदिग्ध क्यों हैं
• फ़िशिंग हमले कैसे काम करते हैं
• संदिग्ध लिंक पर क्लिक करने के बाद क्या करें

ऑनलाइन सुरक्षा के बारे में कोई भी सवाल पूछें!""",
        "mr": """मी तुम्हाला ऑनलाइन सुरक्षित राहण्यात मदत करण्यासाठी येथे आहे! तुम्ही मला विचारू शकता:
• काही URLs संशयास्पद का आहेत
• फिशिंग हल्ले कसे काम करतात

ऑनलाइन सुरक्षिततेबद्दल कोणताही प्रश्न विचारा!"""
    }
    
    return defaults.get(lang, defaults["en"])


def build_context_prompt(scan_context: ScanContext, lang: str) -> str:
    """Build context information for the AI from scan results."""
    if not scan_context or not scan_context.url:
        return ""
    
    context_templates = {
        "en": f"""
The user recently scanned this URL: {scan_context.url}
Scan Result: {scan_context.verdict or 'Unknown'} (Risk Score: {scan_context.risk_score or 0}/100)
Attack Patterns Detected: {', '.join(scan_context.attack_patterns or ['None'])}
Key Findings: {'; '.join(scan_context.reasons[:2]) if scan_context.reasons else 'None'}

Use this context to provide relevant, educational responses about why this URL may be risky.""",

        "hi": f"""
उपयोगकर्ता ने हाल ही में इस URL को स्कैन किया: {scan_context.url}
स्कैन परिणाम: {scan_context.verdict or 'अज्ञात'} (जोखिम स्कोर: {scan_context.risk_score or 0}/100)
पता लगाए गए हमले के पैटर्न: {', '.join(scan_context.attack_patterns or ['कोई नहीं'])}

इस संदर्भ का उपयोग करके प्रासंगिक जानकारी प्रदान करें।""",

        "mr": f"""
वापरकर्त्याने अलीकडेच हा URL स्कॅन केला: {scan_context.url}
स्कॅन निकाल: {scan_context.verdict or 'अज्ञात'} (धोका स्कोर: {scan_context.risk_score or 0}/100)

या संदर्भाचा वापर करून संबंधित माहिती द्या."""
    }
    
    return context_templates.get(lang, context_templates["en"])


def _log_chat_event(event: Dict[str, Any]) -> None:
    """Structured logging for /chat without leaking secrets or prompts."""
    safe_event = {
        k: v
        for k, v in event.items()
        if k not in {"api_key", "authorization", "headers", "prompt", "messages"}
    }
    print("CHAT_EVENT " + json.dumps(safe_event, ensure_ascii=False))


def _classify_openai_error(err: Exception) -> Dict[str, Any]:
    msg = str(err)
    status_code = getattr(err, "status_code", None)

    # Heuristic classification (keeps us compatible across OpenAI SDK versions)
    error_type = "unknown"
    if "insufficient_quota" in msg:
        error_type = "insufficient_quota"
    elif "rate_limit" in msg or "Error code: 429" in msg or status_code == 429:
        error_type = "rate_limited"
    elif "401" in msg or status_code == 401:
        error_type = "auth"
    elif "timeout" in msg.lower():
        error_type = "timeout"

    return {
        "error_type": error_type,
        "status_code": status_code,
        "message": msg,
    }


async def try_openai_response(
    *,
    message: str,
    scan_context: Optional[ScanContext],
    lang: str,
    request_id: str,
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Try OpenAI chat completions. Returns (text, error_info)."""
    if not settings.OPENAI_API_KEY:
        return None, {
            "provider": "openai",
            "error_type": "not_configured",
        }

    model = "gpt-3.5-turbo"

    try:
        import openai

        client = openai.AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

        system_prompt = SYSTEM_PROMPTS.get(lang, SYSTEM_PROMPTS["en"])
        if scan_context:
            context_info = build_context_prompt(scan_context, lang)
            system_prompt = f"{system_prompt}\n\n{context_info}" if context_info else system_prompt

        _log_chat_event(
            {
                "request_id": request_id,
                "event": "provider_attempt",
                "provider": "openai",
                "model": model,
            }
        )

        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message},
            ],
            max_tokens=500,
            temperature=0.7,
        )

        text = (response.choices[0].message.content or "").strip()
        if not text:
            return None, {
                "provider": "openai",
                "model": model,
                "error_type": "empty_response",
            }

        return text, None

    except Exception as e:
        info = _classify_openai_error(e)
        _log_chat_event(
            {
                "request_id": request_id,
                "event": "provider_error",
                "provider": "openai",
                "model": model,
                "error_type": info.get("error_type"),
                "status_code": info.get("status_code"),
            }
        )
        return None, {
            "provider": "openai",
            "model": model,
            **info,
        }


# Single stable model for HF Inference API (standard endpoint)
HF_CHAT_MODEL = "google/flan-t5-base"


def _build_hf_prompt(message: str, scan_context: Optional[ScanContext], lang: str) -> str:
    """Build a prompt for HF flan-t5 model."""
    context_info = build_context_prompt(scan_context, lang) if scan_context else ""

    # Build a concise prompt for flan-t5
    parts = [
        "You are SafeBot, a cyber safety assistant.",
        f"Context: {context_info}" if context_info else "",
        f"Question: {message}",
        "Answer helpfully and concisely:"
    ]
    return " ".join(p for p in parts if p)


async def try_hf_response(
    *,
    message: str,
    scan_context: Optional[ScanContext],
    lang: str,
    request_id: str,
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Try Hugging Face Inference API with google/flan-t5-base.
    Uses ONLY the standard api-inference.huggingface.co endpoint.
    """
    if not settings.HF_API_KEY:
        return None, {
            "provider": "huggingface",
            "error_type": "not_configured",
        }

    # Use hf_client for the actual API call
    from app.utils.hf_client import hf_client

    # Build prompt with context
    prompt = _build_hf_prompt(message, scan_context, lang)

    # Log attempt
    _log_chat_event(
        {
            "request_id": request_id,
            "event": "provider_attempt",
            "provider": "huggingface",
            "model": HF_CHAT_MODEL,
            "url": f"https://api-inference.huggingface.co/models/{HF_CHAT_MODEL}",
        }
    )

    try:
        # Use hf_client.generate_chat_response which calls the standard HF API
        response_text = await hf_client.generate_chat_response(prompt)

        if response_text:
            _log_chat_event(
                {
                    "request_id": request_id,
                    "event": "provider_success",
                    "provider": "huggingface",
                    "model": HF_CHAT_MODEL,
                }
            )
            return response_text, None

        # Empty response
        _log_chat_event(
            {
                "request_id": request_id,
                "event": "provider_error",
                "provider": "huggingface",
                "model": HF_CHAT_MODEL,
                "error_type": "empty_response",
            }
        )
        return None, {
            "provider": "huggingface",
            "model": HF_CHAT_MODEL,
            "error_type": "empty_response",
        }

    except Exception as e:
        error_msg = str(e)[:200]
        _log_chat_event(
            {
                "request_id": request_id,
                "event": "provider_error",
                "provider": "huggingface",
                "model": HF_CHAT_MODEL,
                "error_type": "exception",
                "message": error_msg,
            }
        )
        return None, {
            "provider": "huggingface",
            "model": HF_CHAT_MODEL,
            "error_type": "exception",
            "message": error_msg,
        }


# ========================
# API Endpoints
# ========================

@router.post("", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Send a message to SafeBot assistant.
    
    REQUIRES HF_API_KEY for AI responses.
    Falls back to local knowledge base ONLY if explicitly no HF key.
    """

    request_id = str(uuid.uuid4())
    message = request.message.strip()

    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    if len(message) > 1000:
        raise HTTPException(status_code=400, detail="Message too long (max 1000 characters)")

    # Validate language
    lang = request.language if request.language in ["en", "hi", "mr"] else "en"

    # Generate conversation ID if not provided
    conversation_id = request.conversation_id or str(uuid.uuid4())

    warnings: List[str] = []
    provider = "local"
    response_text: Optional[str] = None

    # Check if HF_API_KEY is configured
    if not settings.HF_API_KEY:
        # NO API KEY - This should fail visibly in production
        print(f"❌ CHAT_ERROR: HF_API_KEY not configured - request_id={request_id}")
        warnings.append("HF_API_KEY not configured. AI features disabled.")
        # Use local fallback only when no key is configured
        response_text = get_local_response(message, request.scan_context, lang)
        provider = "local_no_api_key"
    else:
        # HF_API_KEY is set - MUST use external HF API
        print(f"🤖 CHAT: Attempting Hugging Face API - request_id={request_id}")
        
        response_text, hf_error = await try_hf_response(
            message=message,
            scan_context=request.scan_context,
            lang=lang,
            request_id=request_id,
        )
        
        if response_text:
            provider = "huggingface"
            print(f"✅ CHAT_SUCCESS: HF response received - request_id={request_id}")
        else:
            # HF failed even with API key - log clearly
            error_type = hf_error.get('error_type', 'unknown') if hf_error else 'unknown'
            status_code = hf_error.get('status_code', '') if hf_error else ''
            print(f"❌ CHAT_ERROR: All HF models failed - error={error_type} status={status_code} request_id={request_id}")
            
            warnings.append(
                f"Hugging Face API failed ({error_type}{' ' + str(status_code) if status_code else ''}). Using local knowledge base."
            )
            # Fallback to local only after HF failure
            response_text = get_local_response(message, request.scan_context, lang)
            provider = "local_hf_failed"

    _log_chat_event(
        {
            "request_id": request_id,
            "event": "chat_completed",
            "provider": provider,
            "conversation_id": conversation_id,
            "language": lang,
            "hf_api_key_set": bool(settings.HF_API_KEY),
        }
    )

    return ChatResponse(
        response=response_text,
        conversation_id=conversation_id,
        language=lang,
        provider=provider,
        request_id=request_id,
        warnings=warnings,
    )


@router.get("/tips")
async def get_safety_tips(language: str = "en"):
    """Get a list of general safety tips in the specified language."""
    
    tips_data = {
        "en": [
            {
                "title": "Never Share OTPs",
                "description": "Banks and legitimate services will never ask for your OTP over phone or message."
            },
            {
                "title": "Verify Caller Identity",
                "description": "If someone claims to be from a bank or government, hang up and call the official number."
            },
            {
                "title": "Check URLs Carefully",
                "description": "Look for double extensions (.com.com) or brand names in unusual places."
            },
            {
                "title": "No Upfront Payments",
                "description": "Legitimate jobs, prizes, or refunds don't require you to pay money first."
            },
            {
                "title": "Trust Your Instincts",
                "description": "If something feels too good to be true or creates urgency, it's likely a scam."
            },
            {
                "title": "Report Suspicious Activity",
                "description": "Report scams to cybercrime.gov.in or call 1930 (India). Your report helps protect others."
            }
        ],
        "hi": [
            {
                "title": "OTP कभी साझा न करें",
                "description": "बैंक और वैध सेवाएं कभी भी फोन या संदेश पर आपका OTP नहीं मांगेंगी।"
            },
            {
                "title": "कॉलर की पहचान सत्यापित करें",
                "description": "अगर कोई बैंक या सरकार से होने का दावा करे, फोन काट दें और आधिकारिक नंबर पर कॉल करें।"
            },
            {
                "title": "URLs को ध्यान से जांचें",
                "description": "डबल एक्सटेंशन (.com.com) या असामान्य स्थानों पर ब्रांड नामों को देखें।"
            },
            {
                "title": "अग्रिम भुगतान नहीं",
                "description": "वैध नौकरियां, पुरस्कार या रिफंड के लिए पहले पैसे देने की आवश्यकता नहीं होती।"
            }
        ],
        "mr": [
            {
                "title": "OTP कधीही शेअर करू नका",
                "description": "बँक आणि वैध सेवा कधीही फोन किंवा मेसेजवर तुमचा OTP मागणार नाहीत।"
            },
            {
                "title": "कॉलरची ओळख सत्यापित करा",
                "description": "जर कोणी बँक किंवा सरकारमधून असल्याचा दावा करत असेल, फोन ठेवा आणि अधिकृत नंबरवर कॉल करा।"
            },
            {
                "title": "URLs काळजीपूर्वक तपासा",
                "description": "डबल एक्स्टेंशन (.com.com) किंवा असामान्य ठिकाणी ब्रँड नावे पहा।"
            }
        ]
    }
    
    lang = language if language in ["en", "hi", "mr"] else "en"
    
    return {
        "tips": tips_data.get(lang, tips_data["en"]),
        "language": lang
    }
