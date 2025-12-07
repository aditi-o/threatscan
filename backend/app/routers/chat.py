"""
Chat router for SafeLink Shield.
Provides AI-powered scam assistance chatbot.
"""

import uuid
from fastapi import APIRouter, HTTPException
from app.schemas import ChatRequest, ChatResponse
from app.config import settings

router = APIRouter(prefix="/chat", tags=["Chatbot"])

# System prompt for the safety assistant
SYSTEM_PROMPT = """You are SafeBot, a friendly and helpful anti-scam assistant for SafeLink Shield.

Your role is to:
1. Help users understand if they've been targeted by a scam
2. Explain common scam tactics in simple terms
3. Provide clear, actionable safety advice
4. Be empathetic - victims may feel embarrassed or scared

Guidelines:
- Always be supportive and non-judgmental
- Keep responses concise and easy to understand
- Provide 3 specific safety steps when relevant
- If the user may have lost money, advise contacting their bank and local cyber crime helpline
- Never ask for personal or financial information

Common scams you can help with:
- Digital arrest scams (fake police/CBI calls)
- UPI/payment scams (QR code tricks)
- Job offer scams (upfront fees)
- Lottery/prize scams
- Romance scams
- Tech support scams
- Phishing messages
"""


async def get_openai_response(message: str) -> str:
    """Get response from OpenAI API."""
    try:
        import openai
        
        client = openai.AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        
        response = await client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": message}
            ],
            max_tokens=500,
            temperature=0.7
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"❌ OpenAI error: {str(e)}")
        return None


async def get_hf_response(message: str) -> str:
    """Get response from HuggingFace API (fallback)."""
    from app.utils.hf_client import hf_client
    
    # Format prompt for Flan-T5
    prompt = f"""Answer as SafeBot, an anti-scam assistant.

User question: {message}

Provide a helpful, concise response about scam safety:"""
    
    response = await hf_client.generate_chat_response(prompt)
    return response


@router.post("", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Send a message to SafeBot assistant.
    
    Uses OpenAI if available, falls back to HuggingFace.
    """
    message = request.message.strip()
    
    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    
    if len(message) > 1000:
        raise HTTPException(status_code=400, detail="Message too long (max 1000 characters)")
    
    # Generate conversation ID if not provided
    conversation_id = request.conversation_id or str(uuid.uuid4())
    
    # Try OpenAI first
    response_text = None
    
    if settings.OPENAI_API_KEY:
        response_text = await get_openai_response(message)
    
    # Fallback to HuggingFace
    if not response_text:
        response_text = await get_hf_response(message)
    
    # Final fallback
    if not response_text:
        response_text = """I apologize, but I'm having trouble processing your request right now. 

Here are some general safety tips:
1. Never share OTPs, PINs, or passwords with anyone
2. Verify requests through official channels before acting
3. If something feels suspicious, trust your instincts

For immediate help, contact your local cyber crime helpline."""
    
    return ChatResponse(
        response=response_text,
        conversation_id=conversation_id
    )


@router.get("/tips")
async def get_safety_tips():
    """Get a list of general safety tips."""
    return {
        "tips": [
            {
                "title": "Never Share OTPs",
                "description": "Banks and legitimate services will never ask for your OTP over phone or message."
            },
            {
                "title": "Verify Caller Identity",
                "description": "If someone claims to be from a bank or government, hang up and call the official number."
            },
            {
                "title": "Don't Click Unknown Links",
                "description": "Hover over links to see the real URL before clicking. When in doubt, go directly to the website."
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
        ]
    }
