"""
Hugging Face Inference API client.
Handles all ML model predictions via HF API.
"""

import httpx
from functools import lru_cache
from typing import Any, Dict, Optional, List
from app.config import settings

# HuggingFace Inference API base URL
HF_API_URL = "https://api-inference.huggingface.co/models"


class HFClient:
    """
    Client for Hugging Face Inference API.
    Provides methods for various ML tasks.
    """
    
    def __init__(self):
        self.api_key = settings.HF_API_KEY
        self.headers = {
            "Authorization": f"Bearer {self.api_key}"
        } if self.api_key else {}
    
    async def model_predict(
        self,
        model_id: str,
        inputs: Any,
        timeout: int = 30
    ) -> Optional[Dict]:
        """
        Make a prediction using a HuggingFace model.
        
        Args:
            model_id: HuggingFace model identifier (e.g., "facebook/bart-large-mnli")
            inputs: Input data for the model
            timeout: Request timeout in seconds
        
        Returns:
            Model prediction result or None if failed
        """
        if not self.api_key:
            print("⚠️ HF_API_KEY not set - using fallback")
            return None
        
        url = f"{HF_API_URL}/{model_id}"
        
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    url,
                    headers=self.headers,
                    json=inputs
                )
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 503:
                    # Model is loading, wait and retry
                    print(f"⏳ Model {model_id} is loading...")
                    return {"loading": True}
                else:
                    print(f"❌ HF API error: {response.status_code} - {response.text}")
                    return None
                    
        except httpx.TimeoutException:
            print(f"⏰ Timeout calling HF model: {model_id}")
            return None
        except Exception as e:
            print(f"❌ Error calling HF API: {str(e)}")
            return None
    
    async def classify_url(self, url: str) -> Optional[Dict]:
        """
        Classify a URL for maliciousness using URLBert.
        
        Returns probability scores for safe/malicious.
        """
        model_id = "CrabInHoney/urlbert-tiny-v4-malicious-url-classifier"
        result = await self.model_predict(model_id, {"inputs": url})
        return result
    
    async def classify_text_zero_shot(
        self,
        text: str,
        labels: List[str]
    ) -> Optional[Dict]:
        """
        Classify text using zero-shot classification.
        
        Args:
            text: Text to classify
            labels: List of possible labels
        
        Returns:
            Classification results with scores for each label
        """
        model_id = "facebook/bart-large-mnli"
        inputs = {
            "inputs": text,
            "parameters": {
                "candidate_labels": labels
            }
        }
        result = await self.model_predict(model_id, inputs)
        return result
    
    async def transcribe_audio(self, audio_bytes: bytes) -> Optional[str]:
        """
        Transcribe audio using Whisper model.
        
        Args:
            audio_bytes: Raw audio file bytes
        
        Returns:
            Transcribed text or None if failed
        """
        model_id = "openai/whisper-small"
        
        if not self.api_key:
            return None
        
        url = f"{HF_API_URL}/{model_id}"
        
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    url,
                    headers=self.headers,
                    content=audio_bytes
                )
                
                if response.status_code == 200:
                    result = response.json()
                    return result.get("text", "")
                else:
                    print(f"❌ Whisper API error: {response.status_code}")
                    return None
                    
        except Exception as e:
            print(f"❌ Error transcribing audio: {str(e)}")
            return None
    
    async def generate_chat_response(self, prompt: str) -> Optional[str]:
        """
        Generate a chat response using Flan-T5.
        Fallback when OpenAI is not available.
        
        Args:
            prompt: User message with system context
        
        Returns:
            Generated response text
        """
        model_id = "google/flan-t5-base"
        result = await self.model_predict(model_id, {"inputs": prompt})
        
        if result and isinstance(result, list) and len(result) > 0:
            return result[0].get("generated_text", "")
        return None


# Singleton instance
hf_client = HFClient()


@lru_cache(maxsize=100)
def cached_classify_text(text: str, labels_tuple: tuple) -> Dict:
    """
    Cached version of text classification.
    Uses LRU cache to avoid repeated API calls for identical inputs.
    
    Note: This is a sync wrapper - for async use, call directly.
    """
    # This is a placeholder for caching logic
    # In production, consider using Redis or similar
    pass
