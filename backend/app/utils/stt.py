"""
Speech-to-Text (STT) module.
Transcribes audio files to text using Whisper.
"""

import io
import os
from typing import Optional

# Try to import faster-whisper for local transcription
try:
    from faster_whisper import WhisperModel
    FASTER_WHISPER_AVAILABLE = True
except ImportError:
    FASTER_WHISPER_AVAILABLE = False
    print("⚠️ faster-whisper not installed. Using HuggingFace API for transcription.")


# Local Whisper model (lazy loaded)
_local_model = None


def get_local_model():
    """
    Get or initialize the local Whisper model.
    Uses 'tiny' model for fast transcription.
    """
    global _local_model
    if _local_model is None and FASTER_WHISPER_AVAILABLE:
        print("🎤 Loading local Whisper model (tiny)...")
        _local_model = WhisperModel(
            "tiny",
            device="cpu",
            compute_type="int8"
        )
        print("✅ Whisper model loaded")
    return _local_model


async def audio_to_text(file_bytes: bytes, filename: str = "audio.wav") -> Optional[str]:
    """
    Transcribe audio to text.
    
    Uses HuggingFace Whisper API by default.
    Falls back to local faster-whisper if API fails.
    
    Args:
        file_bytes: Raw audio file bytes
        filename: Original filename (for format detection)
    
    Returns:
        Transcribed text or None if failed
    """
    # First, try HuggingFace API
    from app.utils.hf_client import hf_client
    
    transcript = await hf_client.transcribe_audio(file_bytes)
    
    if transcript:
        return transcript.strip()
    
    # Fallback to local transcription
    if FASTER_WHISPER_AVAILABLE:
        return await transcribe_local(file_bytes, filename)
    
    return None


async def transcribe_local(file_bytes: bytes, filename: str) -> Optional[str]:
    """
    Transcribe audio using local faster-whisper model.
    
    Args:
        file_bytes: Raw audio file bytes
        filename: Original filename
    
    Returns:
        Transcribed text or None if failed
    """
    if not FASTER_WHISPER_AVAILABLE:
        return None
    
    try:
        model = get_local_model()
        if model is None:
            return None
        
        # Save bytes to temporary file
        # (faster-whisper requires file path)
        temp_path = f"/tmp/{filename}"
        with open(temp_path, "wb") as f:
            f.write(file_bytes)
        
        # Transcribe
        segments, info = model.transcribe(
            temp_path,
            beam_size=5,
            language="en"
        )
        
        # Combine all segments
        transcript = " ".join([segment.text for segment in segments])
        
        # Clean up temp file
        os.remove(temp_path)
        
        return transcript.strip()
        
    except Exception as e:
        print(f"❌ Local transcription error: {str(e)}")
        return None


def get_audio_duration(file_bytes: bytes) -> Optional[float]:
    """
    Get audio file duration in seconds.
    Useful for validation and pricing.
    
    Args:
        file_bytes: Raw audio file bytes
    
    Returns:
        Duration in seconds or None if failed
    """
    try:
        # This is a simplified version
        # For production, use pydub or similar library
        # from pydub import AudioSegment
        # audio = AudioSegment.from_file(io.BytesIO(file_bytes))
        # return len(audio) / 1000.0
        return None
    except:
        return None


# Supported audio formats
SUPPORTED_AUDIO_FORMATS = {
    ".wav": "audio/wav",
    ".mp3": "audio/mpeg",
    ".m4a": "audio/m4a",
    ".aac": "audio/aac",
    ".ogg": "audio/ogg",
    ".flac": "audio/flac"
}


def is_supported_audio_format(filename: str) -> bool:
    """
    Check if audio format is supported.
    
    Args:
        filename: Audio filename
    
    Returns:
        True if format is supported
    """
    ext = os.path.splitext(filename)[1].lower()
    return ext in SUPPORTED_AUDIO_FORMATS
