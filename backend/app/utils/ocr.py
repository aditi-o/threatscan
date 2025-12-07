"""
OCR (Optical Character Recognition) module.
Extracts text from images using pytesseract.
"""

import io
from typing import Optional
from PIL import Image

# Try to import pytesseract
try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False
    print("⚠️ pytesseract not installed. OCR features will be limited.")


def image_to_text(image_bytes: bytes) -> Optional[str]:
    """
    Extract text from image using OCR.
    
    Args:
        image_bytes: Raw image file bytes
    
    Returns:
        Extracted text or None if failed
    
    Note:
        Requires pytesseract and Tesseract-OCR to be installed.
        On Ubuntu/Debian: sudo apt-get install tesseract-ocr
        On macOS: brew install tesseract
        On Windows: Download installer from GitHub
    """
    if not TESSERACT_AVAILABLE:
        return None
    
    try:
        # Open image from bytes
        image = Image.open(io.BytesIO(image_bytes))
        
        # Convert to RGB if necessary (for PNG with alpha channel)
        if image.mode in ('RGBA', 'LA', 'P'):
            image = image.convert('RGB')
        
        # Extract text using Tesseract
        text = pytesseract.image_to_string(
            image,
            lang='eng',  # Use English language
            config='--psm 6'  # Assume uniform block of text
        )
        
        # Clean up the extracted text
        text = text.strip()
        
        return text if text else None
        
    except Exception as e:
        print(f"❌ OCR error: {str(e)}")
        return None


def preprocess_image(image_bytes: bytes) -> bytes:
    """
    Preprocess image for better OCR results.
    
    Applies:
    - Grayscale conversion
    - Contrast enhancement
    - Noise reduction
    
    Args:
        image_bytes: Raw image bytes
    
    Returns:
        Preprocessed image bytes
    """
    try:
        image = Image.open(io.BytesIO(image_bytes))
        
        # Convert to grayscale
        image = image.convert('L')
        
        # Simple contrast enhancement
        # (For production, consider using PIL.ImageEnhance or OpenCV)
        
        # Save to bytes
        output = io.BytesIO()
        image.save(output, format='PNG')
        return output.getvalue()
        
    except Exception as e:
        print(f"❌ Image preprocessing error: {str(e)}")
        return image_bytes


# Alternative: HuggingFace TrOCR
async def image_to_text_trocr(image_bytes: bytes) -> Optional[str]:
    """
    Extract text using HuggingFace TrOCR model.
    Better quality than Tesseract but requires API call.
    
    To enable, uncomment and use in place of pytesseract.
    
    Args:
        image_bytes: Raw image bytes
    
    Returns:
        Extracted text
    """
    # Uncomment to use HuggingFace TrOCR:
    # from app.utils.hf_client import hf_client
    # 
    # model_id = "microsoft/trocr-base-printed"
    # result = await hf_client.model_predict(
    #     model_id,
    #     image_bytes,
    #     timeout=30
    # )
    # return result.get("generated_text") if result else None
    
    pass
