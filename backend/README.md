# SafeLink Shield Backend

FastAPI backend for the SafeLink Shield anti-scam protection platform.

## Features

- 🔗 **URL Scanner** - Detect malicious links using ML + heuristics
- 📝 **Text Scanner** - Identify scam messages with zero-shot classification
- 📸 **Screenshot OCR** - Extract text from images and analyze for scams
- 🎙️ **Audio Analyzer** - Transcribe calls and detect scam patterns
- 🤖 **AI Chatbot** - Get scam protection advice from SafeBot
- 👤 **User Auth** - JWT-based authentication
- 📊 **Reporting** - Submit and track scam reports

## Quick Start

### Prerequisites

- Python 3.10+
- Tesseract OCR (for screenshot scanning)
- HuggingFace account (free)

### Installation

```bash
# 1. Clone/navigate to the backend folder
cd backend

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Set up environment
cp .env.example .env
# Edit .env with your API keys

# 6. Run the server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Get API Keys

1. **HuggingFace API Key** (Required)
   - Go to https://huggingface.co/settings/tokens
   - Create a new token with "read" access
   - Add to `.env` as `HF_API_KEY`

2. **OpenAI API Key** (Optional, for better chatbot)
   - Go to https://platform.openai.com/api-keys
   - Create a new key
   - Add to `.env` as `OPENAI_API_KEY`

### Install Tesseract OCR

For screenshot scanning to work:

**Ubuntu/Debian:**
```bash
sudo apt-get install tesseract-ocr
```

**macOS:**
```bash
brew install tesseract
```

**Windows:**
Download installer from: https://github.com/UB-Mannheim/tesseract/wiki

## API Documentation

Once running, view the interactive API docs:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Replit Deployment

1. Create a new Python Repl
2. Upload all files from `backend/` folder
3. In Replit Secrets, add:
   - `HF_API_KEY`
   - `JWT_SECRET_KEY` (generate a secure random string)
4. In `.replit` file, set run command:
   ```
   run = "uvicorn app.main:app --host 0.0.0.0 --port 8000"
   ```
5. Click "Run"

## Project Structure

```
backend/
├── app/
│   ├── main.py          # FastAPI application
│   ├── config.py        # Environment configuration
│   ├── db.py            # Database setup
│   ├── models.py        # SQLAlchemy models
│   ├── schemas.py       # Pydantic schemas
│   ├── crud.py          # Database operations
│   ├── routers/         # API route handlers
│   │   ├── auth.py      # Authentication
│   │   ├── scan.py      # Scanning endpoints
│   │   ├── chat.py      # Chatbot
│   │   ├── report.py    # Reporting
│   │   └── admin.py     # Admin functions
│   └── utils/           # Helper utilities
│       ├── hf_client.py # HuggingFace API
│       ├── heuristics.py# Rule-based analysis
│       ├── ocr.py       # Image text extraction
│       ├── stt.py       # Speech-to-text
│       ├── jwt_handler.py
│       └── sanitizers.py
├── tests/               # Unit tests
├── requirements.txt
├── .env.example
└── README.md
```

## Connecting Frontend

Update your frontend to call the backend API:

```javascript
const API_BASE_URL = 'http://localhost:8000';  // Or your Replit URL

// Example: Scan a URL
const response = await fetch(`${API_BASE_URL}/scan/url`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ content: 'https://suspicious-link.com' })
});
const result = await response.json();
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HF_API_KEY` | Yes | HuggingFace API token |
| `OPENAI_API_KEY` | No | OpenAI API key for chatbot |
| `DATABASE_URL` | No | SQLite URL (default: ./safelink.db) |
| `JWT_SECRET_KEY` | Yes | Secret for JWT signing |
| `JWT_ALGORITHM` | No | JWT algorithm (default: HS256) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | Token lifetime (default: 60) |

## Running Tests

```bash
pytest tests/ -v
```

## License

MIT
