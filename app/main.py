# app/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.schemas import ScanRequest, ScanResponse
from app.scanner import scanner_engine

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Backend deep-scan API utilizing spaCy NLP and Microsoft Presidio"
)

# Attach CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # Allows extension scripts and Vite frontend
    allow_credentials=False,    # MUST be False when allow_origins is ["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/v1/deep-scan", response_model=ScanResponse, tags=["Security Scanner"])
async def run_deep_scan(payload: ScanRequest):
    try:
        threats, sanitized_text = scanner_engine.analyze_and_sanitize(
            text=payload.text,
            language=payload.language,
            threshold=payload.score_threshold,
            mode=payload.anonymize_mode
        )

        return ScanResponse(
            is_clean=len(threats) == 0,
            threat_count=len(threats),
            original_text=payload.text,
            sanitized_text=sanitized_text,
            threats=threats
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deep scan execution error: {str(e)}")


@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "online",
        "engine": "Microsoft Presidio",
        "nlp_model": settings.DEFAULT_SPACY_MODEL
    }