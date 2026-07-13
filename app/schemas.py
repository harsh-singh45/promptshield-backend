# app/schemas.py
from pydantic import BaseModel, Field
from typing import List, Optional

class ScanRequest(BaseModel):
    text: str = Field(..., description="The prompt text to analyze")
    language: str = Field(default="en", description="Language code for spaCy NLP")
    score_threshold: float = Field(default=0.60, ge=0.0, le=1.0, description="Minimum confidence threshold")
    anonymize_mode: str = Field(default="replace", description="Mode: 'replace', 'mask', or 'redact'")

class DetectedEntity(BaseModel):
    entity_type: str
    start: int
    end: int
    score: float
    snippet: str

class ScanResponse(BaseModel):
    is_clean: bool
    threat_count: int
    original_text: str
    sanitized_text: str
    threats: List[DetectedEntity]