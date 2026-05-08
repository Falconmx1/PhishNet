from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
from phishnet.detector import PhishDetector
from phishnet.utils import logger

# Inicializar app
app = FastAPI(
    title="PhishNet API",
    description="Detección de phishing con Inteligencia Artificial",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS para integración con frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inicializar detector (se carga el modelo ML)
detector = PhishDetector()

# Modelos de datos
class URLRequest(BaseModel):
    url: HttpUrl
    deep_scan: bool = False

class EmailRequest(BaseModel):
    subject: str
    sender: str
    body: str
    headers: Optional[Dict[str, str]] = None

class URLResponse(BaseModel):
    id: str
    url: str
    phish_score: int
    risk_level: str
    red_flags: List[str]
    features_used: Dict[str, Any]
    timestamp: datetime
    recommendation: str

class EmailResponse(BaseModel):
    id: str
    phish_score: int
    risk_level: str
    red_flags: List[str]
    suspicious_links: List[str]
    analysis: Dict[str, Any]
    timestamp: datetime

class BatchResponse(BaseModel):
    total: int
    results: List[URLResponse]
    avg_score: float

# Endpoints
@app.get("/")
async def root():
    return {
        "name": "PhishNet AI",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": ["/analyze/url", "/analyze/email", "/health", "/stats"]
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "model_loaded": detector.model is not None,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/analyze/url", response_model=URLResponse)
async def analyze_url(request: URLRequest):
    """
    Analiza una URL para detectar phishing
    
    - **url**: URL completa a analizar
    - **deep_scan**: Realiza scraping completo (más lento pero preciso)
    """
    try:
        result = detector.analyze_url(str(request.url), deep_scan=request.deep_scan)
        
        return URLResponse(
            id=str(uuid.uuid4())[:8],
            url=str(request.url),
            phish_score=result["score"],
            risk_level=result["risk_level"],
            red_flags=result["red_flags"],
            features_used=result["features"],
            timestamp=datetime.now(),
            recommendation=result["recommendation"]
        )
    except Exception as e:
        logger.error(f"Error analyzing URL: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/email", response_model=EmailResponse)
async def analyze_email(request: EmailRequest):
    """
    Analiza un correo electrónico completo
    
    - **subject**: Asunto del email
    - **sender**: Remitente (ej: "paypal@seguro.com")
    - **body**: Cuerpo del mensaje
    - **headers**: Headers opcionales (Return-Path, Reply-To, etc)
    """
    try:
        result = detector.analyze_email(
            subject=request.subject,
            sender=request.sender,
            body=request.body,
            headers=request.headers or {}
        )
        
        return EmailResponse(
            id=str(uuid.uuid4())[:8],
            phish_score=result["score"],
            risk_level=result["risk_level"],
            red_flags=result["red_flags"],
            suspicious_links=result["extracted_links"],
            analysis=result["details"],
            timestamp=datetime.now()
        )
    except Exception as e:
        logger.error(f"Error analyzing email: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/batch")
async def analyze_batch(urls: List[HttpUrl]):
    """
    Análisis por lotes de URLs
    """
    results = []
    for url in urls:
        result = detector.analyze_url(str(url))
        results.append(URLResponse(
            id=str(uuid.uuid4())[:8],
            url=str(url),
            phish_score=result["score"],
            risk_level=result["risk_level"],
            red_flags=result["red_flags"],
            features_used=result["features"],
            timestamp=datetime.now(),
            recommendation=result["recommendation"]
        ))
    
    avg_score = sum(r.phish_score for r in results) / len(results)
    
    return BatchResponse(
        total=len(results),
        results=results,
        avg_score=avg_score
    )

@app.get("/stats")
async def get_stats():
    """
    Estadísticas del detector
    """
    return detector.get_stats()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
