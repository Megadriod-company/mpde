from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, status
from typing import List, Dict

# These imports reference the other files in our flat layout
from app.models import URLRequest, PredictionResponse, BatchURLRequest, BatchPredictionResponse
from app.engine import analyze_url_pipeline
from app.core import verify_api_key, log_prediction_to_db, get_recent_logs

# NEW IMPORT: Pull in our dynamic business impact logic
from app.ai_utils import build_business_impact_report

# Initialize the router with versioning tags
router = APIRouter(prefix="/api/v1", tags=["Phishing Detection"])

@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """
    Load Balancer & Orchestration Health Check.
    Ensures the API is responsive.
    """
    return {
        "status": "healthy",
        "engine": "MPDE",
        "version": "1.0.0",
        "mode": "Heuristic & Behavioral"
    }

# NOTICE: Removed response_model=PredictionResponse so it allows our custom AI fields through to the frontend
@router.post("/predict", status_code=status.HTTP_200_OK)
async def predict_single_url(
    payload: URLRequest, 
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Single URL Prediction Endpoint.
    Requires a valid API Key. Runs Lexical and Behavioral checks.
    """
    try:
        # 1. Run the core engine pipeline (Lexical + DNS/WHOIS)
        verdict, confidence, features = await analyze_url_pipeline(payload.url)
        
        # 2. Extract behavioral data (Based on your engine output)
        behavioral = features.get("behavioral_summary", {})
        
        # 3. Generate the Dynamic Business Impact Report
        report = build_business_impact_report(payload.url, verdict, confidence, features, behavioral)
        
        # 4. Construct the rich data dictionary for the frontend Dashboard
        response_data = {
            "url": payload.url,
            "verdict": report["verdict"],
            "confidence_score": report["confidence"],
            "features": features, 
            "likely_impact": report["likely_impact"],
            "prevention_recommendations": report["prevention_recommendations"],
            "escalation_recommendation": report["escalation_recommendation"],
            "framework_alignment": report["framework_alignment"]
        }
        
        # 5. Enterprise Logging: Construct the strict model for the DB logger
        db_log_model = PredictionResponse(
            url=payload.url,
            verdict=report["verdict"],
            confidence_score=report["confidence"],
            features=features
        )
        
        # Save to DB in the background to prevent API latency
        background_tasks.add_task(log_prediction_to_db, db_log_model)
        
        # 6. Return the dynamic data to the frontend
        return response_data

    except Exception as e:
        # Print to terminal for debugging
        print(f"CRITICAL API ERROR: {str(e)}")
        # Prevent internal stack traces from leaking to users
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Engine analysis failed: {str(e)}"
        )

@router.post("/batch_predict", response_model=BatchPredictionResponse, status_code=status.HTTP_200_OK)
async def predict_batch_urls(
    payload: BatchURLRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Batch Processing Endpoint (e.g., for email gateways scanning multiple links).
    """
    if len(payload.urls) > 50:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Batch size exceeds the maximum limit of 50 URLs per request."
        )

    results = []
    try:
        for url in payload.urls:
            # In a true high-concurrency setup, this could use asyncio.gather
            verdict, confidence, features = await analyze_url_pipeline(url)
            
            prediction = PredictionResponse(
                url=url,
                verdict=verdict,
                confidence_score=confidence,
                features=features
            )
            results.append(prediction)
            
            # Queue each result for database logging
            background_tasks.add_task(log_prediction_to_db, prediction)

        return BatchPredictionResponse(
            batch_id=payload.batch_id,
            total_processed=len(results),
            results=results
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch processing failed: {str(e)}"
        )

@router.get("/audit", status_code=status.HTTP_200_OK)
async def fetch_audit_logs(
    limit: int = 100, 
    api_key: str = Depends(verify_api_key)
):
    """
    SIEM Integration Endpoint.
    Allows external security tools to pull recent scan logs.
    """
    try:
        logs = get_recent_logs(limit=limit)
        return {"count": len(logs), "logs": logs}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve audit logs."
        )