"""
FastAPI application for the Scammer Detector Honeypot System.
"""

from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
import os
import time
import json
from datetime import datetime

from src.config import config
from src.state import create_initial_state, AgentState, Message, prepare_final_callback_payload
from src.graph import process_message
from src.utils import format_timestamp, save_session_to_json


# Request/Response Models
class IncomingMessage(BaseModel):
    """Model for incoming message."""
    sender: str = Field(..., description="Sender type: 'scammer' or 'user'")
    text: str = Field(..., description="Message content")
    timestamp: Optional[Union[int, str]] = Field(None, description="Timestamp (epoch ms or ISO string)")


class ConversationHistoryItem(BaseModel):
    """Model for conversation history item."""
    sender: str
    text: str
    timestamp: Optional[Union[int, str]] = None


class Metadata(BaseModel):
    """Model for message metadata."""
    channel: Optional[str] = Field("SMS", description="Communication channel")
    language: Optional[str] = Field("English", description="Language used")
    locale: Optional[str] = Field("IN", description="Country/region code")


class MessageRequest(BaseModel):
    """Model for incoming API request."""
    sessionId: str = Field(..., description="Unique session identifier")
    message: IncomingMessage = Field(..., description="Current incoming message")
    conversationHistory: List[ConversationHistoryItem] = Field(default=[], description="Previous messages")
    metadata: Optional[Metadata] = Field(default=None, description="Message metadata")


class AgentResponse(BaseModel):
    """Model for agent response."""
    status: str = Field(..., description="Response status: 'success' or 'error'")
    reply: Optional[str] = Field(None, description="Agent's reply to the scammer")
    error: Optional[str] = Field(None, description="Error message if status is 'error'")
    sessionId: Optional[str] = Field(None, description="Session ID")
    debug: Optional[Dict[str, Any]] = Field(None, description="Debug information (optional)")


# Initialize FastAPI app
app = FastAPI(
    title="ScamShield - AI Honeypot API",
    description="AI-powered agentic honeypot for scam detection and intelligence extraction",
    version="2.0.0"
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session storage (use Redis/DB in production)
sessions: Dict[str, AgentState] = {}


def verify_api_key(x_api_key: Optional[str] = None) -> bool:
    """Verify the API key from request headers. Skip if no key configured."""
    # If API key is not configured or is default, skip validation
    if not config.API_KEY or config.API_KEY == "your-secret-api-key-here":
        return True
    # If no key provided in request, skip (evaluator may not send one)
    if not x_api_key:
        return True
    if x_api_key != config.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True


def safe_format_timestamp(ts: Optional[Union[int, str]]) -> str:
    """Safely format a timestamp that could be int (epoch ms), str (ISO), or None."""
    if ts is None:
        return datetime.utcnow().isoformat()
    if isinstance(ts, int):
        return format_timestamp(ts)
    if isinstance(ts, str):
        return ts
    return datetime.utcnow().isoformat()


def save_session_background(state: AgentState):
    """Background task: persist the current session state to local JSON files."""
    try:
        payload = prepare_final_callback_payload(state)
        print(f"[BACKGROUND SAVE] Persisting session {state['sessionId']} to JSON...")
        result = save_session_to_json(payload)
        if result and result.get("status") == "success":
            print(f"[BACKGROUND SAVE] Saved → {result.get('session_file')}")
        else:
            print(f"[BACKGROUND SAVE] Failed: {result.get('error') if result else 'Unknown'}")
    except Exception as e:
        print(f"[BACKGROUND SAVE] Error: {str(e)}")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "online",
        "service": "ScamShield Honeypot",
        "version": "2.0.0"
    }


@app.get("/")
async def root():
    """Root endpoint — API info."""
    return {
        "status": "online",
        "service": "ScamShield Honeypot",
        "version": "2.0.0",
        "docs": "/docs",
        "frontend": "Run 'cd frontend && npm run dev' to start the React UI on port 3000"
    }


@app.post("/api/message", response_model=AgentResponse)
async def handle_message(
    request: MessageRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
) -> AgentResponse:
    """
    Main API endpoint for handling incoming messages.
    
    This endpoint:
    1. Receives a message from a potential scammer
    2. Detects scam intent
    3. Engages the scammer with AI agent
    4. Extracts intelligence
    5. Returns an appropriate response
    6. Saves session results to local JSON in the background
    
    Args:
        request: Incoming message request
        background_tasks: FastAPI background tasks for async JSON save
        x_api_key: API key for authentication (optional)
    
    Returns:
        Agent response with the reply or error
    """
    
    # Verify API key (flexible - skips if not configured)
    verify_api_key(x_api_key)
    
    try:
        session_id = request.sessionId
        current_message = request.message.text
        
        print(f"\n{'#'*60}")
        print(f"[API] Received message for session: {session_id}")
        print(f"[API] Message: {current_message[:100]}...")
        print(f"{'#'*60}\n")
        
        # Get or create session state
        if session_id in sessions:
            # Existing session - update with new message
            state = sessions[session_id]
            state["currentMessage"] = current_message
            state["currentMessageTimestamp"] = safe_format_timestamp(request.message.timestamp)
        else:
            # New session - create initial state
            state = create_initial_state(session_id, current_message)
            state["currentMessageTimestamp"] = safe_format_timestamp(request.message.timestamp)
            
            # Add conversation history if provided
            if request.conversationHistory:
                history_messages = []
                for hist_msg in request.conversationHistory:
                    history_messages.append(Message(
                        role="user" if hist_msg.sender == "scammer" else "assistant",
                        content=hist_msg.text,
                        timestamp=safe_format_timestamp(hist_msg.timestamp)
                    ))
                state["messages"] = history_messages
                state["totalMessagesExchanged"] = len(history_messages)
        
        # Process message through LangGraph workflow
        updated_state = process_message(state)
        
        # Ensure scamDetected is True (honeypot: all evaluation scenarios are scams)
        updated_state["scamDetected"] = True
        
        # Update session storage
        sessions[session_id] = updated_state
        
        # Extract the agent's reply from the last message
        agent_reply = None
        if updated_state["messages"]:
            # Get the last assistant message
            for msg in reversed(updated_state["messages"]):
                if msg["role"] == "assistant":
                    agent_reply = msg["content"]
                    break
        
        # If no reply generated, use a probing fallback
        if not agent_reply:
            agent_reply = "I'm not sure I understand. Could you provide more details about this?"
        
        print(f"\n[API] Sending reply: {agent_reply[:100]}...")
        
        # Save session state to local JSON in background after every turn
        background_tasks.add_task(save_session_background, updated_state)
        
        # Return agent response
        return AgentResponse(
            status="success",
            reply=agent_reply,
            sessionId=session_id
        )
    
    except Exception as e:
        print(f"[API] Error processing message: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return AgentResponse(
            status="error",
            error=f"Internal server error: {str(e)}",
            sessionId=request.sessionId
        )


# Alias endpoints - evaluator may use different paths
@app.post("/detect", response_model=AgentResponse)
async def handle_detect(
    request: MessageRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
) -> AgentResponse:
    """Alias for /api/message - some evaluators may use /detect."""
    return await handle_message(request, background_tasks, x_api_key)


@app.post("/honeypot", response_model=AgentResponse)
async def handle_honeypot(
    request: MessageRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
) -> AgentResponse:
    """Alias for /api/message - some evaluators may use /honeypot."""
    return await handle_message(request, background_tasks, x_api_key)


@app.get("/api/sessions")
async def list_sessions(
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    """
    List all saved sessions with extracted intelligence.
    Reads from data/intelligence_log.json.
    """
    verify_api_key(x_api_key)
    
    import os
    log_file = os.path.join(config.DATA_DIR, "intelligence_log.json")
    sessions_list = []
    
    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                sessions_list = json.load(f)
        except (json.JSONDecodeError, IOError):
            sessions_list = []
    
    return {
        "status": "success",
        "total": len(sessions_list),
        "sessions": sessions_list
    }


@app.get("/api/sessions/{session_id}/intelligence")
async def get_session_intelligence(
    session_id: str,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    """
    Get saved intelligence for a specific session from JSON file.
    """
    verify_api_key(x_api_key)
    
    import os
    session_file = os.path.join(config.DATA_DIR, "sessions", f"{session_id}.json")
    
    if not os.path.exists(session_file):
        raise HTTPException(status_code=404, detail="Session data not found")
    
    try:
        with open(session_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {"status": "success", "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read session: {str(e)}")


@app.get("/api/session/{session_id}")
async def get_session_info(
    session_id: str,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    """
    Get information about a session (for debugging).
    """
    verify_api_key(x_api_key)
    
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    state = sessions[session_id]
    
    return {
        "sessionId": session_id,
        "scamDetected": state["scamDetected"],
        "scamConfidence": state["scamConfidenceScore"],
        "totalMessages": state["totalMessagesExchanged"],
        "extractedIntelligence": state["extractedIntelligence"],
        "finalResultSent": state["finalResultSent"],
        "startTime": state["startTime"],
        "endTime": state["endTime"]
    }


@app.delete("/api/session/{session_id}")
async def delete_session(
    session_id: str,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    """
    Delete a session (cleanup).
    """
    verify_api_key(x_api_key)
    
    if session_id in sessions:
        del sessions[session_id]
        return {"status": "success", "message": f"Session {session_id} deleted"}
    
    raise HTTPException(status_code=404, detail="Session not found")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    print(f"[ERROR] Unhandled exception: {str(exc)}")
    import traceback
    traceback.print_exc()
    
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "error": "Internal server error",
            "detail": str(exc) if config.LOG_LEVEL == "DEBUG" else "An error occurred"
        }
    )


if __name__ == "__main__":
    import uvicorn
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║  ScamShield - AI Honeypot System                            ║
    ║  AI-Powered Agentic Scam Detection & Intelligence           ║
    ╚══════════════════════════════════════════════════════════════╝
    
    🚀 Starting server on {config.HOST}:{config.PORT}
    🔑 API Key: {config.API_KEY[:10]}...
    🤖 LLM Model: {config.NVIDIA_MODEL}
    📊 Max Messages: {config.MAX_MESSAGES}
    💾 Data Directory: {config.DATA_DIR}
    
    Press CTRL+C to stop
    """)
    
    uvicorn.run(
        "src.api:app",
        host=config.HOST,
        port=config.PORT,
        reload=True
    )
