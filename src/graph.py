"""
LangGraph workflow definition for the Scammer Detector Honeypot System.
"""

from typing import Literal
from langgraph.graph import StateGraph, END

from src.state import AgentState
from src.nodes import (
    add_user_message_node,
    scam_detection_node,
    intelligence_extraction_node,
    agent_response_node,
    check_continuation_node,
    final_callback_node
)


def should_engage_scammer(state: AgentState) -> Literal["engage", "reject"]:
    """
    Conditional edge: Determine if we should engage the scammer.
    
    Honeypot strategy: ALWAYS engage with incoming messages to maximize
    intelligence gathering. Even if initial confidence is low, further
    conversation turns may reveal scam patterns.
    
    Returns:
        "engage" always — honeypot best practice
    """
    print(f"[ROUTING] Engaging with message for intelligence gathering (confidence: {state.get('scamConfidenceScore', 0)})")
    return "engage"


def should_continue_conversation(state: AgentState) -> Literal["continue", "end"]:
    """
    Conditional edge: Determine if conversation should continue.
    
    Returns:
        "continue" to keep engaging, "end" to finish
    """
    if state["shouldContinueConversation"]:
        print("[ROUTING] Continuing conversation")
        return "continue"
    else:
        print("[ROUTING] Ending conversation - sending final callback")
        return "end"


def create_scammer_detector_graph() -> StateGraph:
    """
    Create the LangGraph workflow for scammer detection and engagement.
    
    Workflow:
    1. Add user message to history
    2. Detect scam intent
    3. If scam: engage with AI agent
    4. Extract intelligence
    5. Generate agent response
    6. Check if should continue
    7. If continue: wait for next message
    8. If end: send final callback
    
    Returns:
        Compiled StateGraph
    """
    
    # Create the graph
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("add_message", add_user_message_node)
    workflow.add_node("detect_scam", scam_detection_node)
    workflow.add_node("extract_intelligence", intelligence_extraction_node)
    workflow.add_node("generate_response", agent_response_node)
    workflow.add_node("check_continuation", check_continuation_node)
    workflow.add_node("final_callback", final_callback_node)
    
    # Set entry point
    workflow.set_entry_point("add_message")
    
    # Add edges
    # 1. Add message -> Detect scam
    workflow.add_edge("add_message", "detect_scam")
    
    # 2. Detect scam -> Conditional routing
    workflow.add_conditional_edges(
        "detect_scam",
        should_engage_scammer,
        {
            "engage": "extract_intelligence",
            "reject": END  # Don't engage if not a scam
        }
    )
    
    # 3. Extract intelligence -> Generate response
    workflow.add_edge("extract_intelligence", "generate_response")
    
    # 4. Generate response -> Check continuation
    workflow.add_edge("generate_response", "check_continuation")
    
    # 5. Check continuation -> Conditional routing
    workflow.add_conditional_edges(
        "check_continuation",
        should_continue_conversation,
        {
            "continue": END,  # Return to API, wait for next message
            "end": "final_callback"  # Conversation complete, send callback
        }
    )
    
    # 6. Final callback -> END
    workflow.add_edge("final_callback", END)
    
    # Compile the graph
    app = workflow.compile()
    
    return app


# Create the compiled graph
scammer_detector_app = create_scammer_detector_graph()


def process_message(state: AgentState) -> AgentState:
    """
    Process a single message through the workflow.
    
    Args:
        state: Current agent state
    
    Returns:
        Updated agent state
    """
    print(f"\n{'='*60}")
    print(f"[WORKFLOW] Processing message for session: {state['sessionId']}")
    print(f"[WORKFLOW] Total messages so far: {state['totalMessagesExchanged']}")
    print(f"{'='*60}\n")
    
    # Run the graph
    result = scammer_detector_app.invoke(state)
    
    print(f"\n{'='*60}")
    print(f"[WORKFLOW] Processing complete")
    print(f"[WORKFLOW] Scam detected: {result['scamDetected']}")
    print(f"[WORKFLOW] Total messages: {result['totalMessagesExchanged']}")
    print(f"[WORKFLOW] Should continue: {result['shouldContinueConversation']}")
    print(f"{'='*60}\n")
    
    return result
