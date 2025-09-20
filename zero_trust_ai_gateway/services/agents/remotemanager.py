"""Remote AI agent lifecycle manager.

Adapted from Enterprise Gateway kernel manager patterns for AI agents.
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import numpy as np

logger = logging.getLogger(__name__)

class AgentState(Enum):
    """AI agent states"""
    STARTING = "starting"
    RUNNING = "running"
    IDLE = "idle"
    BUSY = "busy"
    STOPPING = "stopping"
    DEAD = "dead"

@dataclass
class AgentSession:
    """AI agent session information"""
    agent_id: str
    user_id: str
    model: str
    state: AgentState = AgentState.STARTING
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    request_count: int = 0
    total_tokens: int = 0
    error_count: int = 0
    config: Dict[str, Any] = field(default_factory=dict)

class RemoteAgentManager:
    """AI agent lifecycle manager adapted from Enterprise Gateway patterns"""

    def __init__(self, parent=None, log=None):
        self.parent = parent
        self.log = log or logger

        # Agent session tracking
        self.active_sessions: Dict[str, AgentSession] = {}
        self.user_agent_mapping: Dict[str, List[str]] = {}

        # Performance optimization
        self.session_cache = np.zeros((10000, 10), dtype=np.float64)  # Pre-allocated cache
        self.cache_index = {}

        # Configuration
        self.max_agents_per_user = 10
        self.session_timeout = 3600  # 1 hour
        self.cleanup_interval = 300  # 5 minutes

        # Start cleanup task
        self.cleanup_task = None

    async def start_agent_session(
        self,
        user_id: str,
        model: str,
        config: Dict[str, Any] = None
    ) -> str:
        """Start new AI agent session"""

        start_time = time.perf_counter()

        try:
            # Check user limits
            user_agents = self.user_agent_mapping.get(user_id, [])
            if len(user_agents) >= self.max_agents_per_user:
                raise Exception(f"User {user_id} has reached maximum agent limit ({self.max_agents_per_user})")

            # Generate unique agent ID
            agent_id = f"agent_{user_id}_{int(time.time() * 1000000)}"

            # Create agent session
            session = AgentSession(
                agent_id=agent_id,
                user_id=user_id,
                model=model,
                config=config or {}
            )

            # Store session
            self.active_sessions[agent_id] = session

            # Update user mapping
            if user_id not in self.user_agent_mapping:
                self.user_agent_mapping[user_id] = []
            self.user_agent_mapping[user_id].append(agent_id)

            # Cache session for performance
            self._cache_session(session)

            # Transition to running state
            session.state = AgentState.RUNNING

            latency_ms = (time.perf_counter() - start_time) * 1000
            self.log.info(f"Started agent session {agent_id} for user {user_id} in {latency_ms:.2f}ms")

            return agent_id

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            self.log.error(f"Failed to start agent session for user {user_id}: {e} (took {latency_ms:.2f}ms)")
            raise

    async def invoke_agent(
        self,
        agent_id: str,
        prompt: str,
        user_id: str = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Invoke AI agent with given prompt"""

        start_time = time.perf_counter()

        try:
            # Get session
            session = self.active_sessions.get(agent_id)
            if not session:
                # Auto-create session if needed
                if user_id:
                    model = kwargs.get('model', 'gpt-3.5-turbo')
                    agent_id = await self.start_agent_session(user_id, model)
                    session = self.active_sessions[agent_id]
                else:
                    raise Exception(f"Agent session {agent_id} not found")

            # Update session state
            session.state = AgentState.BUSY
            session.last_activity = time.time()
            session.request_count += 1

            # Simulate AI model invocation (in production, would call actual AI service)
            await asyncio.sleep(0.01)  # Simulate processing time

            # Generate response
            response_text = f"AI response to: {prompt[:100]}..."
            usage = {
                'prompt_tokens': len(prompt.split()),
                'completion_tokens': len(response_text.split()),
                'total_tokens': len(prompt.split()) + len(response_text.split())
            }

            # Update session metrics
            session.total_tokens += usage['total_tokens']
            session.state = AgentState.IDLE

            # Calculate latency
            latency_ms = (time.perf_counter() - start_time) * 1000

            result = {
                'success': True,
                'response': response_text,
                'model': session.model,
                'usage': usage,
                'latency_ms': round(latency_ms, 2),
                'agent_id': agent_id,
                'session_info': {
                    'request_count': session.request_count,
                    'total_tokens': session.total_tokens,
                    'uptime_seconds': time.time() - session.created_at
                }
            }

            return result

        except Exception as e:
            # Handle errors
            if agent_id in self.active_sessions:
                self.active_sessions[agent_id].error_count += 1
                self.active_sessions[agent_id].state = AgentState.IDLE

            latency_ms = (time.perf_counter() - start_time) * 1000
            self.log.error(f"Agent invocation failed for {agent_id}: {e} (took {latency_ms:.2f}ms)")

            return {
                'success': False,
                'error': str(e),
                'latency_ms': round(latency_ms, 2),
                'agent_id': agent_id
            }

    async def stop_agent_session(self, agent_id: str) -> bool:
        """Stop AI agent session"""

        try:
            session = self.active_sessions.get(agent_id)
            if not session:
                return False

            # Update state
            session.state = AgentState.STOPPING

            # Remove from active sessions
            del self.active_sessions[agent_id]

            # Update user mapping
            user_agents = self.user_agent_mapping.get(session.user_id, [])
            if agent_id in user_agents:
                user_agents.remove(agent_id)

            # Remove from cache
            if agent_id in self.cache_index:
                del self.cache_index[agent_id]

            self.log.info(f"Stopped agent session {agent_id}")
            return True

        except Exception as e:
            self.log.error(f"Failed to stop agent session {agent_id}: {e}")
            return False

    def list_user_agents(self, user_id: str) -> List[Dict[str, Any]]:
        """List all active agents for a user"""

        user_agents = self.user_agent_mapping.get(user_id, [])
        result = []

        for agent_id in user_agents:
            session = self.active_sessions.get(agent_id)
            if session:
                result.append({
                    'agent_id': agent_id,
                    'model': session.model,
                    'state': session.state.value,
                    'created_at': session.created_at,
                    'last_activity': session.last_activity,
                    'request_count': session.request_count,
                    'total_tokens': session.total_tokens,
                    'error_count': session.error_count,
                    'uptime_seconds': time.time() - session.created_at
                })

        return result

    def get_agent_stats(self) -> Dict[str, Any]:
        """Get overall agent statistics"""

        total_sessions = len(self.active_sessions)
        total_users = len(self.user_agent_mapping)

        # Calculate state distribution
        state_counts = {}
        total_requests = 0
        total_tokens = 0
        total_errors = 0

        for session in self.active_sessions.values():
            state = session.state.value
            state_counts[state] = state_counts.get(state, 0) + 1
            total_requests += session.request_count
            total_tokens += session.total_tokens
            total_errors += session.error_count

        return {
            'total_sessions': total_sessions,
            'total_users': total_users,
            'state_distribution': state_counts,
            'total_requests': total_requests,
            'total_tokens': total_tokens,
            'total_errors': total_errors,
            'error_rate': total_errors / max(total_requests, 1)
        }

    def _cache_session(self, session: AgentSession):
        """Cache session for performance optimization"""

        if len(self.cache_index) < len(self.session_cache):
            cache_idx = len(self.cache_index)
            self.cache_index[session.agent_id] = cache_idx

            # Store session data in contiguous memory
            self.session_cache[cache_idx] = [
                hash(session.agent_id) & 0xFFFFFFFF,  # Agent ID hash
                hash(session.user_id) & 0xFFFFFFFF,   # User ID hash
                session.created_at,
                session.last_activity,
                session.request_count,
                session.total_tokens,
                session.error_count,
                int(session.state.value == "running"),  # State as binary
                0,  # Reserved
                0   # Reserved
            ]

    async def cleanup_expired_sessions(self):
        """Clean up expired sessions"""

        current_time = time.time()
        expired_sessions = []

        for agent_id, session in self.active_sessions.items():
            if current_time - session.last_activity > self.session_timeout:
                expired_sessions.append(agent_id)

        for agent_id in expired_sessions:
            await self.stop_agent_session(agent_id)

        if expired_sessions:
            self.log.info(f"Cleaned up {len(expired_sessions)} expired sessions")

    async def start_cleanup_task(self):
        """Start background cleanup task"""

        if self.cleanup_task is None:
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def _cleanup_loop(self):
        """Background cleanup loop"""

        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup_expired_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.log.error(f"Cleanup task error: {e}")

    async def shutdown(self):
        """Shutdown agent manager"""

        # Cancel cleanup task
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass

        # Stop all active sessions
        agent_ids = list(self.active_sessions.keys())
        for agent_id in agent_ids:
            await self.stop_agent_session(agent_id)

        self.log.info("Agent manager shutdown complete")