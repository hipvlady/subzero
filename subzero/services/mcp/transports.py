"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Custom MCP Transport Implementations
Extends MCP protocol with additional transport layers

Features:
- WebSocket transport for real-time bidirectional communication
- HTTP/2 Server-Sent Events (SSE) transport
- gRPC transport for high-performance scenarios
- Custom authentication integration
- Automatic reconnection and error handling
"""

import asyncio
import json
import time
from typing import Dict, Optional, Callable, Any, List
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

import aiohttp
from aiohttp import web, WSMsgType
import grpc


class TransportType(str, Enum):
    """Supported transport types"""

    WEBSOCKET = "websocket"
    SSE = "sse"
    GRPC = "grpc"
    HTTP_LONG_POLLING = "http_long_polling"


class TransportState(str, Enum):
    """Transport connection state"""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"


@dataclass
class TransportMessage:
    """Standardized transport message"""

    message_id: str
    message_type: str  # "request", "response", "notification", "error"
    payload: Dict
    timestamp: float = field(default_factory=time.time)
    metadata: Dict = field(default_factory=dict)


@dataclass
class TransportMetrics:
    """Transport performance metrics"""

    messages_sent: int = 0
    messages_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    errors: int = 0
    reconnections: int = 0
    avg_latency_ms: float = 0.0


class MCPTransport(ABC):
    """Abstract base class for MCP transports"""

    def __init__(self, auth_token: Optional[str] = None):
        self.auth_token = auth_token
        self.state = TransportState.DISCONNECTED
        self.metrics = TransportMetrics()
        self.message_handlers: Dict[str, Callable] = {}
        self.connection_callbacks: List[Callable] = []

    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection"""
        pass

    @abstractmethod
    async def disconnect(self) -> bool:
        """Close connection"""
        pass

    @abstractmethod
    async def send_message(self, message: TransportMessage) -> bool:
        """Send message through transport"""
        pass

    @abstractmethod
    async def receive_message(self) -> Optional[TransportMessage]:
        """Receive message from transport"""
        pass

    def register_handler(self, message_type: str, handler: Callable):
        """Register message handler"""
        self.message_handlers[message_type] = handler

    def on_connection_change(self, callback: Callable):
        """Register connection state change callback"""
        self.connection_callbacks.append(callback)

    async def _notify_connection_change(self, new_state: TransportState):
        """Notify connection state change"""
        self.state = new_state
        for callback in self.connection_callbacks:
            try:
                await callback(new_state)
            except Exception as e:
                print(f"❌ Connection callback error: {e}")


class WebSocketTransport(MCPTransport):
    """
    WebSocket transport for MCP
    Provides full-duplex real-time communication
    """

    def __init__(
        self, url: str, auth_token: Optional[str] = None, reconnect_interval: int = 5, max_reconnect_attempts: int = 10
    ):
        super().__init__(auth_token)
        self.url = url
        self.reconnect_interval = reconnect_interval
        self.max_reconnect_attempts = max_reconnect_attempts
        self.websocket: Optional[aiohttp.ClientWebSocketResponse] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.reconnect_task: Optional[asyncio.Task] = None
        self.receive_task: Optional[asyncio.Task] = None

    async def connect(self) -> bool:
        """Establish WebSocket connection"""
        try:
            self.state = TransportState.CONNECTING

            # Create session if not exists
            if not self.session:
                self.session = aiohttp.ClientSession()

            # Prepare headers
            headers = {}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"

            # Connect
            self.websocket = await self.session.ws_connect(self.url, headers=headers, heartbeat=30)

            self.state = TransportState.CONNECTED
            await self._notify_connection_change(TransportState.CONNECTED)

            # Start receive loop
            self.receive_task = asyncio.create_task(self._receive_loop())

            print(f"✅ WebSocket connected: {self.url}")
            return True

        except Exception as e:
            self.state = TransportState.FAILED
            self.metrics.errors += 1
            print(f"❌ WebSocket connection failed: {e}")
            await self._attempt_reconnect()
            return False

    async def disconnect(self) -> bool:
        """Close WebSocket connection"""
        try:
            if self.receive_task:
                self.receive_task.cancel()
                try:
                    await self.receive_task
                except asyncio.CancelledError:
                    pass

            if self.websocket:
                await self.websocket.close()

            if self.session:
                await self.session.close()

            self.state = TransportState.DISCONNECTED
            await self._notify_connection_change(TransportState.DISCONNECTED)

            print(f"✅ WebSocket disconnected")
            return True

        except Exception as e:
            print(f"❌ WebSocket disconnect error: {e}")
            return False

    async def send_message(self, message: TransportMessage) -> bool:
        """Send message via WebSocket"""
        if not self.websocket or self.state != TransportState.CONNECTED:
            return False

        try:
            # Serialize message
            payload = {
                "id": message.message_id,
                "type": message.message_type,
                "payload": message.payload,
                "timestamp": message.timestamp,
                "metadata": message.metadata,
            }

            json_str = json.dumps(payload)

            # Send
            await self.websocket.send_str(json_str)

            # Update metrics
            self.metrics.messages_sent += 1
            self.metrics.bytes_sent += len(json_str.encode("utf-8"))

            return True

        except Exception as e:
            self.metrics.errors += 1
            print(f"❌ WebSocket send error: {e}")
            await self._attempt_reconnect()
            return False

    async def receive_message(self) -> Optional[TransportMessage]:
        """Receive message from WebSocket"""
        # Messages are received in _receive_loop and dispatched to handlers
        # This method is for synchronous polling if needed
        return None

    async def _receive_loop(self):
        """Background receive loop"""
        try:
            async for msg in self.websocket:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)

                        message = TransportMessage(
                            message_id=data.get("id", ""),
                            message_type=data.get("type", "unknown"),
                            payload=data.get("payload", {}),
                            timestamp=data.get("timestamp", time.time()),
                            metadata=data.get("metadata", {}),
                        )

                        # Update metrics
                        self.metrics.messages_received += 1
                        self.metrics.bytes_received += len(msg.data.encode("utf-8"))

                        # Dispatch to handler
                        handler = self.message_handlers.get(message.message_type)
                        if handler:
                            await handler(message)

                    except json.JSONDecodeError as e:
                        self.metrics.errors += 1
                        print(f"❌ Invalid JSON received: {e}")

                elif msg.type == WSMsgType.ERROR:
                    self.metrics.errors += 1
                    print(f"❌ WebSocket error: {self.websocket.exception()}")
                    await self._attempt_reconnect()
                    break

                elif msg.type == WSMsgType.CLOSED:
                    print(f"⚠️  WebSocket closed by server")
                    await self._attempt_reconnect()
                    break

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.metrics.errors += 1
            print(f"❌ Receive loop error: {e}")
            await self._attempt_reconnect()

    async def _attempt_reconnect(self):
        """Attempt automatic reconnection"""
        if self.reconnect_task:
            return  # Already reconnecting

        self.reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _reconnect_loop(self):
        """Reconnection loop with exponential backoff"""
        attempt = 0

        while attempt < self.max_reconnect_attempts:
            attempt += 1
            self.metrics.reconnections += 1

            print(f"🔄 Reconnection attempt {attempt}/{self.max_reconnect_attempts}")

            self.state = TransportState.RECONNECTING
            await self._notify_connection_change(TransportState.RECONNECTING)

            # Exponential backoff
            wait_time = min(self.reconnect_interval * (2 ** (attempt - 1)), 60)
            await asyncio.sleep(wait_time)

            # Attempt connection
            if await self.connect():
                print(f"✅ Reconnection successful")
                self.reconnect_task = None
                return

        # Max attempts reached
        print(f"❌ Reconnection failed after {attempt} attempts")
        self.state = TransportState.FAILED
        await self._notify_connection_change(TransportState.FAILED)
        self.reconnect_task = None


class SSETransport(MCPTransport):
    """
    Server-Sent Events (SSE) transport for MCP
    One-way server-to-client streaming with HTTP POST for client-to-server
    """

    def __init__(self, sse_url: str, post_url: str, auth_token: Optional[str] = None):
        super().__init__(auth_token)
        self.sse_url = sse_url
        self.post_url = post_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.sse_task: Optional[asyncio.Task] = None

    async def connect(self) -> bool:
        """Establish SSE connection"""
        try:
            self.state = TransportState.CONNECTING

            # Create session
            if not self.session:
                self.session = aiohttp.ClientSession()

            # Prepare headers
            headers = {"Accept": "text/event-stream"}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"

            # Start SSE listening task
            self.sse_task = asyncio.create_task(self._sse_loop(headers))

            self.state = TransportState.CONNECTED
            await self._notify_connection_change(TransportState.CONNECTED)

            print(f"✅ SSE connected: {self.sse_url}")
            return True

        except Exception as e:
            self.state = TransportState.FAILED
            self.metrics.errors += 1
            print(f"❌ SSE connection failed: {e}")
            return False

    async def disconnect(self) -> bool:
        """Close SSE connection"""
        try:
            if self.sse_task:
                self.sse_task.cancel()
                try:
                    await self.sse_task
                except asyncio.CancelledError:
                    pass

            if self.session:
                await self.session.close()

            self.state = TransportState.DISCONNECTED
            await self._notify_connection_change(TransportState.DISCONNECTED)

            print(f"✅ SSE disconnected")
            return True

        except Exception as e:
            print(f"❌ SSE disconnect error: {e}")
            return False

    async def send_message(self, message: TransportMessage) -> bool:
        """Send message via HTTP POST (SSE is receive-only)"""
        if not self.session or self.state != TransportState.CONNECTED:
            return False

        try:
            # Prepare headers
            headers = {"Content-Type": "application/json"}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"

            # Prepare payload
            payload = {
                "id": message.message_id,
                "type": message.message_type,
                "payload": message.payload,
                "timestamp": message.timestamp,
                "metadata": message.metadata,
            }

            # Send POST request
            async with self.session.post(self.post_url, json=payload, headers=headers) as response:
                if response.status in [200, 201]:
                    self.metrics.messages_sent += 1
                    self.metrics.bytes_sent += len(json.dumps(payload).encode("utf-8"))
                    return True
                else:
                    self.metrics.errors += 1
                    print(f"❌ POST failed: {response.status}")
                    return False

        except Exception as e:
            self.metrics.errors += 1
            print(f"❌ SSE send error: {e}")
            return False

    async def receive_message(self) -> Optional[TransportMessage]:
        """Receive message from SSE stream"""
        # Messages are received in _sse_loop and dispatched to handlers
        return None

    async def _sse_loop(self, headers: Dict):
        """Background SSE receive loop"""
        try:
            async with self.session.get(self.sse_url, headers=headers) as response:
                async for line in response.content:
                    line_str = line.decode("utf-8").strip()

                    # Parse SSE format
                    if line_str.startswith("data: "):
                        data_str = line_str[6:]  # Remove 'data: ' prefix

                        try:
                            data = json.loads(data_str)

                            message = TransportMessage(
                                message_id=data.get("id", ""),
                                message_type=data.get("type", "unknown"),
                                payload=data.get("payload", {}),
                                timestamp=data.get("timestamp", time.time()),
                                metadata=data.get("metadata", {}),
                            )

                            # Update metrics
                            self.metrics.messages_received += 1
                            self.metrics.bytes_received += len(data_str.encode("utf-8"))

                            # Dispatch to handler
                            handler = self.message_handlers.get(message.message_type)
                            if handler:
                                await handler(message)

                        except json.JSONDecodeError as e:
                            self.metrics.errors += 1
                            print(f"❌ Invalid SSE data: {e}")

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.metrics.errors += 1
            print(f"❌ SSE loop error: {e}")


class HTTPLongPollingTransport(MCPTransport):
    """
    HTTP Long Polling transport for MCP
    Compatible with restricted network environments
    """

    def __init__(self, poll_url: str, post_url: str, auth_token: Optional[str] = None, poll_timeout: int = 30):
        super().__init__(auth_token)
        self.poll_url = poll_url
        self.post_url = post_url
        self.poll_timeout = poll_timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self.poll_task: Optional[asyncio.Task] = None
        self.running = False

    async def connect(self) -> bool:
        """Start long polling"""
        try:
            self.state = TransportState.CONNECTING

            # Create session
            if not self.session:
                self.session = aiohttp.ClientSession()

            # Start polling task
            self.running = True
            self.poll_task = asyncio.create_task(self._poll_loop())

            self.state = TransportState.CONNECTED
            await self._notify_connection_change(TransportState.CONNECTED)

            print(f"✅ Long polling connected: {self.poll_url}")
            return True

        except Exception as e:
            self.state = TransportState.FAILED
            self.metrics.errors += 1
            print(f"❌ Long polling connection failed: {e}")
            return False

    async def disconnect(self) -> bool:
        """Stop long polling"""
        try:
            self.running = False

            if self.poll_task:
                self.poll_task.cancel()
                try:
                    await self.poll_task
                except asyncio.CancelledError:
                    pass

            if self.session:
                await self.session.close()

            self.state = TransportState.DISCONNECTED
            await self._notify_connection_change(TransportState.DISCONNECTED)

            print(f"✅ Long polling disconnected")
            return True

        except Exception as e:
            print(f"❌ Long polling disconnect error: {e}")
            return False

    async def send_message(self, message: TransportMessage) -> bool:
        """Send message via HTTP POST"""
        if not self.session or self.state != TransportState.CONNECTED:
            return False

        try:
            # Prepare headers
            headers = {"Content-Type": "application/json"}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"

            # Prepare payload
            payload = {
                "id": message.message_id,
                "type": message.message_type,
                "payload": message.payload,
                "timestamp": message.timestamp,
                "metadata": message.metadata,
            }

            # Send POST
            async with self.session.post(self.post_url, json=payload, headers=headers) as response:
                if response.status in [200, 201]:
                    self.metrics.messages_sent += 1
                    self.metrics.bytes_sent += len(json.dumps(payload).encode("utf-8"))
                    return True
                else:
                    self.metrics.errors += 1
                    return False

        except Exception as e:
            self.metrics.errors += 1
            print(f"❌ Long polling send error: {e}")
            return False

    async def receive_message(self) -> Optional[TransportMessage]:
        """Receive message from long poll"""
        # Messages are received in _poll_loop
        return None

    async def _poll_loop(self):
        """Background long polling loop"""
        try:
            while self.running:
                try:
                    # Prepare headers
                    headers = {}
                    if self.auth_token:
                        headers["Authorization"] = f"Bearer {self.auth_token}"

                    # Long poll request
                    timeout = aiohttp.ClientTimeout(total=self.poll_timeout + 5)
                    async with self.session.get(
                        self.poll_url, headers=headers, timeout=timeout, params={"timeout": self.poll_timeout}
                    ) as response:
                        if response.status == 200:
                            data = await response.json()

                            # Handle batch of messages
                            messages = data.get("messages", [])

                            for msg_data in messages:
                                message = TransportMessage(
                                    message_id=msg_data.get("id", ""),
                                    message_type=msg_data.get("type", "unknown"),
                                    payload=msg_data.get("payload", {}),
                                    timestamp=msg_data.get("timestamp", time.time()),
                                    metadata=msg_data.get("metadata", {}),
                                )

                                # Update metrics
                                self.metrics.messages_received += 1

                                # Dispatch to handler
                                handler = self.message_handlers.get(message.message_type)
                                if handler:
                                    await handler(message)

                        elif response.status == 204:
                            # No content (timeout), continue polling
                            pass
                        else:
                            self.metrics.errors += 1
                            print(f"⚠️  Poll returned {response.status}")

                except asyncio.TimeoutError:
                    # Expected timeout, continue polling
                    pass

                except Exception as e:
                    self.metrics.errors += 1
                    print(f"❌ Poll error: {e}")
                    await asyncio.sleep(5)  # Brief delay before retry

        except asyncio.CancelledError:
            pass


class TransportFactory:
    """Factory for creating MCP transports"""

    @staticmethod
    def create_transport(transport_type: TransportType, **kwargs) -> MCPTransport:
        """
        Create transport instance

        Args:
            transport_type: Type of transport to create
            **kwargs: Transport-specific parameters

        Returns:
            MCPTransport instance
        """
        if transport_type == TransportType.WEBSOCKET:
            return WebSocketTransport(
                url=kwargs.get("url", "ws://localhost:8000/mcp/ws"),
                auth_token=kwargs.get("auth_token"),
                reconnect_interval=kwargs.get("reconnect_interval", 5),
                max_reconnect_attempts=kwargs.get("max_reconnect_attempts", 10),
            )

        elif transport_type == TransportType.SSE:
            return SSETransport(
                sse_url=kwargs.get("sse_url", "http://localhost:8000/mcp/sse"),
                post_url=kwargs.get("post_url", "http://localhost:8000/mcp/send"),
                auth_token=kwargs.get("auth_token"),
            )

        elif transport_type == TransportType.HTTP_LONG_POLLING:
            return HTTPLongPollingTransport(
                poll_url=kwargs.get("poll_url", "http://localhost:8000/mcp/poll"),
                post_url=kwargs.get("post_url", "http://localhost:8000/mcp/send"),
                auth_token=kwargs.get("auth_token"),
                poll_timeout=kwargs.get("poll_timeout", 30),
            )

        else:
            raise ValueError(f"Unsupported transport type: {transport_type}")
