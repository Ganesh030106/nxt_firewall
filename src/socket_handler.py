"""Socket.IO Handler Module

Provides centralized WebSocket communication for real-time firewall events.
Decoupled design prevents circular imports and enables any module to emit events.

Usage:
    from src.socket_handler import socketio
    socketio.emit('event_name', {'data': 'value'})
"""

from flask_socketio import SocketIO
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Socket.IO Configuration
SOCKETIO_CONFIG = {
    'cors_allowed_origins': '*',
    'async_mode': 'threading',
    'logger': False,
    'engineio_logger': False,
    'ping_timeout': 60,
    'ping_interval': 25
}

# [ENHANCEMENT] Decoupled Communication Architecture
# Creates SocketIO instance independently of Flask app to:
# 1. Prevent circular import issues
# 2. Enable event emission from any module
# 3. Centralize WebSocket configuration
socketio = SocketIO(**SOCKETIO_CONFIG)

logger.info("Socket.IO handler initialized")