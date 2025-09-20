#!/usr/bin/env python3
"""
Startup script for Zero Trust AI Gateway

Simple launcher that sets up the environment and starts the application
with optimal performance settings.
"""

import os
import sys
import uvloop
import asyncio
from .aigatewayapp import ZeroTrustGatewayApp

def main():
    """Main startup function"""
    print("🚀 Starting Zero Trust AI Gateway...")
    print("=" * 50)

    # Set uvloop for maximum performance
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    # Create and initialize the application
    app = ZeroTrustGatewayApp()

    print(f"📡 Port: {app.port}")
    print(f"🔐 Auth0 Domain: {app.auth0_domain}")
    print(f"⚡ Performance Mode: Enabled (uvloop)")
    print(f"🛡️ Security: Zero Trust")
    print("=" * 50)

    # Initialize and start
    app.initialize()
    app.start()

if __name__ == "__main__":
    main()