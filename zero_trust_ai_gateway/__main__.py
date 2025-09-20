"""Entry point for Zero Trust AI Gateway application."""

import sys
import uvloop
import asyncio
from .aigatewayapp import ZeroTrustGatewayApp

def main():
    """Main entry point for the Zero Trust AI Gateway."""
    # Set uvloop as default event loop for maximum performance
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    app = ZeroTrustGatewayApp.instance()
    app.initialize()
    app.start()

if __name__ == "__main__":
    main()