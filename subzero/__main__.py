# Copyright (c) Subzero Development Team.
# Distributed under the terms of the Modified BSD License.

"""
Command-line interface for Subzero Zero Trust API Gateway.

This module provides the main entry point for running Subzero from the command line.
"""

import argparse
import asyncio
import sys

from subzero import __version__


def parse_args(args=None):
    """
    Parse command line arguments.

    Parameters
    ----------
    args : list of str, optional
        Command line arguments to parse. If None, uses sys.argv.

    Returns
    -------
    argparse.Namespace
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Subzero Zero Trust API Gateway",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start gateway with default configuration
  subzero

  # Start with custom configuration file
  subzero --config /path/to/config.py

  # Run in debug mode
  subzero --debug

  # Show version
  subzero --version
        """,
    )

    parser.add_argument("--version", action="version", version=f"Subzero {__version__}")

    parser.add_argument("--config", type=str, help="Path to configuration file")

    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")

    parser.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")

    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes (default: 1)")

    parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload on code changes (development only)"
    )

    parser.add_argument(
        "--access-log/--no-access-log",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Enable/disable access logging (default: enabled)",
    )

    return parser.parse_args(args)


def start_server(args: argparse.Namespace) -> None:
    """
    Start the Subzero FastAPI server with uvicorn + uvloop.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed command line arguments
    """
    try:
        import uvicorn
    except ImportError:
        print("❌ uvicorn is not installed. Install with: pip install uvicorn[standard]")
        sys.exit(1)

    # Try to use uvloop for better performance
    try:
        import uvloop

        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        print("✅ Using uvloop for high-performance event loop")
    except ImportError:
        print("⚠️  uvloop not available, using default asyncio (install with: pip install uvloop)")

    print(f"🚀 Starting Subzero Zero Trust API Gateway v{__version__}")
    print(f"📍 Host: {args.host}")
    print(f"📍 Port: {args.port}")
    print(f"📍 Workers: {args.workers}")
    print(f"📍 Debug: {args.debug}")
    if args.reload:
        print("🔄 Auto-reload: ENABLED (development mode)")
    print("-" * 60)
    print(f"📖 API Documentation: http://{args.host}:{args.port}/docs")
    print(f"📖 ReDoc: http://{args.host}:{args.port}/redoc")
    print(f"🔍 OpenAPI Schema: http://{args.host}:{args.port}/openapi.json")
    print("-" * 60)

    # Uvicorn configuration
    uvicorn_config = {
        "app": "subzero.api.server:app",
        "host": args.host,
        "port": args.port,
        "workers": args.workers,
        "log_level": "debug" if args.debug else "info",
        "access_log": args.access_log,
        "reload": args.reload,
        "server_header": False,  # Don't expose server details
        "date_header": False,  # Don't expose date header
    }

    # Use uvloop if available
    try:
        import uvloop  # noqa: F401

        uvicorn_config["loop"] = "uvloop"
    except ImportError:
        uvicorn_config["loop"] = "asyncio"

    # Start server
    try:
        uvicorn.run(**uvicorn_config)
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")
        if args.debug:
            import traceback

            traceback.print_exc()
        sys.exit(1)


def main(args=None):
    """
    Main entry point for the Subzero CLI.

    Parameters
    ----------
    args : list of str, optional
        Command line arguments. If None, uses sys.argv.
    """
    parsed_args = parse_args(args)

    # Start the FastAPI server with uvicorn
    start_server(parsed_args)


if __name__ == "__main__":
    main()
