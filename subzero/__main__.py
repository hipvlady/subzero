# Copyright (c) Subzero Development Team.
# Distributed under the terms of the Modified BSD License.

"""
Command-line interface for Subzero Zero Trust API Gateway.

This module provides the main entry point for running Subzero from the command line.
"""

import sys
import argparse
import asyncio
from typing import Optional

from subzero import __version__
from subzero.subzeroapp import UnifiedZeroTrustGateway
from subzero.config.defaults import settings


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
        description='Subzero Zero Trust API Gateway',
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
        """
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'Subzero {__version__}'
    )

    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )

    parser.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Port to bind to (default: 8000)'
    )

    parser.add_argument(
        '--workers',
        type=int,
        default=1,
        help='Number of worker processes (default: 1)'
    )

    return parser.parse_args(args)


async def start_gateway(args: argparse.Namespace) -> None:
    """
    Start the Subzero gateway.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed command line arguments
    """
    print(f"🚀 Starting Subzero Zero Trust API Gateway v{__version__}")
    print(f"📍 Host: {args.host}")
    print(f"📍 Port: {args.port}")
    print(f"📍 Debug: {args.debug}")
    print("-" * 60)

    # Initialize gateway
    gateway = UnifiedZeroTrustGateway()

    try:
        # Start gateway components
        await gateway.start()

        print("✅ Gateway started successfully")
        print(f"🌐 API available at http://{args.host}:{args.port}")
        print("Press Ctrl+C to stop")

        # Keep running
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        print("\n🛑 Shutting down gateway...")
        await gateway.stop()
        print("✅ Gateway stopped successfully")
    except Exception as e:
        print(f"❌ Error starting gateway: {e}")
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

    # Run the gateway
    try:
        asyncio.run(start_gateway(parsed_args))
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()