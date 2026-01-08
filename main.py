#!/usr/bin/env python3
"""
FlowScope - Main Entry Point
Professional-grade network traffic analyzer
"""

import sys
import argparse
import asyncio
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from frontend.ui.main_window import MainWindow
from backend.core.packet_capture import PacketCaptureEngine
try:
    from backend.api.rest_api import start_api_server
    HAS_API = True
except ImportError:
    HAS_API = False
from config.settings import Settings
from backend.database.session_manager import SessionManager
import logging


def setup_logging():
    """Configure logging system"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "analyzer.log"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="FlowScope - Professional Network Traffic Analyzer"
    )
    
    parser.add_argument(
        '--headless',
        action='store_true',
        help='Run in headless mode (no GUI)'
    )
    
    parser.add_argument(
        '--api',
        action='store_true',
        help='Start REST API server'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='API server port (default: 8080)'
    )
    
    parser.add_argument(
        '--interface',
        type=str,
        help='Network interface to capture from'
    )
    
    parser.add_argument(
        '--duration',
        type=int,
        help='Capture duration in seconds (headless mode)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        help='Output file for capture (headless mode)'
    )
    
    parser.add_argument(
        '--filter',
        type=str,
        help='BPF filter expression'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config/settings.yaml',
        help='Configuration file path'
    )
    
    return parser.parse_args()


async def run_headless(args, logger):
    """Run analyzer in headless mode"""
    logger.info("Starting FlowScope in headless mode")
    
    # Initialize settings
    settings = Settings(args.config)
    
    # Initialize capture engine
    engine = PacketCaptureEngine(
        interface=args.interface or settings.default_interface,
        bpf_filter=args.filter
    )
    
    # Initialize session manager
    session_mgr = SessionManager()
    session = session_mgr.create_session(f"headless_{args.output or 'capture'}")
    
    try:
        # Start capture
        logger.info(f"Capturing on interface: {engine.interface}")
        await engine.start()
        
        # Run for specified duration or until interrupted
        if args.duration:
            logger.info(f"Capturing for {args.duration} seconds...")
            await asyncio.sleep(args.duration)
        else:
            logger.info("Capturing until interrupted (Ctrl+C)...")
            await asyncio.Event().wait()
            
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user")
    finally:
        # Stop capture
        await engine.stop()
        
        # Save session
        if args.output:
            logger.info(f"Saving capture to {args.output}")
            session_mgr.export_pcap(session.id, args.output)
        
        # Print statistics
        stats = engine.get_statistics()
        logger.info(f"Capture complete:")
        logger.info(f"  Packets captured: {stats['total_packets']}")
        logger.info(f"  Bytes captured: {stats['total_bytes']}")
        logger.info(f"  Duration: {stats['duration']:.2f}s")


def run_gui(args, logger):
    """Run analyzer with GUI"""
    logger.info("Starting FlowScope with GUI")
    
    # Enable high DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    
    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("FlowScope")
    app.setOrganizationName("FlowScope")
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = MainWindow(config_path=args.config)
    window.show()
    
    # Run application
    sys.exit(app.exec())


async def run_api_server(args, logger):
    """Run REST API server"""
    if not HAS_API:
        logger.error("FastAPI not installed. Install with: pip install fastapi uvicorn")
        sys.exit(1)
    logger.info(f"Starting REST API server on port {args.port}")
    await start_api_server(port=args.port)


def main():
    """Main entry point"""
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging()
    
    try:
        # Check for admin privileges
        import os
        if os.name == 'nt':  # Windows
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.warning("Administrator privileges recommended for packet capture")
        else:  # Unix-like
            if os.geteuid() != 0:
                logger.warning("Root privileges recommended for packet capture")
        
        # Run in appropriate mode
        if args.api:
            asyncio.run(run_api_server(args, logger))
        elif args.headless:
            asyncio.run(run_headless(args, logger))
        else:
            run_gui(args, logger)
            
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
