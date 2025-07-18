# backend/utils/ssl_utils.py
"""
Shared SSL configuration utilities to eliminate code duplication.
"""

import ssl
import urllib3
import subprocess
import sys
import logging

logger = logging.getLogger(__name__)

def configure_ssl_bypass():
    """Configure SSL to bypass certificate verification."""
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logger.debug("SSL certificate verification bypassed")

def ensure_jsonrpclib():
    """Ensure jsonrpclib-pelix is installed and import it."""
    try:
        from jsonrpclib import Server
        return Server
    except ImportError:
        logger.info("Installing jsonrpclib-pelix...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "jsonrpclib-pelix"])
            from jsonrpclib import Server
            logger.info("jsonrpclib-pelix installed successfully")
            return Server
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install jsonrpclib-pelix: {e}")
            raise ImportError("Could not install jsonrpclib-pelix. Please install manually: pip install jsonrpclib-pelix")

def setup_arista_connection():
    """Setup SSL bypass and ensure jsonrpclib is available."""
    configure_ssl_bypass()
    return ensure_jsonrpclib()