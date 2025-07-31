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
CIPHERS = "AES256-SHA:DHE-RSA-AES256-SHA:AES128-SHA:DHE-RSA-AES128-SHA"

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

def create_ssl_context(ciphers):
    """
    Create an SSL context with specific cipher configuration.

    Args:
        ciphers (str): A string specifying the ciphers to use. Defaults to a predefined list.

    Returns:
        ssl.SSLContext: Configured SSL context.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        # Set the specified ciphers
        context.set_ciphers(ciphers)
        logger.debug(f"Configured SSL context with ciphers: {ciphers}")
    except ssl.SSLError as e:
        logger.error(f"Failed to set ciphers: {e}")
        raise ValueError(f"Invalid ciphers provided: {e}")

    # Enable compatibility options
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_COMPRESSION

    return context

def setup_arista_connection(url, ciphers=CIPHERS):
    """
    Setup SSL context and ensure jsonrpclib is available for Arista connection.

    Args:
        url (str): The URL of the EOS device.
        ciphers (str): A string specifying the ciphers to use. If None, default ciphers are used.

    Returns:
        jsonrpclib.ServerProxy: A configured ServerProxy object for connecting to the EOS device.
    """
    configure_ssl_bypass()
    Server = ensure_jsonrpclib()
    ssl_context = create_ssl_context(ciphers)
    return Server(url, context=ssl_context)