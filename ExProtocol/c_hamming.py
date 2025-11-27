import subprocess
import os
import platform
import sys

# Global flag to track if Hamming binary is available
_HAMMING_AVAILABLE = None
_HAMMING_BINARY_PATH = None

# Magic byte to identify Hamming-encoded data (0xAA = 10101010 in binary)
# This makes it easy to detect Hamming-encoded vs plain data
_HAMMING_MAGIC_BYTE = b'\xAA'

def _get_hamming_binary_path():
    """
    Get the path to the Hamming binary for the current platform.
    
    Returns:
        str or None: Path to the Hamming binary (hamming.exe on Windows, hamming on Unix),
                     or None if not found.
    """
    global _HAMMING_BINARY_PATH
    
    # Return cached path if already found
    if _HAMMING_BINARY_PATH is not None:
        return _HAMMING_BINARY_PATH
    
    # Determine binary name based on platform
    system = platform.system()
    if system == 'Windows':
        binary_name = 'hamming.exe'
    else:  # Linux, macOS, etc. (ELF binary)
        binary_name = 'hamming'
    
    # Get the directory where this module is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # In installed packages: ExProtocol/c_hamming.py and ExProtocol/c_hamming/hamming
    # In development: ExProtocol/c_hamming.py and ../c_hamming/hamming
    hamming_path = os.path.join(script_dir, 'c_hamming', binary_name)
    
    # Check if binary exists
    if not os.path.exists(hamming_path):
        # Try development mode: c_hamming at repo root
        dev_path = os.path.join(os.path.dirname(script_dir), 'c_hamming', binary_name)
        if os.path.exists(dev_path):
            _HAMMING_BINARY_PATH = dev_path
            return dev_path
        
        # Try alternative: relative to package root
        alt_path = os.path.join(script_dir, '..', 'c_hamming', binary_name)
        alt_path = os.path.normpath(alt_path)
        if os.path.exists(alt_path):
            _HAMMING_BINARY_PATH = alt_path
            return alt_path
        
        # Binary not found - cache None
        _HAMMING_BINARY_PATH = None
        return None
    
    _HAMMING_BINARY_PATH = hamming_path
    return hamming_path

def is_hamming_available() -> bool:
    """
    Check if the Hamming binary is available.
    
    Returns:
        bool: True if Hamming binary is available, False otherwise.
    """
    global _HAMMING_AVAILABLE
    
    if _HAMMING_AVAILABLE is not None:
        return _HAMMING_AVAILABLE
    
    hamming_path = _get_hamming_binary_path()
    _HAMMING_AVAILABLE = hamming_path is not None and os.path.exists(hamming_path)
    return _HAMMING_AVAILABLE

def encode_bytes_with_hamming(data_bytes: bytes, use_hamming: bool = True) -> bytes:
    """
    Encode bytes using the Hamming(7,4) encoding implemented in C.
    If Hamming is not available or use_hamming is False, returns the original data.

    Args:
        data_bytes (bytes): The input data to encode.
        use_hamming (bool): Whether to use Hamming encoding. Defaults to True.
                           If False or binary unavailable, returns original data.

    Returns:
        bytes: The encoded data, or original data if Hamming is disabled/unavailable.
    """
    if not isinstance(data_bytes, bytes):
        raise ValueError("Input data must be bytes")

    # If Hamming is disabled, return original data
    if not use_hamming:
        return data_bytes

    # Get the platform-specific binary path
    hamming_path = _get_hamming_binary_path()
    
    # If binary is not available, return original data (graceful fallback)
    if hamming_path is None or not os.path.exists(hamming_path):
        return data_bytes
    
    try:
        process = subprocess.run(
            [hamming_path, 'encode'],
            input=data_bytes,
            capture_output=True,
            text=False  # Ensure binary mode
        )
        if process.returncode != 0:
            # If encoding fails, return original data (graceful fallback)
            return data_bytes

        result = process.stdout
        # Prepend magic byte to indicate this is Hamming-encoded
        # This allows reliable detection during decoding
        return _HAMMING_MAGIC_BYTE + result
    except Exception:
        # If any error occurs, return original data (graceful fallback)
        return data_bytes

def _is_hamming_encoded(data: bytes) -> bool:
    """
    Check if data is Hamming-encoded by checking for the magic byte header.
    This is a reliable way to detect Hamming-encoded data.
    
    Args:
        data: The data to check
        
    Returns:
        bool: True if data starts with Hamming magic byte
    """
    return len(data) > 0 and data[0:1] == _HAMMING_MAGIC_BYTE

def decode_bytes_with_hamming(encoded_bytes: bytes, use_hamming: bool = True) -> bytes:
    """
    Decode bytes using the Hamming(7,4) decoding implemented in C.
    Automatically detects if data is Hamming-encoded by checking for magic byte.
    If data doesn't have magic byte or use_hamming is False, returns original data.
    This makes it cross-compatible - can accept both Hamming-encoded and plain data.

    Args:
        encoded_bytes (bytes): The encoded data to decode (or plain data).
        use_hamming (bool): Whether to attempt Hamming decoding. Defaults to True.
                           If False, returns original data immediately.

    Returns:
        bytes: The decoded data, or original data if not Hamming-encoded/disabled/unavailable.
    """
    if not isinstance(encoded_bytes, bytes):
        raise ValueError("Encoded data must be bytes")

    # If Hamming is disabled, return original data immediately
    if not use_hamming:
        return encoded_bytes

    # Quick check: if data doesn't have Hamming magic byte, return as-is
    # This makes it cross-compatible - can accept both Hamming-encoded and plain data
    if not _is_hamming_encoded(encoded_bytes):
        return encoded_bytes

    # Remove magic byte and get the actual encoded data
    hamming_data = encoded_bytes[1:]

    # Get the platform-specific binary path
    hamming_path = _get_hamming_binary_path()
    
    # If binary is not available, return original data (graceful fallback)
    if hamming_path is None or not os.path.exists(hamming_path):
        # Return original without magic byte (strip it since we detected it)
        return hamming_data
    
    try:
        process = subprocess.run(
            [hamming_path, 'decode'],
            input=hamming_data,
            capture_output=True,
            text=False  # Ensure binary mode
        )
        if process.returncode != 0:
            # If decoding fails, return original data without magic byte
            return hamming_data

        result = process.stdout
        # Verify we got a result
        if len(result) > 0:
            return result
        else:
            # Empty result means decode failed, return original without magic byte
            return hamming_data
    except Exception:
        # If any error occurs, return original data without magic byte
        return hamming_data
