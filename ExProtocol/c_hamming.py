import subprocess
import os
import platform
import sys

def _get_hamming_binary_path():
    """
    Get the path to the Hamming binary for the current platform.
    
    Returns:
        str: Path to the Hamming binary (hamming.exe on Windows, hamming on Unix)
    """
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
            return dev_path
        
        # Try alternative: relative to package root
        alt_path = os.path.join(script_dir, '..', 'c_hamming', binary_name)
        alt_path = os.path.normpath(alt_path)
        if os.path.exists(alt_path):
            return alt_path
        
        raise FileNotFoundError(
            f"Hamming binary not found. Searched:\n"
            f"  - {hamming_path}\n"
            f"  - {alt_path}\n"
            f"  - {dev_path}\n"
            f"Please ensure the binary is built for your platform ({system}).\n"
            f"Run 'python setup.py build_hamming' or use the build scripts."
        )
    
    return hamming_path

def encode_bytes_with_hamming(data_bytes: bytes) -> bytes:
    """
    Encode bytes using the Hamming(7,4) encoding implemented in C.

    Args:
        data_bytes (bytes): The input data to encode.

    Returns:
        bytes: The encoded data.
    """
    if not isinstance(data_bytes, bytes):
        raise ValueError("Input data must be bytes")

    # Get the platform-specific binary path
    hamming_path = _get_hamming_binary_path()
    
    process = subprocess.run(
        [hamming_path, 'encode'],
        input=data_bytes,
        capture_output=True,
        text=False  # Ensure binary mode
    )
    if process.returncode != 0:
        raise RuntimeError(f"Fast encoding failed: {process.stderr.decode()}")

    result = process.stdout
    # print(f'Encoded bytes: {result}')

    return result

def decode_bytes_with_hamming(encoded_bytes: bytes) -> bytes:
    """
    Decode bytes using the Hamming(7,4) decoding implemented in C.

    Args:
        encoded_bytes (bytes): The encoded data to decode.

    Returns:
        bytes: The decoded data.
    """
    if not isinstance(encoded_bytes, bytes):
        raise ValueError("Encoded data must be bytes")

    # Get the platform-specific binary path
    hamming_path = _get_hamming_binary_path()
    
    process = subprocess.run(
        [hamming_path, 'decode'],
        input=encoded_bytes,
        capture_output=True,
        text=False  # Ensure binary mode
    )
    if process.returncode != 0:
        raise RuntimeError(f"Fast decoding failed: {process.stderr.decode()}")

    result = process.stdout
    # print(f'Decoded bytes: {result}')

    return result
