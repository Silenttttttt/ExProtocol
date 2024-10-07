import subprocess

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

    process = subprocess.run(
        ['./c_hamming/hamming', 'encode'],
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

    process = subprocess.run(
        ['./c_hamming/hamming', 'decode'],
        input=encoded_bytes,
        capture_output=True,
        text=False  # Ensure binary mode
    )
    if process.returncode != 0:
        raise RuntimeError(f"Fast decoding failed: {process.stderr.decode()}")

    result = process.stdout
    # print(f'Decoded bytes: {result}')

    return result
