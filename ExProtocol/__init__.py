"""
ExProtocol - Secure peer-to-peer communication protocol
"""

__version__ = '0.1.0'

from .protocol import ExProtocol, Packet, Connection
from .protocol_wrapper import ProtocolWrapper
from .protocol_socket import SocketProtocolWrapper
from .c_hamming import encode_bytes_with_hamming, decode_bytes_with_hamming

__all__ = [
    'ExProtocol',
    'Packet',
    'Connection',
    'ProtocolWrapper',
    'SocketProtocolWrapper',
    'encode_bytes_with_hamming',
    'decode_bytes_with_hamming',
]

