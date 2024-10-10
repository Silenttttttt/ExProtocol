import struct
import json
import zlib
import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import hashlib
import traceback
from c_hamming import encode_bytes_with_hamming, decode_bytes_with_hamming


class Packet:
    def __init__(self, packet_type, payload: bytes = None, public_key: bytes = None, nonce: bytes = None, packet_size_limit: int = None, encrypted_data: bytes = None, header_dict: dict = None, packet_uuid: str = None, packet_family: str = None, timestamp: int = None, encoding: str = 'utf-8', data_type: str = 'text', status_code: int = 200, connection_key: bytes = None, connection_id: bytes = None):
        self.packet_type = packet_type
        self.payload = payload  # Plaintext payload
        self.public_key = public_key
        self.nonce = nonce
        self.packet_size_limit = packet_size_limit
        self.encrypted_data = encrypted_data
        self.header_dict = header_dict or {}
        self.packet_uuid = packet_uuid
        self.packet_family = packet_family
        self.packet_payload = None  # Structured data to be encrypted
        self.packet_validity = 20  # Validity period in seconds
        self.last_generated_time = None

        self.connection_key = connection_key  # Attribute for private connection key
        self.connection_id = connection_id

        # Header attributes
        self.timestamp = timestamp or int(time.time())
        self.encoding = encoding
        self.data_type = data_type
        self.status_code = status_code

    def prepare_for_encryption(self, connection_key: bytes = None):
        """Prepare the packet for encryption by ensuring all necessary attributes are set."""
        if not self.header_dict or self.packet_type is None:
            raise ValueError("Header dictionary and packet type must be set.")
        
        if not self.nonce:
            self.nonce = os.urandom(ExProtocol.NONCE_LENGTH)  # Generate a nonce if not set
        
        # Check if the packet_payload needs to be regenerated
        current_time = time.time()
        if self.packet_payload is None or (self.last_generated_time and (current_time - self.last_generated_time > self.packet_validity)):
            self.generate_packet_payload(connection_key)
            self.last_generated_time = current_time

    def generate_packet_payload(self, connection_key: bytes = None):
        """Generate the packet payload based on the current attributes."""
        if not self.payload:
            raise ValueError("Payload must be set before generating packet payload.")
        
        # Use the provided connection key or the attribute
        key_to_use = connection_key or self.connection_key
        if not key_to_use:
            raise ValueError("Connection key must be provided.")

        # Construct the header using attributes or provided header_dict
        self.header_dict.update({
            "timestamp": self.timestamp,
            "encoding": self.encoding,
            "type": self.packet_type,
            "data_type": self.data_type
        })
        
        if self.packet_family == 'response':
            self.header_dict["status_code"] = self.status_code

        header_json = zlib.compress(json.dumps(self.header_dict).encode('utf-8'))
        
        # Handle packet_type as bytes or int
        if isinstance(self.packet_type, int):
            packet_type_bytes = struct.pack('!I', self.packet_type)
        else:
            packet_type_bytes = self.packet_type

        # Initialize AESGCM for encryption
        aesgcm = AESGCM(key_to_use)

        # Compress and encrypt the payload
        compressed_payload = zlib.compress(self.payload)
        encrypted_payload = aesgcm.encrypt(self.nonce, compressed_payload, None)
        
        # Calculate the length of the encrypted payload
        encrypted_payload_length = len(encrypted_payload)

        self.packet_payload = (
            packet_type_bytes +
            self.nonce +
            struct.pack('!I', len(header_json)) +
            header_json +
            struct.pack('!Q', encrypted_payload_length) +
            encrypted_payload
        )


    def generate_packet(self, connection_key: bytes) -> bytes:
        """Encrypt the packet using the attributes like header_dict and packet_type."""
        self.prepare_for_encryption(connection_key)
        aesgcm = AESGCM(connection_key)
        
        # Use self.header_dict if it's not empty, otherwise construct the header from attributes
        if self.header_dict:
            header_dict = self.header_dict
        else:
            header_dict = {
                "timestamp": self.timestamp,
                "encoding": self.encoding,
                "type": self.packet_type,
                "data_type": self.data_type
            }
            
            if self.packet_family == 'response':
                header_dict["status_code"] = self.status_code

        header_json = zlib.compress(json.dumps(header_dict).encode('utf-8'))
        
        # Encrypt the header
        encrypted_header = aesgcm.encrypt(self.nonce, header_json, None)
        
        # Calculate the length of the encrypted header
        encrypted_header_length = len(encrypted_header)
        
        # Compress and encrypt the payload
        compressed_payload = zlib.compress(self.payload)
        encrypted_payload = aesgcm.encrypt(self.nonce, compressed_payload, None)
        
        # Calculate the length of the encrypted payload
        encrypted_payload_length = len(encrypted_payload)
        
        # Construct the final packet structure with version at the beginning
        packet = (
            ExProtocol.PROTOCOL_VERSION +
            self.public_key +  # Assuming public_key is used as connection ID
            self.nonce +
            struct.pack('!I', encrypted_header_length) +  # Correctly encode the length of the encrypted header
            encrypted_header +
            struct.pack('!Q', encrypted_payload_length) +  # Include the encrypted payload length
            encrypted_payload
        )
        
        return packet


    @staticmethod
    def decrypt(encrypted_packet: bytes, connection: 'Connection') -> 'Packet':
        try:

            connection_key = connection.connection_key
            connection_id = connection.connection_id

            # Decode the packet using Hamming
            packet_bytes = decode_bytes_with_hamming(encrypted_packet)

            # Calculate offsets
            version_end = ExProtocol.VERSION_LENGTH
            connection_id_end = version_end + ExProtocol.CONNECTION_ID_LENGTH
            nonce_end = connection_id_end + ExProtocol.NONCE_LENGTH
            encrypted_header_length_start = nonce_end
            encrypted_header_length_end = encrypted_header_length_start + ExProtocol.ENCRYPTED_HEADER_LENGTH_SIZE


            # Derive packet UUID by hashing the decoded packet
            packet_uuid = hashlib.sha256(packet_bytes).hexdigest()



            # Check for replay attack
            if packet_uuid in connection.processed_uuids:
                print("Replay attack detected: Packet UUID already processed.")
                return None

            # Store the UUID with the current timestamp
            connection.processed_uuids[packet_uuid] = time.time()

            connection.cleanup_uuids()

            # Extract and verify the protocol version
            version = packet_bytes[:version_end]
            if version != ExProtocol.PROTOCOL_VERSION:
                raise ValueError("Unsupported protocol version.")

            # Extract the connection ID
            extracted_connection_id = packet_bytes[version_end:connection_id_end]
            if connection_id != extracted_connection_id:
                raise ValueError("Connection ID mismatch.")

            # Extract the nonce
            nonce = packet_bytes[connection_id_end:nonce_end]

            # Extract the encrypted header length
            encrypted_header_length_bytes = packet_bytes[encrypted_header_length_start:encrypted_header_length_end]
            encrypted_header_length = struct.unpack('!I', encrypted_header_length_bytes)[0]
            
            # Extract the encrypted header
            encrypted_header_start = encrypted_header_length_end
            encrypted_header_end = encrypted_header_start + encrypted_header_length
            encrypted_header = packet_bytes[encrypted_header_start:encrypted_header_end]

            # Calculate the start and end of the payload length
            payload_length_start = encrypted_header_end
            payload_length_end = payload_length_start + ExProtocol.PAYLOAD_LENGTH_SIZE

            # Ensure the packet is long enough to contain the payload length
            if len(packet_bytes) < payload_length_end:
                raise ValueError("Packet is too short to contain a valid payload length.")

            # Extract the payload length
            payload_length_bytes = packet_bytes[payload_length_start:payload_length_end]
            payload_length = struct.unpack('!Q', payload_length_bytes)[0]
            
            # Extract the encrypted payload
            encrypted_payload_start = payload_length_end
            encrypted_payload_end = encrypted_payload_start + payload_length
            encrypted_payload = packet_bytes[encrypted_payload_start:encrypted_payload_end]

            # Initialize AESGCM for decryption
            aesgcm = AESGCM(connection_key)

            # Decrypt the header
            header_json = zlib.decompress(aesgcm.decrypt(nonce, encrypted_header, None))
            header_dict = json.loads(header_json.decode('utf-8'))

            # Determine packet type
            packet_type = header_dict["type"]

            # Verify required fields based on packet type
            if packet_type == ExProtocol.DATA_FLAG:
                if not all(k in header_dict for k in ("timestamp", "encoding", "type")):
                    raise ValueError("Decrypted header must include 'timestamp', 'encoding', and 'type' for data packets.")
            elif packet_type == ExProtocol.RESPONSE_FLAG:
                if not all(k in header_dict for k in ("status_code", "packet_uuid")):
                    raise ValueError("Decrypted header must include 'status_code' and 'packet_uuid' for response packets.")
            else:
                raise ValueError("Unsupported packet type.")

            # Determine packet family
            packet_family = 'data' if packet_type == ExProtocol.DATA_FLAG else 'response'

            # Decrypt the payload
            plaintext = zlib.decompress(aesgcm.decrypt(nonce, encrypted_payload, None))

            # Generate packet UUID for data packets
            packet_uuid = hashlib.sha256(packet_bytes).hexdigest() if packet_family == 'data' else header_dict.get("packet_uuid")

            # Create a Packet object with the decrypted attributes
            packet = Packet(
                packet_type=packet_type,
                payload=plaintext,
                nonce=nonce,
                header_dict=header_dict,
                packet_uuid=packet_uuid,
                packet_family=packet_family,
                connection_id=connection_id
            )

            return packet

        except InvalidSignature:
            print("Decryption failed: Integrity check failed.")
            return None
        except Exception as e:
            traceback.print_exc()
            print(f"Decryption failed: {e}")
            return None


    def encode_hpw_request(self) -> bytes:
        """Encode an Initiator PoW Request packet."""
        packet = self.public_key + self.packet_type + struct.pack('!I', self.packet_size_limit)
        return encode_bytes_with_hamming(packet)

    def encode_hpw_response(self) -> bytes:
        """Encode a Responder PoW Challenge packet."""
        packet = self.public_key + self.nonce + self.packet_type + self.encrypted_data
        return encode_bytes_with_hamming(packet)

    def encode_handshake_request(self) -> bytes:
        """Encode a Handshake Request packet."""
        packet = self.public_key + self.packet_type + self.payload
        return encode_bytes_with_hamming(packet)

    def encode_handshake_response(self) -> bytes:
        """Encode a Handshake Response packet."""
        packet_size_limit_length = struct.pack('!I', len(str(self.packet_size_limit)))
        encrypted_data_length = struct.pack('!I', len(self.encrypted_data))
        packet = (
            self.public_key +
            self.packet_type +
            self.nonce +
            packet_size_limit_length +
            str(self.packet_size_limit).encode('utf-8') +
            encrypted_data_length +
            self.encrypted_data
        )
        return encode_bytes_with_hamming(packet)

    @staticmethod
    def decode_hpw_request(packet_bytes: bytes) -> 'Packet':
        """Decode an Initiator PoW Request packet."""
        packet_bytes = decode_bytes_with_hamming(packet_bytes)
        public_key = packet_bytes[:91]
        packet_type = packet_bytes[91:92]
        max_packet_size = struct.unpack('!I', packet_bytes[92:96])[0]
        return Packet(packet_type, b'', public_key, packet_size_limit=max_packet_size)

    @staticmethod
    def decode_hpw_response(packet_bytes: bytes) -> 'Packet':
        """Decode a Responder PoW Challenge packet."""
        packet_bytes = decode_bytes_with_hamming(packet_bytes)
        public_key = packet_bytes[:91]
        nonce = packet_bytes[91:107]
        packet_type = packet_bytes[107:108]
        difficulty = packet_bytes[108]
        return Packet(packet_type, b'', public_key, nonce, encrypted_data=difficulty.to_bytes(1, 'big'))

    @staticmethod
    def decode_handshake_request(packet_bytes: bytes) -> 'Packet':
        """Decode a Handshake Request packet."""
        packet_bytes = decode_bytes_with_hamming(packet_bytes)
        public_key = packet_bytes[:91]
        packet_type = packet_bytes[91:92]
        proof_of_work = packet_bytes[92:]
        return Packet(packet_type, proof_of_work, public_key)

    @staticmethod
    def decode_handshake_response(packet_bytes: bytes) -> 'Packet':
        """Decode a Handshake Response packet and return a Packet object."""
        packet_bytes = decode_bytes_with_hamming(packet_bytes)
        public_key = packet_bytes[:91]
        packet_type = packet_bytes[91:92]
        nonce = packet_bytes[92:104]
        packet_size_limit_length = struct.unpack('!I', packet_bytes[104:108])[0]
        packet_size_limit_end = 108 + packet_size_limit_length
        packet_size_limit = int(packet_bytes[108:packet_size_limit_end].decode('utf-8'))
        encrypted_data_length = struct.unpack('!I', packet_bytes[packet_size_limit_end:packet_size_limit_end + 4])[0]
        encrypted_data_start = packet_size_limit_end + 4
        encrypted_data = packet_bytes[encrypted_data_start:encrypted_data_start + encrypted_data_length]
        
        return Packet(packet_type, b'', public_key, nonce, packet_size_limit, encrypted_data)

    def encrypt_with_payload(self, connection_key: bytes) -> bytes:
        """Encrypt the packet using the payload directly."""
        if not isinstance(connection_key, bytes):
            raise ValueError("Connection key must be bytes")
        if not self.payload:
            raise ValueError("Payload is empty")

        aesgcm = AESGCM(connection_key)
        nonce = os.urandom(ExProtocol.NONCE_LENGTH)
        encrypted_payload = aesgcm.encrypt(nonce, self.payload, None)
        return nonce + encrypted_payload



class ExProtocol:
    HPW_FLAG = b'\x01'               # Initiator PoW Request
    HPW_RESPONSE_FLAG = b'\x02'      # Responder PoW Challenge
    HANDSHAKE_FLAG = b'\x03'         # Handshake Request
    HANDSHAKE_RESPONSE_FLAG = b'\x04' # Handshake Response
    DATA_FLAG = 5
    RESPONSE_FLAG = 6

    DEFAULT_VALIDITY_PERIOD = 3600  # 1 hour
    POW_DIFFICULTY = 4
    NONCE_VALIDITY_PERIOD = 60  # 1 minute
    DIFFICULTY_LIMIT = 10
    MAX_PROOF_LENGTH = 64
    POW_TIMEOUT = 20
    MAX_PACKET_SIZE = 8192
    PUBLIC_KEY_SIZE = 91

    PROTOCOL_VERSION = b'\x01'  



    VERSION_LENGTH = len(PROTOCOL_VERSION)
    CONNECTION_ID_LENGTH = 16
    NONCE_LENGTH = 12
    ENCRYPTED_HEADER_LENGTH_SIZE = 4
    PAYLOAD_LENGTH_SIZE = 8



    def __init__(self):
        self.connections = {}
        self.nonce_store = {}


    def generate_key_pair(self):
        try:
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            print(f"Key pair generation failed: {e}")
            return None, None

    def exchange_keys(self, private_key, peer_public_key_bytes):
        try:
            peer_public_key = serialization.load_der_public_key(peer_public_key_bytes)
            shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
            return shared_secret
        except Exception as e:
            print(f"Key exchange failed: {e}")
            return None

    def derive_connection_key(self, shared_secret):
        if shared_secret is None:
            print("Shared secret is None, cannot derive connection key.")
            return None
        try:
            connection_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_secret)
            return connection_key
        except Exception as e:
            print(f"Connection key derivation failed: {e}")
            return None

    def initiate_handshake_request(self) -> tuple[bytes, bytes]:
        private_key, public_key = self.generate_key_pair()
        if not private_key or not public_key:
            print("Failed to generate key pair for handshake.")
            return None, None

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Construct the packet according to the Initiator PoW Request structure
        packet = Packet(self.HPW_FLAG, b'', public_key_bytes, packet_size_limit=self.MAX_PACKET_SIZE)
        encoded_packet = packet.encode_hpw_request()
        return encoded_packet, private_key

    def create_pow_challenge(self, pow_request) -> tuple[bytes, bytes]:
        packet = Packet.decode_hpw_request(pow_request)

        if packet.packet_type != self.HPW_FLAG:
            print("Invalid PoW request.")
            return None, None

        nonce = os.urandom(16)
        difficulty = self.POW_DIFFICULTY

        self.nonce_store[packet.public_key] = {
            'nonce': nonce,
            'difficulty': difficulty,
            'timestamp': time.time()
        }

        pow_challenge_packet = Packet(self.HPW_RESPONSE_FLAG, b'', packet.public_key, nonce, encrypted_data=difficulty.to_bytes(1, 'big'))
        return pow_challenge_packet.encode_hpw_response(), packet.public_key

    def verify_pow(self, nonce, proof, difficulty) -> bool:
        hash_result = hashlib.sha256(nonce + proof).hexdigest()
        return hash_result.startswith('0' * difficulty)

    def complete_pow_request(self, pow_challenge, private_key) -> bytes:
        packet = Packet.decode_hpw_response(pow_challenge)

        if packet.packet_type != self.HPW_RESPONSE_FLAG:
            print("Invalid PoW challenge structure.")
            return None

        if int.from_bytes(packet.encrypted_data, 'big') > self.DIFFICULTY_LIMIT:
            raise Exception("Difficulty too high.")

        proof = 0
        start_time = time.time()
        while True:
            if time.time() - start_time > self.POW_TIMEOUT:
                print("Proof of work timed out.")
                return None

            proof_bytes = proof.to_bytes((proof.bit_length() + 7) // 8, byteorder='big')
            if len(proof_bytes) <= self.MAX_PROOF_LENGTH and self.verify_pow(packet.nonce, proof_bytes, int.from_bytes(packet.encrypted_data, 'big')):
                break
            proof += 1

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        handshake_request_packet = Packet(self.HANDSHAKE_FLAG, proof_bytes, public_key_bytes)
        return handshake_request_packet.encode_handshake_request()


    def perform_handshake_response(self, handshake_request):
        packet = Packet.decode_handshake_request(handshake_request)

        if packet.packet_type != self.HANDSHAKE_FLAG:
            print("Invalid handshake request.")
            return None, None, None

        if len(packet.payload) > self.MAX_PROOF_LENGTH:
            print("Proof of work solution is too long, possible attack.")
            return None, None, None

        nonce_data = self.nonce_store.get(packet.public_key)
        if not nonce_data:
            print("Nonce not found or expired.")
            return None, None, None

        if time.time() - nonce_data['timestamp'] > self.NONCE_VALIDITY_PERIOD:
            print("Nonce expired.")
            del self.nonce_store[packet.public_key]
            return None, None, None

        nonce = nonce_data['nonce']
        difficulty = nonce_data['difficulty']

        if not self.verify_pow(nonce, packet.payload, difficulty):
            print("Invalid PoW solution.")
            return None, None, None

        private_key, public_key_b = self.generate_key_pair()
        shared_secret = self.exchange_keys(private_key, packet.public_key)
        if not shared_secret:
            print("Failed to exchange keys during handshake.")
            return None, None, None

        connection_key = self.derive_connection_key(shared_secret)
        if not connection_key:
            print("Failed to derive connection key during handshake.")
            return None, None, None

        connection_id = os.urandom(16)
        valid_until = time.time() + self.DEFAULT_VALIDITY_PERIOD
        max_packet_size = self.MAX_PACKET_SIZE

        # Encrypt handshake data
        aesgcm = AESGCM(connection_key)
        nonce = os.urandom(ExProtocol.NONCE_LENGTH)
        handshake_data = json.dumps({
            'connection_id': connection_id.hex(),
            'valid_until': valid_until,
            'max_packet_size': max_packet_size
        }).encode('utf-8')
        encrypted_handshake_data = aesgcm.encrypt(nonce, handshake_data, None)

        # Create a Packet object for the handshake response
        handshake_response_packet = Packet(
            self.HANDSHAKE_RESPONSE_FLAG,
            b'',
            public_key_b.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            nonce,
            max_packet_size,
            encrypted_handshake_data
        )

        # Initialize the connection for Node B
        self.initialize_connection(connection_id, connection_key, valid_until, private_key, self.MAX_PACKET_SIZE, max_packet_size, self)

        return handshake_response_packet.encode_handshake_response(), private_key, connection_id


    def complete_handshake(self, handshake_response, private_key):
        packet = Packet.decode_handshake_response(handshake_response)

        if packet.packet_type != self.HANDSHAKE_RESPONSE_FLAG:
            print("Invalid handshake response flag.")
            return None

        # Decrypt the handshake data
        shared_secret = self.exchange_keys(private_key, packet.public_key)
        connection_key = self.derive_connection_key(shared_secret)

        aesgcm = AESGCM(connection_key)
        try:
            handshake_data = aesgcm.decrypt(packet.nonce, packet.encrypted_data, None)
            handshake_info = json.loads(handshake_data.decode('utf-8'))
        except Exception as e:
            print(f"Failed to decrypt handshake data: {e}")
            return None

        connection_id = bytes.fromhex(handshake_info['connection_id'])
        valid_until = handshake_info['valid_until']
        max_packet_size = handshake_info['max_packet_size']

        # Initialize the connection
        self.initialize_connection(connection_id, connection_key, valid_until, private_key, self.MAX_PACKET_SIZE, max_packet_size, self)

        return connection_id

    def initialize_connection(self, connection_id, connection_key, valid_until, private_key, max_packet_size_a, max_packet_size_b, protocol):
        self.connections[connection_id] = Connection(connection_id, connection_key, min(max_packet_size_a, max_packet_size_b), private_key, valid_until, protocol)


class Connection:
    def __init__(self, connection_id, connection_key, max_packet_size, private_key, valid_until, protocol):
        self.protocol = protocol
        self.connection_id = connection_id
        self.connection_key = connection_key
        self.max_packet_size = max_packet_size
        self.private_key = private_key
        self.valid_until = valid_until
        self.processed_uuids = {}

    def cleanup_uuids(self):
        current_time = time.time()
        self.processed_uuids = {uuid: ts for uuid, ts in self.processed_uuids.items() if current_time - ts < 60}


    def create_data_packet(self, data=None, header=None, connection_id=None):
        if connection_id is None:
            connection_id = self.connection_id

        default_header = {
            "timestamp": int(time.time()),
            "encoding": 'utf-8',
            "type": ExProtocol.DATA_FLAG,
            "data_type": "application/json"
        }
        if header:
            default_header.update(header)

        packet = Packet(
            packet_type=ExProtocol.DATA_FLAG,
            payload=data,
            header_dict=default_header,
            public_key=connection_id  # Use connection_id as the public key
        )
        encrypted_packet = packet.generate_packet(self.connection_key)

        if encrypted_packet is None:
            raise Exception("Failed to create data packet.")
        
        packet_uuid = hashlib.sha256(encrypted_packet).hexdigest()
        encoded_packet = encode_bytes_with_hamming(encrypted_packet)
        return encoded_packet, packet_uuid

    def create_response_packet(self, data=None, original_packet_uuid=None, header=None, connection_id=None):
        if connection_id is None:
            connection_id = self.connection_id

        default_header = {
            "timestamp": int(time.time()),
            "encoding": 'utf-8',
            "type": ExProtocol.RESPONSE_FLAG,
            "data_type": "application/json",
            "status_code": 200,
            "packet_uuid": original_packet_uuid  # Include original packet UUID
            
        }
        if header:
            default_header.update(header)

        packet = Packet(
            packet_type=ExProtocol.RESPONSE_FLAG,
            payload=data,
            header_dict=default_header,
            packet_uuid=original_packet_uuid,
            public_key=connection_id,  # Use connection_id as the public key
            status_code=default_header['status_code']
        )
        encrypted_packet = packet.generate_packet(self.connection_key)

        if encrypted_packet is None:
            raise Exception("Failed to create response packet.")
        
        encoded_packet = encode_bytes_with_hamming(encrypted_packet)
        return encoded_packet

    def decrypt_packet(self, encrypted_packet: bytes) -> Packet:
        self.cleanup_uuids()
        return Packet.decrypt(encrypted_packet, self)


# Example usage
def main():
    protocol_a = ExProtocol()
    protocol_b = ExProtocol()

    # Node A initiates a handshake request to Node B
    pow_request, node_a_private_key = protocol_a.initiate_handshake_request()

    # Node B responds with a PoW challenge
    pow_challenge, peer_public_key_bytes = protocol_b.create_pow_challenge(pow_request)

    # Node A completes the handshake request with PoW solution
    handshake_request = protocol_a.complete_pow_request(pow_challenge, node_a_private_key)

    # Node B processes the handshake request and responds
    response, private_key, connection_id_b = protocol_b.perform_handshake_response(handshake_request)

    # Node A completes the handshake by processing the response
    connection_id_a = protocol_a.complete_handshake(response, node_a_private_key)

    print("Handshake completed successfully.")
    print("Connection ID A:", connection_id_a)
    print("Connection ID B:", connection_id_b)

    # Create a data packet
    data_packet, packet_uuid = protocol_a.connections[connection_id_a].create_data_packet(b'Hello, Node B!')
   #  print("Data packet:", data_packet)
    print("Packet UUID:", packet_uuid)

    # Decrypt the data packet
    decrypted_packet = protocol_b.connections[connection_id_b].decrypt_packet(data_packet)
    print("Decrypted data:", decrypted_packet.payload)
    print("Header:", decrypted_packet.header_dict)
    print("Packet type:", decrypted_packet.packet_type)
    print("Packet UUID:", decrypted_packet.packet_uuid)

    # Create a response packet
    response_packet = protocol_b.connections[connection_id_b].create_response_packet(b'Hello, Node A!', original_packet_uuid=decrypted_packet.packet_uuid)
  #  print("Response packet:", response_packet)
    print("Response packet UUID:", packet_uuid)

    # Decrypt the response packet
    packet = protocol_a.connections[connection_id_a].decrypt_packet(response_packet)
    print("Decrypted response:", packet.payload)
    print("Header:", packet.header_dict)


if __name__ == "__main__":
    main()