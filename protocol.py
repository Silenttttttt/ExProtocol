from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import os
import json
import struct
import time
import zlib
import hashlib
import traceback
from c_hamming import encode_bytes_with_hamming, decode_bytes_with_hamming


class ExProtocol:
    # Static flags for packet types
    HANDSHAKE_FLAG = b'\x01'
    HANDSHAKE_RESPONSE_FLAG = b'\x02'
    DATA_FLAG = b'\x03'
    RESPONSE_FLAG = b'\x04'
    HPW_FLAG = b'\x05'
    HPW_RESPONSE_FLAG = b'\x06'

    DEFAULT_VALIDITY_PERIOD = 3600  # 1 hour
    POW_DIFFICULTY = 4
    NONCE_VALIDITY_PERIOD = 60  # 1 minute
    DIFFICULTY_LIMIT = 10
    MAX_PROOF_LENGTH = 64
    POW_TIMEOUT = 20
    MAX_PACKET_SIZE = 8192
    PUBLIC_KEY_SIZE = 91

    def __init__(self):
        self.connections = {}
        self.nonce_store = {}
        self.processed_uuids = {}

    def cleanup_uuids(self):
        current_time = time.time()
        self.processed_uuids = {uuid: ts for uuid, ts in self.processed_uuids.items() if current_time - ts < 60}

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

    def derive_session_key(self, shared_secret):
        if shared_secret is None:
            print("Shared secret is None, cannot derive session key.")
            return None
        try:
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_secret)
            return session_key
        except Exception as e:
            print(f"Session key derivation failed: {e}")
            return None

    def initialize_session(self, connection_id, session_key, valid_until, private_key, max_packet_size_a, max_packet_size_b):
        self.connections[connection_id] = {
            'session_key': session_key,
            'valid_until': valid_until,
            'private_key': private_key,
            'max_packet_size': min(max_packet_size_a, max_packet_size_b)
        }

    def perform_handshake_request(self) -> tuple[bytes, bytes]:
        private_key, public_key = self.generate_key_pair()
        if not private_key or not public_key:
            print("Failed to generate key pair for handshake.")
            return None, None
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Prepare the PoW request with public key and HPW flag
        pow_request = (
            public_key_bytes +
            self.HPW_FLAG
        )
        pow_request_encoded = encode_bytes_with_hamming(pow_request)
        return pow_request_encoded, private_key
    
    def perform_pow_challenge(self, pow_request) -> tuple[bytes, bytes]:
        pow_request = decode_bytes_with_hamming(pow_request)
        
        # Extract public key based on known length
        public_key_bytes = pow_request[:self.PUBLIC_KEY_SIZE]
        flag = pow_request[self.PUBLIC_KEY_SIZE:self.PUBLIC_KEY_SIZE + 1]
        
        if flag != self.HPW_FLAG:
            print("Invalid PoW request.")
            return None, None

        # Generate nonce and difficulty
        nonce = os.urandom(16)
        difficulty = self.POW_DIFFICULTY

        # Store the nonce and its metadata
        self.nonce_store[public_key_bytes] = {
            'nonce': nonce,
            'difficulty': difficulty,
            'timestamp': time.time()
        }

        # Prepare the PoW challenge with the public key and response flag
        pow_challenge = public_key_bytes + nonce + self.HPW_RESPONSE_FLAG + difficulty.to_bytes(1, 'big')
        pow_challenge_encoded = encode_bytes_with_hamming(pow_challenge)
        return pow_challenge_encoded, public_key_bytes

    def verify_pow(self, nonce, proof, difficulty) -> bool:
        hash_result = hashlib.sha256(nonce + proof).hexdigest()
        return hash_result.startswith('0' * difficulty)

    def complete_handshake_request(self, pow_challenge, private_key) -> bytes:
        pow_challenge = decode_bytes_with_hamming(pow_challenge)
        
        # Extract the public key, nonce, and difficulty from the challenge
        public_key_bytes_received = pow_challenge[:self.PUBLIC_KEY_SIZE]
        nonce = pow_challenge[self.PUBLIC_KEY_SIZE:self.PUBLIC_KEY_SIZE + 16]
        flag = pow_challenge[self.PUBLIC_KEY_SIZE + 16:self.PUBLIC_KEY_SIZE + 17]
        difficulty = pow_challenge[self.PUBLIC_KEY_SIZE + 17]

        if flag != self.HPW_RESPONSE_FLAG:
            print("Invalid PoW challenge structure.")
            return None

        if difficulty > self.DIFFICULTY_LIMIT:
            raise Exception("Difficulty too high.")

        # Perform proof of work with timeout
        proof = 0
        start_time = time.time()
        while True:
            if time.time() - start_time > self.POW_TIMEOUT:
                print("Proof of work timed out.")
                return None

            proof_bytes = proof.to_bytes((proof.bit_length() + 7) // 8, byteorder='big')
            if len(proof_bytes) <= self.MAX_PROOF_LENGTH and self.verify_pow(nonce, proof_bytes, difficulty):
                break
            proof += 1

        # Prepare the handshake request with the proof of work solution and max packet size
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        handshake_request = (
            public_key_bytes +
            struct.pack('!I', self.MAX_PACKET_SIZE) +  # Include max packet size
            self.HANDSHAKE_FLAG +
            proof_bytes
        )
        handshake_request_encoded = encode_bytes_with_hamming(handshake_request)
        return handshake_request_encoded

    def perform_handshake_response(self, handshake_request):
        handshake_request = decode_bytes_with_hamming(handshake_request)

        # Extract the public key bytes, max packet size, and the proof of work solution
        public_key_bytes = handshake_request[:self.PUBLIC_KEY_SIZE]
        max_packet_size = struct.unpack('!I', handshake_request[self.PUBLIC_KEY_SIZE:self.PUBLIC_KEY_SIZE + 4])[0]
        flag = handshake_request[self.PUBLIC_KEY_SIZE + 4:self.PUBLIC_KEY_SIZE + 5]
        proof_bytes = handshake_request[self.PUBLIC_KEY_SIZE + 5:]

        if flag != self.HANDSHAKE_FLAG:
            print("Invalid handshake request.")
            return None, None, None

        # Check proof length
        if len(proof_bytes) > self.MAX_PROOF_LENGTH:
            print("Proof of work solution is too long, possible attack.")
            return None, None, None

        # Retrieve the correct nonce and difficulty
        nonce_data = self.nonce_store.get(public_key_bytes)
        if not nonce_data:
            print("Nonce not found or expired.")
            return None, None, None

        # Check nonce validity
        if time.time() - nonce_data['timestamp'] > self.NONCE_VALIDITY_PERIOD:
            print("Nonce expired.")
            del self.nonce_store[public_key_bytes]
            return None, None, None

        nonce = nonce_data['nonce']
        difficulty = nonce_data['difficulty']

        # Verify PoW
        if not self.verify_pow(nonce, proof_bytes, difficulty):
            print("Invalid PoW solution.")
            return None, None, None

        # Proceed with key generation and session initialization
        private_key, public_key = self.generate_key_pair()
        shared_secret = self.exchange_keys(private_key, public_key_bytes)
        if not shared_secret:
            print("Failed to exchange keys during handshake.")
            return None, None, None

        session_key = self.derive_session_key(shared_secret)
        if not session_key:
            print("Failed to derive session key during handshake.")
            return None, None, None

        connection_id = os.urandom(16)
        valid_until = time.time() + self.DEFAULT_VALIDITY_PERIOD
        self.initialize_session(connection_id, session_key, valid_until, private_key, self.MAX_PACKET_SIZE, max_packet_size)

        # Prepare encrypted data with session ID and validity timestamp
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        handshake_data = json.dumps({
            'connection_id': connection_id.hex(),
            'valid_until': valid_until,
            'max_packet_size': self.MAX_PACKET_SIZE
        }).encode('utf-8')
        encrypted_handshake_data = aesgcm.encrypt(nonce, handshake_data, None)

        # Prepare the response
        response = (
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ) +
            self.HANDSHAKE_RESPONSE_FLAG +
            nonce +
            encrypted_handshake_data
        )

        response_encoded = encode_bytes_with_hamming(response)
        return response_encoded, private_key, connection_id

    def complete_handshake(self, response, private_key) -> bytes:
        if not response:
            print("Response is empty.")
            return None

        response = decode_bytes_with_hamming(response)

        # Extract the public key bytes and the encrypted handshake data
        public_key_bytes = response[:self.PUBLIC_KEY_SIZE]
        flag = response[self.PUBLIC_KEY_SIZE:self.PUBLIC_KEY_SIZE + 1]
        nonce = response[self.PUBLIC_KEY_SIZE + 1:self.PUBLIC_KEY_SIZE + 13]
        encrypted_handshake_data = response[self.PUBLIC_KEY_SIZE + 13:]

        if flag != self.HANDSHAKE_RESPONSE_FLAG:
            print("HSR flag not found in response.")
            return None

        # Derive shared secret and session key
        shared_secret = self.exchange_keys(private_key, public_key_bytes)
        session_key = self.derive_session_key(shared_secret)
        if not session_key:
            print("Failed to derive session key during handshake completion.")
            return None

        # Decrypt the handshake data
        aesgcm = AESGCM(session_key)
        handshake_data_json = aesgcm.decrypt(nonce, encrypted_handshake_data, None)
        handshake_data = json.loads(handshake_data_json.decode('utf-8'))

        connection_id = bytes.fromhex(handshake_data['connection_id'])
        valid_until = handshake_data['valid_until']
        max_packet_size = handshake_data['max_packet_size']

        self.initialize_session(connection_id, session_key, valid_until, private_key, self.MAX_PACKET_SIZE, max_packet_size)
        return connection_id

    def create_data_packet(self, connection_id, request_data) -> bytes:
        header = {
            "timestamp": int(time.time()),
            "encoding": 'utf-8',
            "type": int.from_bytes(ExProtocol.DATA_FLAG, byteorder='big'),  # Convert byte to int
            "data_type": "application/json"
        }
        encrypted_packet = self.encrypt_data(connection_id, request_data, header)
        if encrypted_packet is None:
            raise Exception("Failed to create request.")
           
        # Derive packet UUID by hashing the encrypted packet
        packet_uuid = hashlib.sha256(encrypted_packet).hexdigest()

        # Encode the entire packet using Hamming code
        encoded_packet = encode_bytes_with_hamming(encrypted_packet)

        return encoded_packet, packet_uuid
        
        
    def create_response_packet(self, connection_id, response_data, original_packet_uuid, response_code=200) -> bytes:
        header = {
            "timestamp": int(time.time()),
            "encoding": 'utf-8',
            "type": int.from_bytes(ExProtocol.RESPONSE_FLAG, byteorder='big'),  # Convert byte to int
            "data_type": "application/json",
            "status_code": response_code,
            "packet_uuid": original_packet_uuid  # Include original packet UUID
        }
        encrypted_packet = self.encrypt_data(connection_id, response_data, header)
        if encrypted_packet is None:
            raise Exception("Failed to create response.")

        # Encode the entire packet using Hamming code
        encoded_packet = encode_bytes_with_hamming(encrypted_packet)

        return encoded_packet
    
    def encrypt_data(self, connection_id, data, header) -> bytes:
        try:
            # Validate header
            if not all(k in header for k in ("timestamp", "encoding", "type", "data_type")):
                print("To encrypt data, header must include 'timestamp', 'encoding', 'type', and 'data_type'.")
                print("Missing fields : ", [k for k in ("timestamp", "encoding", "type", "data_type") if k not in header])
                return None

            session_info = self.connections.get(connection_id)
            if not session_info:
                print("Session not found in encrypt data.")
                return None

            if time.time() > session_info['valid_until']:
                print("Session expired, please perform a new handshake.")
                return None

            session_key = session_info['session_key']
            aesgcm = AESGCM(session_key)
            nonce = os.urandom(12)

            # Compress, then encrypt header and data
            header_json = zlib.compress(json.dumps(header).encode('utf-8'))
            data = zlib.compress(data)

            encrypted_header = aesgcm.encrypt(nonce, header_json, None)
            encrypted_data = aesgcm.encrypt(nonce, data, None)

            encrypted_header_length = struct.pack('!I', len(encrypted_header))
            payload_length = struct.pack('!Q', len(encrypted_data))
            packet = connection_id + nonce + encrypted_header_length + encrypted_header + payload_length + encrypted_data

            return packet

        except Exception as e:
            traceback.print_exc()
            print(f"Encryption failed: {e}")
            return None
        
    def decrypt_packet(self, packet: bytes) -> tuple[bytes, dict, str, str]:
        try:
            # Decode the entire packet using Hamming code
            decoded_packet = decode_bytes_with_hamming(packet)

            connection_id = decoded_packet[:16]
            session_info = self.connections.get(connection_id)
            if not session_info:
                print("Session not found for decryption.")
                return None, None, None, None

            if time.time() > session_info['valid_until']:
                print("Session expired, please perform a new handshake.")
                return None, None, None, None

            session_key = session_info['session_key']
            nonce = decoded_packet[16:28]
            encrypted_header_length = struct.unpack('!I', decoded_packet[28:32])[0]
            encrypted_header = decoded_packet[32:32+encrypted_header_length]
            payload_length = struct.unpack('!Q', decoded_packet[32+encrypted_header_length:40+encrypted_header_length])[0]
            ciphertext = decoded_packet[40+encrypted_header_length:40+encrypted_header_length+payload_length]

            aesgcm = AESGCM(session_key)
            header_json = zlib.decompress(aesgcm.decrypt(nonce, encrypted_header, None))
            header_dict = json.loads(header_json.decode('utf-8'))

            # Validate header fields
            if not all(k in header_dict for k in ("timestamp", "encoding", "type", "data_type")):
                print("Decrypted header must include 'timestamp', 'encoding', 'type', and 'data_type'.")
                return None, None, None, None

            # Check if the request is older than 1 minute
            if time.time() - header_dict["timestamp"] > 60:
                print("Request is older than 1 minute.")
                return None, None, None, None

            # Derive packet UUID from the encrypted header
            packet_uuid = header_dict.get("packet_uuid", hashlib.sha256(decoded_packet).hexdigest())

            # Check for replay attack
            if packet_uuid in self.processed_uuids:
                print("Replay attack detected: Packet UUID already processed.")
                return None, None, None, None

            # Determine packet type
            packet_type = bytes([header_dict["type"]])

            if packet_type == self.DATA_FLAG:
                print("Processing data packet.")
            elif packet_type == self.RESPONSE_FLAG:
                print("Processing response packet.")
            else:
                print("Unknown packet type.")
                return None, None, None, None

            # Process the packet
            if ciphertext:
                plaintext = zlib.decompress(aesgcm.decrypt(nonce, ciphertext, None))
            else:
                plaintext = b''

            # Store the UUID with the current timestamp
            self.processed_uuids[packet_uuid] = time.time()

            # Cleanup old UUIDs
            self.cleanup_uuids()

            return plaintext, header_dict, packet_type, packet_uuid
        except InvalidSignature:
            print("Decryption failed: Integrity check failed.")
            return None, None, None, None
        except Exception as e:
            traceback.print_exc()
            print(f"Decryption failed: {e}")
            return None, None, None, None

# Example usage
def main():
    protocol_a = ExProtocol()
    protocol_b = ExProtocol()

    # Node A initiates a handshake request to Node B
    pow_request, node_a_private_key = protocol_a.perform_handshake_request()

    # Node B responds with a PoW challenge
    pow_challenge, peer_public_key_bytes = protocol_b.perform_pow_challenge(pow_request)

    # Node A completes the handshake request with PoW solution
    handshake_request = protocol_a.complete_handshake_request(pow_challenge, node_a_private_key)

    # Node B processes the handshake request and responds
    response, private_key, connection_id_b = protocol_b.perform_handshake_response(handshake_request)

    # Node A completes the handshake by processing the response
    connection_id_a = protocol_a.complete_handshake(response, node_a_private_key)

    print("Handshake completed successfully.")
    print("Session ID A:", connection_id_a.hex())
    print("Session ID B:", connection_id_b.hex())

    encrypted_packet, packet_uuid = protocol_a.create_data_packet(connection_id_a, b'Hello, Node B!')
    print("Encrypted packet:", encrypted_packet)
    print("Packet UUID:", packet_uuid)

    decrypted_packet, header, flag, packet_uuid_b = protocol_b.decrypt_packet(encrypted_packet)
    print("Decrypted packet:", decrypted_packet)
    print("Header:", header)
    print("Flag:", flag)
    print("Packet UUID:", packet_uuid_b)


if __name__ == "__main__":
    main()