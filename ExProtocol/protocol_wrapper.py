from .protocol import ExProtocol
import json


class ProtocolWrapper:
    def __init__(self, use_hamming: bool = True):
        """
        Initialize ProtocolWrapper instance.
        
        Args:
            use_hamming (bool): Whether to use Hamming encoding for error correction.
                              Defaults to True. If False, packets will be sent without
                              Hamming encoding. The protocol is cross-compatible and can
                              receive both Hamming-encoded and plain data.
        """
        self.protocol = ExProtocol(use_hamming=use_hamming)
        self.connection_id = None
        self.private_key = None
        self.use_hamming = use_hamming

    def create_handshake_request(self):
        # Create a handshake request and store the private key
        pow_request, self.private_key = self.protocol.initiate_handshake_request()
        if not pow_request:
            raise Exception("Failed to initiate handshake request.")
        if self.private_key is None:
            raise Exception("Private key was not generated.")
        return pow_request

    def respond_handshake(self, pow_request):
        # Respond to a PoW request and generate a new private key
        pow_challenge, peer_public_key_bytes = self.protocol.create_pow_challenge(pow_request)
        if not pow_challenge:
            raise Exception("Failed to create PoW challenge.")
        return pow_challenge

    def complete_handshake_request(self, pow_challenge):
        # Complete the handshake request with PoW solution
        handshake_request = self.protocol.complete_pow_request(pow_challenge, self.private_key)
        if not handshake_request:
            raise Exception("Failed to complete handshake request.")
        return handshake_request

    def perform_handshake_response(self, handshake_request):
        # Respond to a handshake request and generate a new private key
        response, self.private_key, self.connection_id = self.protocol.perform_handshake_response(handshake_request)
        if not response:
            raise Exception("Failed to create handshake response.")
        if self.private_key is None:
            raise Exception("Private key was not generated.")
        if not self.connection_id:
            raise Exception("Connection ID was not generated.")
        print(f"Connection ID established: {self.connection_id.hex()}")
        return response

    def complete_handshake(self, response):
        # Complete the handshake using the response and private key
        self.connection_id = self.protocol.complete_handshake(response, self.private_key)
        if not self.connection_id:
            raise Exception("Failed to complete handshake.")
        print(f"Connection ID established: {self.connection_id.hex()}")

    def send_data(self, data, header=None):
        if isinstance(data, dict):
            data = json.dumps(data).encode('utf-8')

        if not self.connection_id:
            raise Exception("No active connection. Please initiate a handshake first.")

        encrypted_message, packet_uuid = self.protocol.connections[self.connection_id].create_data_packet(data, header)
        if encrypted_message is None:
            raise Exception("Failed to encrypt message.")

        return encrypted_message, packet_uuid

    def send_response(self, data, original_packet_uuid, header=None):
        if not self.connection_id:
            raise Exception("No active connection. Please initiate a handshake first.")

        response_data = json.dumps(data).encode('utf-8')
        encrypted_message = self.protocol.connections[self.connection_id].create_response_packet(response_data, original_packet_uuid, header)
        if encrypted_message is None:
            raise Exception("Failed to encrypt message.")

        return encrypted_message

    def decrypt_data(self, encrypted_data_packet):
        if not self.connection_id:
            raise Exception("No active connection. Please initiate a handshake first.")

        packet = self.protocol.connections[self.connection_id].decrypt_packet(encrypted_data_packet)
        if packet is None:
            raise Exception("Failed to decrypt data packet.")

        if packet.packet_type != ExProtocol.DATA_FLAG:
            raise Exception("Invalid flag for data packet.")

        data = json.loads(packet.payload.decode(packet.header_dict['encoding']))
        return data, packet.header_dict, packet.packet_uuid

    def decrypt_response(self, encrypted_response_packet):
        if not self.connection_id:
            raise Exception("No active connection. Please initiate a handshake first.")

        packet = self.protocol.connections[self.connection_id].decrypt_packet(encrypted_response_packet)
        if packet is None:
            raise Exception("Failed to decrypt response packet.")

        if packet.packet_type != ExProtocol.RESPONSE_FLAG:
            raise Exception("Invalid flag for response packet.")

        response = json.loads(packet.payload.decode(packet.header_dict['encoding']))
        return response, packet.header_dict, packet.packet_uuid


# Example usage
def main():
    print("=== Testing ProtocolWrapper with PoW ===")

    # Initialize wrapper objects for Node A and Node B
    wrapper_a = ProtocolWrapper()
    wrapper_b = ProtocolWrapper()

    # Node A creates a PoW request
    pow_request = wrapper_a.create_handshake_request()
    print(f"Node A created PoW request")

    # Node B responds with a PoW challenge
    pow_challenge = wrapper_b.respond_handshake(pow_request)
    print(f"Node B created PoW challenge")

    # Node A completes the handshake request with PoW solution
    handshake_request = wrapper_a.complete_handshake_request(pow_challenge)
    print(f"Node A completed handshake request with PoW solution")

    # Node B processes the handshake request and responds
    response = wrapper_b.perform_handshake_response(handshake_request)
    print(f"Node B created handshake response")

    # Node A completes the handshake using the response
    wrapper_a.complete_handshake(response)

    # Node A sends a request to Node B
    request_data = {"action": "get_data"}
    encrypted_request, request_uuid_a = wrapper_a.send_data(request_data)
    print("Node A sends encrypted request")

    # Node B decrypts the request and sends a response
    received_request, request_header, request_uuid_b = wrapper_b.decrypt_data(encrypted_request)
    print("Request Header:", request_header)
    print("Node B received request:", received_request)

    response_data = {"data": "Here is your data"}
    encrypted_response = wrapper_b.send_response(response_data, original_packet_uuid=request_uuid_b)
    print(f"Node B sends encrypted response")

    # Node A decrypts the response
    received_response, response_header, request_uuid_c = wrapper_a.decrypt_response(encrypted_response)
    print("Response Header:", response_header)
    print("Node A received response:", received_response)

    assert request_uuid_c == request_uuid_b == request_uuid_a

if __name__ == "__main__":
    main()