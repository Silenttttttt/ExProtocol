import socket
import json
from protocol_wrapper import ProtocolWrapper
import sys


MAX_PACKET_SIZE = 8192

class SocketProtocolWrapper:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.protocol_wrapper = ProtocolWrapper()

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        print(f"Server listening on {self.host}:{self.port}")

        connection, address = server_socket.accept()
        print(f"Connection established with {address}")

        try:
            # Receive PoW request from client
            pow_request = connection.recv(MAX_PACKET_SIZE)
            print("Received PoW request")
            pow_challenge = self.protocol_wrapper.respond_handshake(pow_request)
            print("Sending PoW challenge")
            connection.sendall(pow_challenge)

            # Receive handshake request with PoW solution
            handshake_request = connection.recv(MAX_PACKET_SIZE)
            print("Received handshake request with PoW solution")
            response = self.protocol_wrapper.perform_handshake_response(handshake_request)
            print("Sending handshake response")
            connection.sendall(response)

            while True:
                # Receive data from client
                data = connection.recv(MAX_PACKET_SIZE)
                if not data:
                    break
                print("Received data")
                # Decrypt and process the received message
                received_data, header, packet_uuid = self.protocol_wrapper.decrypt_data(data)
                print(f"Received from client: {received_data}")


                # Send a response back to client
                response_data = {"response": "Message received"}
                encrypted_response = self.protocol_wrapper.send_response(response_data, original_packet_uuid=packet_uuid)
                print("Sending encrypted response")
                connection.sendall(encrypted_response)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            connection.close()
            server_socket.close()
            if 'e' in locals():
                if e:
                    raise

    def start_client(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))
        print(f"Connected to server at {self.host}:{self.port}")

        try:
            # Initiate PoW request with server
            pow_request = self.protocol_wrapper.create_handshake_request()
            print("Sending PoW request")
            client_socket.sendall(pow_request)

            # Receive PoW challenge from server
            print("Receiving PoW challenge")
            pow_challenge = client_socket.recv(MAX_PACKET_SIZE)
            handshake_request = self.protocol_wrapper.complete_handshake_request(pow_challenge)
            print("Sending handshake request with PoW solution")
            client_socket.sendall(handshake_request)

            # Receive handshake response from server
            print("Receiving handshake response")
            response = client_socket.recv(MAX_PACKET_SIZE)
            self.protocol_wrapper.complete_handshake(response)

            while True:
                # Send a message to server
                message = input("Enter message to send: ")
                request_data = {"message": message}
                encrypted_request, packet_uuid = self.protocol_wrapper.send_data(request_data)
                print("Sending encrypted request")
                client_socket.sendall(encrypted_request)

                # Receive a response from server
                data = client_socket.recv(MAX_PACKET_SIZE)
                if not data:
                    break
                print("Received encrypted response")
                # Decrypt and process the received response
                received_response, header, _ = self.protocol_wrapper.decrypt_response(data)
                print(f"Received from server: {received_response}")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()
            if 'e' in locals():
                if e:
                    raise
def main():

    host = '0.0.0.0'
    port = 12345

    if len(sys.argv) != 2:
        wrapper = SocketProtocolWrapper(host=host, port=port)  # Use '0.0.0.0' to listen on all interfaces

        wrapper.start_server()
        exit()

    role = sys.argv[1].lower()
    wrapper = SocketProtocolWrapper(host=host, port=port)  # Use '0.0.0.0' to listen on all interfaces

    if role == 'server':
        wrapper.start_server()
    elif role == 'client':
        wrapper.start_client()
    else:
        wrapper.start_server()


if __name__ == "__main__":
    main()



