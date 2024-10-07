# ExProtocol

ExProtocol provides a comprehensive framework for establishing secure connections and exchanging data between nodes. It includes mechanisms for performing proof-of-work (PoW) challenges, establishing encrypted sessions, and transmitting data with integrity checks. The protocol is designed to be extensible and adaptable to different use cases, making it suitable for a wide range of applications.

## Features

- **Secure Handshake**: Establishes a secure connection using elliptic curve cryptography and proof-of-work challenges.
- **Encrypted Communication**: Ensures data confidentiality and integrity using AES-GCM encryption.
- **Flexible Packet Structure**: Supports various packet types with customizable headers and payloads.
- **Replay Attack Prevention**: Implements mechanisms to detect and prevent replay attacks.
- **Error Correction**: Utilizes Hamming code for error detection and correction in packet transmission.
## Getting Started

### Prerequisites
- Python 3.8 or higher
- Required Python packages: `cryptography`

### Installation
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/ExProtocol.git
   ```
2. Navigate to the project directory:
   ```
   cd ExProtocol
   ```
3. Install the required packages:
   ```
   pip install cryptography
   ```


# 1. Initiator PoW Request (HPW)

| Field | Description | Length (Bytes) | Notes |
|---------------------|------------------------------------|----------------|--------------------------------|
| Public Key | Node A's public key | 91 | Fixed length |
| Type | Packet type identifier | 1 | Fixed length, replaces HPW_FLAG|
| Packet Size Limit | Maximum packet size allowed | Variable | Last field, no length prefix |

# 2. Responder PoW Challenge (HPR)
| Field | Description | Length (Bytes) | Notes |
|---------------------|------------------------------------|----------------|--------------------------------|
| Public Key | Node A's public key | 91 | Fixed length |
| Nonce | Random nonce for PoW | 16 | Fixed length |
| Type | Packet type identifier | 1 | Fixed length, replaces HPR_FLAG|
| Difficulty | PoW difficulty level | 1 | Fixed length |

# 3. Handshake Request (HSK)
| Field | Description | Length (Bytes) | Notes |
|---------------------|------------------------------------|----------------|--------------------------------|
| Public Key | Node A's public key | 91 | Fixed length |
| Type | Packet type identifier | 1 | Fixed length, replaces HANDSHAKE_FLAG |
| Proof of Work Solution | Solution to PoW challenge | Variable | Last field, no length prefix |

# 4. Handshake Response (HSR)
| Field | Description | Length (Bytes) | Notes |
|-----------------------------|------------------------------------|----------------|--------------------------------|
| Public Key | Node B's public key | 91 | Fixed length |
| Type | Packet type identifier | 1 | Fixed length, replaces HANDSHAKE_RESPONSE_FLAG |
| Nonce | Random nonce for connection | 12 | Fixed length |
| Packet Size Limit Length| Length of packet size limit | 4 | Length prefix |
| Packet Size Limit | Maximum packet size allowed | Variable | Length-prefixed |
| Encrypted Handshake Data Length | Length of encrypted data | 4 | Length prefix |
| Encrypted Handshake Data| Encrypted connection information | Variable | Length-prefixed |
Encrypted Handshake Data Fields
| Field | Description |
|----------------|--------------------------------------------------|
| Connection ID | Unique identifier for the connection |
| Valid Until| Timestamp indicating connection expiration |
| Max Packet Size | Maximum packet size agreed upon |


# 5. General data packet structure

| Field                   | Description                                                                 | Length (Bytes) | Encrypted |
|-------------------------|-----------------------------------------------------------------------------|----------------|-----------|
| Version                 | Protocol version number                                                     | 1              | No        |
| Connection ID           | Unique identifier for the connection                                           | 16             | No        |
| Encrypted Header Length | Length of the encrypted header                                              | 4              | No        |
| Encrypted Header        | Contains metadata and control information                                   | Variable       | Yes       |
| Payload Length          | Length of the encrypted payload                                             | 8              | No        |
| Payload                 | The main data being transmitted                                             | Variable       | Yes       |

## Encrypted Header Fields

| Field       | Description                                                                 |
|-------------|-----------------------------------------------------------------------------|
| Timestamp   | The time at which the packet was created, used for freshness validation     |
| Encoding    | Character encoding used for the payload, typically 'utf-8'                  |
| Type        | Indicates the nature of the packet (e.g., data, response)                   |
| Data Type   | Specifies the type of data being transmitted (e.g., text, binary)           |

## Data Packet Structure

- **Type**: Set to indicate a data packet
- **Data Type**: Specifies the type of data (e.g., text, binary)

## Response Packet Structure

- **Type**: Set to indicate a response packet
- **Data Type**: Specifies the type of data (e.g., text, binary)
- **Status Code**: Required field indicating the status of the response (e.g., HTTP-like status codes)

### Encrypted Header Fields for Response Packet

| Field       | Description                                                                 |
|-------------|-----------------------------------------------------------------------------|
| Timestamp   | The time at which the packet was created, used for freshness validation     |
| Encoding    | Character encoding used for the payload, e.g. 'utf-8'                       |
| Type        | Indicates the nature of the packet (response)                               |
| Data Type   | Specifies the type of data being transmitted (e.g., text, binary)           |
| Status Code | Indicates the status of the response (e.g., 200, 500)                       |



### Usage
- Import the `ExProtocol` class and use it to establish secure connections and exchange data between nodes.
- Refer to the example usage in the `main()` function for a demonstration of the protocol's capabilities.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your changes. Or just message me directly.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- Thanks to the contributors and the open-source community for their support and inspiration.
