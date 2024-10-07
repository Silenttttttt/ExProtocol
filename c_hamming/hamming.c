#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Function to generate Hamming(7,4) code
void generate_hamming_code(const uint8_t *data_bits, uint8_t *hamming_code) {
    int data[4];
    for (int i = 0; i < 4; i++) {
        data[i] = data_bits[i];
    }

    // Calculate parity bits
    int p1 = data[0] ^ data[1] ^ data[3];
    int p2 = data[0] ^ data[2] ^ data[3];
    int p3 = data[1] ^ data[2] ^ data[3];

    // Construct the Hamming code
    hamming_code[0] = p1;
    hamming_code[1] = p2;
    hamming_code[2] = data[0];
    hamming_code[3] = p3;
    hamming_code[4] = data[1];
    hamming_code[5] = data[2];
    hamming_code[6] = data[3];
}

// Function to detect and correct a single-bit error in a Hamming(7,4) code
void detect_and_correct_error(uint8_t *hamming_code) {
    int hamming[7];
    for (int i = 0; i < 7; i++) {
        hamming[i] = hamming_code[i];
    }

    // Calculate parity checks
    int p1 = hamming[0] ^ hamming[2] ^ hamming[4] ^ hamming[6];
    int p2 = hamming[1] ^ hamming[2] ^ hamming[5] ^ hamming[6];
    int p3 = hamming[3] ^ hamming[4] ^ hamming[5] ^ hamming[6];

    // Calculate error position
    int error_pos = p1 * 1 + p2 * 2 + p3 * 4;

    // Correct the error if there is one
    if (error_pos != 0) {
        hamming[error_pos - 1] ^= 1;
    }

    // Update the corrected Hamming code
    for (int i = 0; i < 7; i++) {
        hamming_code[i] = hamming[i];
    }
}

// Function to encode a byte array using Hamming(7,4) encoding with padding
void encode_byte_array(const uint8_t *data_bits, size_t len, uint8_t *encoded_array) {
    size_t padding_length = (4 - (len % 4)) % 4;
    size_t padded_len = len + padding_length;
    uint8_t *padded_data = (uint8_t *)malloc(padded_len);
    memcpy(padded_data, data_bits, len);
    memset(padded_data + len, 0, padding_length);

    uint8_t hamming_code[7];
    uint8_t *encoded_ptr = encoded_array;

    for (size_t i = 0; i < padded_len; i += 4) {
        generate_hamming_code(padded_data + i, hamming_code);
        for (int j = 0; j < 7; j++) {
            *encoded_ptr++ = hamming_code[j];
        }
    }

    // Append padding information
    uint8_t padding_info = (padding_length << 1) | 1;
    *encoded_ptr++ = padding_info;

    free(padded_data);
}

// Function to decode a byte array encoded with Hamming(7,4) and correct errors
void decode_byte_array(const uint8_t *encoded_array, size_t len, uint8_t *decoded_array) {
    size_t encoded_data_len = len - 1; // Exclude padding info byte
    uint8_t padding_info = encoded_array[encoded_data_len];
    size_t padding_length = (padding_info >> 1) & 0x07;

    uint8_t hamming_code[7];
    uint8_t corrected_code[4];
    uint8_t *decoded_ptr = decoded_array; // Initialize decoded_ptr

    for (size_t i = 0; i < encoded_data_len; i += 7) {
        for (int j = 0; j < 7; j++) {
            hamming_code[j] = encoded_array[i + j];
        }
        detect_and_correct_error(hamming_code);

        // Extract the original data bits
        corrected_code[0] = hamming_code[2];
        corrected_code[1] = hamming_code[4];
        corrected_code[2] = hamming_code[5];
        corrected_code[3] = hamming_code[6];
        for (int j = 0; j < 4; j++) {
            *decoded_ptr++ = corrected_code[j];
        }
    }

    // Calculate the actual decoded size by subtracting padding
    size_t actual_decoded_size = (decoded_ptr - decoded_array) - padding_length;

    // Write the actual decoded data to stdout
    fwrite(decoded_array, 1, actual_decoded_size, stdout);
}

// Main function for CLI tool
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <encode|decode> [data]\n", argv[0]);
        return 1;
    }

    char *operation = argv[1];
    uint8_t *input_bytes = NULL;
    size_t buffer_size = 1024;
    size_t total_read = 0;
    size_t bytes_read;

    // Allocate initial buffer
    input_bytes = malloc(buffer_size);
    if (!input_bytes) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    // Read from stdin if data is available
    while ((bytes_read = fread(input_bytes + total_read, 1, buffer_size - total_read, stdin)) > 0) {
        total_read += bytes_read;
        // Reallocate buffer if necessary
        if (total_read == buffer_size) {
            buffer_size *= 2;
            input_bytes = realloc(input_bytes, buffer_size);
            if (!input_bytes) {
                fprintf(stderr, "Memory reallocation failed\n");
                return 1;
            }
        }
    }

    if (total_read == 0 && argc == 3) {
        // Use command-line argument if no stdin input
        input_bytes = (uint8_t *)argv[2];
        total_read = strlen(argv[2]);
    } else if (total_read == 0) {
        fprintf(stderr, "No input data provided.\n");
        free(input_bytes);
        return 1;
    }

    if (strcmp(operation, "encode") == 0) {
        // Encode the byte array
        size_t encoded_size = ((total_read + 3) / 4) * 7 + 1; // +1 for padding info
        uint8_t *encoded_array = (uint8_t *)malloc(encoded_size);
        if (!encoded_array) {
            fprintf(stderr, "Memory allocation failed\n");
            free(input_bytes);
            return 1;
        }
        encode_byte_array(input_bytes, total_read, encoded_array);
        fwrite(encoded_array, 1, encoded_size, stdout);

        free(encoded_array);
    } else if (strcmp(operation, "decode") == 0) {
        // Decode the byte array
        size_t decoded_size = ((total_read - 1) / 7) * 4; // -1 for padding info
        uint8_t *decoded_array = (uint8_t *)malloc(decoded_size);
        if (!decoded_array) {
            fprintf(stderr, "Memory allocation failed\n");
            free(input_bytes);
            return 1;
        }
        decode_byte_array(input_bytes, total_read, decoded_array);

        free(decoded_array);
    } else {
        fprintf(stderr, "Invalid operation. Use 'encode' or 'decode'.\n");
        free(input_bytes);
        return 1;
    }

    free(input_bytes);
    return 0;
}