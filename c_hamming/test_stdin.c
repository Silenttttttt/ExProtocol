#include <stdio.h>
#include <stdlib.h>

int main() {
    // Allocate an initial buffer size
    size_t buffer_size = 1024;
    char *input_string = malloc(buffer_size);
    if (!input_string) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    size_t total_read = 0;
    size_t bytes_read;

    // Read from stdin until EOF
    while ((bytes_read = fread(input_string + total_read, 1, buffer_size - total_read, stdin)) > 0) {
        total_read += bytes_read;
        // Reallocate buffer if necessary
        if (total_read == buffer_size) {
            buffer_size *= 2;
            input_string = realloc(input_string, buffer_size);
            if (!input_string) {
                fprintf(stderr, "Memory reallocation failed\n");
                return 1;
            }
        }
    }

    // Null-terminate the string
    input_string[total_read] = '\0';

    // Print the input
    printf("Received input: %s\n", input_string);

    // Free the allocated memory
    free(input_string);

    return 0;
}