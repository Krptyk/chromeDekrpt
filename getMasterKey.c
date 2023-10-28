//Example compilation: gcc getMasterKey.c -o getMasterKey.exe -lcrypt32

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <dpapi.h>

typedef struct {
    const char *filepath;
    const char *output_filepath;
} Arguments;

void parse_args(int argc, char *argv[], Arguments *args) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            args->filepath = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            args->output_filepath = argv[++i];
        } else {
            fprintf(stderr, "Unknown argument or missing value: %s\n", argv[i]);
            exit(EXIT_FAILURE);
        }
    }
}

void find_master_key(Arguments *args) {
    FILE *file = fopen(args->filepath, "r");
    if (file == NULL) {
        fprintf(stderr, "Could not open file\n");
        exit(EXIT_FAILURE);
    }

    char line[1024];  // Adjust buffer size as necessary
    char *value_ptr = NULL;
    while (fgets(line, sizeof(line), file) != NULL) {
        char *key_ptr = strstr(line, "encrypted_key");
        if (key_ptr != NULL) {
            char *colon_ptr = strchr(key_ptr, ':');
            if (colon_ptr != NULL) {
                value_ptr = colon_ptr + 2;  // move past the colon, space, and the first double quote
                char *end_ptr = strchr(value_ptr, '"');
                if (end_ptr != NULL) {
                    *end_ptr = '\0';  // terminate string at the ending double quote
                }
                break;  // exit the while loop
            }
        }
    }
    fclose(file);

    if (value_ptr == NULL) {
        fprintf(stderr, "String 'encrypted_key' not found\n");
        exit(EXIT_FAILURE);
    }

    printf("Extracted encrypted_key: %s\n", value_ptr);

    DWORD bufferSize = strlen(value_ptr);
    BYTE *decodedData = malloc(bufferSize);

    if (!CryptStringToBinaryA(value_ptr, bufferSize, CRYPT_STRING_BASE64, decodedData, &bufferSize, NULL, NULL)) {
        fprintf(stderr, "Error decoding base64 string.\n");
        free(decodedData);
        exit(EXIT_FAILURE);
    }

    if (bufferSize <= 5 || memcmp(decodedData, "DPAPI", 5) != 0) {
        fprintf(stderr, "Data doesn't start with DPAPI.\n");
        free(decodedData);
        exit(EXIT_FAILURE);
    }

    DATA_BLOB input, output;
    input.pbData = decodedData + 5;
    input.cbData = bufferSize - 5;

    if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        fprintf(stderr, "CryptUnprotectData failed with error code %u\n", GetLastError());
        free(decodedData);
        exit(EXIT_FAILURE);
    }

    FILE *outputFile = fopen(args->output_filepath, "wb");
    if (!outputFile) {
        fprintf(stderr, "Could not open the output file.\n");
        free(decodedData);
        LocalFree(output.pbData);
        exit(EXIT_FAILURE);
    }
    
    fwrite(output.pbData, 1, output.cbData, outputFile);
    fclose(outputFile);
    printf("Master key written to %s\n", args->output_filepath);

    free(decodedData);
    LocalFree(output.pbData);
}

int main(int argc, char *argv[]) {
    Arguments args = {0};
    parse_args(argc, argv, &args);

    if (args.filepath == NULL || args.output_filepath == NULL) {
        fprintf(stderr, "File path and output file path are required\n");
        printf("Usage:\n");
        printf("[+] -f path to local state file\n");
        printf("[+] -o file to output decoded key to\n\n");
        exit(EXIT_FAILURE);
    }

    find_master_key(&args);

    return 0;
}
