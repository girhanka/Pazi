#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <string.h>

#define AES_KEYLEN 32 
#define AES_BLOCK_SIZE 16
#define ITERATIONS 100

/**
 * @brief Convert hexidecimal to bytes
 * 
 * @param hex_str Pointer to hexidecimal string
 * @param byte_array Pointer to array of bytes to write down
 * @param byte_array_len length of byte_array
 */
int hex_to_bytes(const char *hex_str, unsigned char *byte_array, int byte_array_len) {
    if (strlen(hex_str) != byte_array_len * 2) {
	return 0;
    }

    for (int i = 0; i < byte_array_len; ++i) {
        sscanf(hex_str + 2 * i, "%2hhx", &byte_array[i]);
    }

    return 1;
}

/**
 * @bried Generating key from password using PBKDF2
 *
 * @param password Pointer to password
 * @param salt Pointer to salt
 * @param salt_len Length of salt
 * @param key Pointer to array of generated key
 * @param key_len Length of key
 */
int derive_key(const char*password, const unsigned char *salt, int salt_len, unsigned char *key, int key_len) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password), salt, salt_len, ITERATIONS, EVP_sha256(), key_len, key);
}

/**
 * @brief Encrypt file using AES
 *
 * @param input_file Pointer to name of input file
 * @param output_file Pointer to name of output file
 * @param key Pointer to array of key
 * @param iv Pointer to Initial vector
 */
int encrypt_file(const char *input_file, const char *output_file, const unsigned char *key, const unsigned char *iv) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in) {
        perror("Error opening input file\n");
        return -1;
    }
    if (!out) {
	perror("Error out\n");
       return -1;
    }       

    AES_KEY encrypt_key;
    AES_set_encrypt_key(key, 256, &encrypt_key);
    
    unsigned char inbuf[AES_BLOCK_SIZE], outbuf[AES_BLOCK_SIZE];
    int num_read, num_written;
    unsigned char ecount_buf[AES_BLOCK_SIZE];
    unsigned int num = 0;

    while ((num_read = fread(inbuf, 1, AES_BLOCK_SIZE, in)) > 0) {
        if (num_read < AES_BLOCK_SIZE) {
            memset(inbuf + num_read, AES_BLOCK_SIZE - num_read, AES_BLOCK_SIZE - num_read);
        }
        AES_cfb128_encrypt(inbuf, outbuf, AES_BLOCK_SIZE, &encrypt_key, (unsigned char *)iv, &num, AES_ENCRYPT);
        num_written = fwrite(outbuf, 1, AES_BLOCK_SIZE, out);
        if (num_written != AES_BLOCK_SIZE) {
            perror("write error\n");
            fclose(in);
            fclose(out);
            return -1;
        }
    }
    
    fclose(in);
    fclose(out);
    return 0;
}

/**
 * @brief Main function of program
 *
 * @param argc Count of arguments of command line
 * @param argv Array of command line arguments
 */

int main(int argc, char *argv[]) {

    //salt generation
    unsigned char salt[AES_BLOCK_SIZE];
    if (!RAND_bytes(salt, sizeof(salt))) {
	fprintf(stderr, "Error generating salt\n");
	return 1;
    }
       
    const char *input_file;
    unsigned char *psw;
    int opt;
    unsigned char key[AES_KEYLEN];
    
    while((opt = getopt(argc, argv, "f:p:")) != -1) {
        switch(opt) {
            case 'f':
                input_file = optarg;
                break;
            case 'p':
                psw = optarg;
                break;
        }
    }

    if (!input_file || !psw) {
	fprintf(stderr, "Usage: %s -f <input file> -p <password>\n", argv[0]);
	return 1;
    }

    if (!derive_key(psw, salt, sizeof(salt), key, sizeof(key))) {
	fprintf(stderr, "Error deriving key from password\n");
	return 1;
    }

    char output_file[strlen(input_file)+5];
    strcpy(output_file, input_file);
    strcat(output_file, ".enc");
    
    unsigned char iv[AES_BLOCK_SIZE] = "000102030405060708090a0b0c0d0e0f";
/*
    if (!hex_to_bytes(hex_key, key, AES_KEYLEN)) {
        fprintf(stderr, "Error hex o bytes");
        return 1;
    }
*/
    if (encrypt_file(input_file, output_file, key, iv) == 0) {
        printf("File encrypted successfully\n");
    } else {
        printf("encrypt failed\n");
        return 1;
    }

    return 0;
}
