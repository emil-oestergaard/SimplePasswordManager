#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#define KEY_SIZE 32

void generate_password(int length, const char *characters, char *password);
void save_to_file(FILE *file, const char *title, const unsigned char *encrypted_password, int encrypted_password_len);
int encrypt_password(const unsigned char *key, const unsigned char *plaintext, unsigned char *ciphertext, int *ciphertext_len);

const char *ALPHA_NUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const char *SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:',.<>?";

int main(int argc, char *argv[])
{
    unsigned char key[KEY_SIZE];
    FILE *encryption_key_file = fopen("encryption_key.txt", "r");
    if (encryption_key_file == NULL) {
        encryption_key_file = fopen("encryption_key.txt", "w");
        if (encryption_key_file == NULL) {
            printf("Failed to open encryption_key.txt for writing.\n");
            return 1;
        }

        if (RAND_bytes(key, sizeof(key)) != 1) {
            printf("Failed to generate encryption key.\n");
            fclose(encryption_key_file);
            return 1;
        }

        for (int i = 0; i < KEY_SIZE; i++) {
            fprintf(encryption_key_file, "%02x", key[i]);
        }
        fprintf(encryption_key_file, "\n");
        fclose(encryption_key_file);
    } else {
        for (int i = 0; i < KEY_SIZE; i++) {
            fscanf(encryption_key_file, "%2hhx", &key[i]);
        }
        fclose(encryption_key_file);
    }

    int length = 12;
    int use_special = 0;
    const char *filename = "passwords.txt";
    char *title = NULL;
    int title_allocated = 0;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc)
        {
            length = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-s") == 0)
        {
            use_special = 1;
        }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
        {
            const char *input_title = argv[++i];
            title = malloc(strlen(input_title) + 1);
            if (title == NULL)
            {
                printf("Failed to allocate memory for title\n");
                return 1;
            }

            for (size_t j = 0; j < strlen(input_title); j++)
            {
                title[j] = tolower((unsigned char)input_title[j]);
            }
            title[strlen(input_title)] = '\0';
            title_allocated = 1;
        }
    }

    if (title == NULL)
    {
        title = "unnamed";
    }

    char *password = malloc(length + 1);
    if (password == NULL)
    {
        printf("Failed to allocate memory for password\n");
        if (title_allocated)
        {
            free(title);
        }
        return 1;
    }

    const char *characters = ALPHA_NUMERIC;
    char *combined_characters = NULL;

    if (use_special)
    {
        combined_characters = malloc(strlen(ALPHA_NUMERIC) + strlen(SPECIAL_CHARS) + 1);
        if (combined_characters == NULL)
        {
            printf("Failed to allocate memory for combined characters\n");
            if (title_allocated)
            {
                free(title);
            }
            free(password);
            return 1;
        }

        strcpy(combined_characters, ALPHA_NUMERIC);
        strcat(combined_characters, SPECIAL_CHARS);
        characters = combined_characters;
    }

    srand((unsigned int)time(NULL));

    generate_password(length, characters, password);
    password[length] = '\0';

    unsigned char encrypted_password[1024];
    int encrypted_password_len;
    int encrypt_result = encrypt_password(key, (unsigned char *)password, encrypted_password, &encrypted_password_len);

    if (encrypt_result != 0) {
        printf("Encryption failed.\n");
        if (title_allocated)
        {
            free(title);
        }
        free(password);
        if (use_special) 
        {
            free(combined_characters);
        }
        return 1;
    }

    FILE *file = fopen(filename, "a");
    if (file)
    {
        save_to_file(file, title, encrypted_password, encrypted_password_len);
        fclose(file);
    }
    else
    {
        printf("Failed to open file: %s\n", filename);
        if (title_allocated)
        {
            free(title);
        }
        free(password);
        if (use_special) 
        {
            free(combined_characters);
        }
        return 1;
    }

    if (title_allocated)
    {
        free(title);
    }
    free(password);
    if (use_special) 
    {
        free(combined_characters);
    }
    return 0;
}

void generate_password(int length, const char *characters, char *password)
{
    for (int i = 0; i < length; i++)
    {
        password[i] = characters[rand() % strlen(characters)];
    }
}

void save_to_file(FILE *file, const char *title, const unsigned char *encrypted_password, int encrypted_password_len)
{
    fprintf(file, "%s: ", title);
    for (int i = 0; i < encrypted_password_len; i++) {
        fprintf(file, "%02x", encrypted_password[i]);
    }
    fprintf(file, "\n\n");
}

int encrypt_password(const unsigned char *key, const unsigned char *plaintext, unsigned char *ciphertext, int *ciphertext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("Failed to create EVP_CIPHER_CTX\n");
        return 1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)) {
        printf("Failed to initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char *)plaintext))) {
        printf("Failed to encrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        printf("Failed to finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}