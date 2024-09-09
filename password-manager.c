#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#define KEY_SIZE 32
#define INITIAL_CAPACITY 10

void generate_password(int length, const char *characters, char *password);
void save_to_file(FILE *file, const char *title, const unsigned char *encrypted_password, int encrypted_password_len);
int encrypt_password(const unsigned char *key, const unsigned char *plaintext, unsigned char *ciphertext, int *ciphertext_len);
int decrypt_password(const unsigned char *key, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int *plaintext_len);
void hex_to_bin(const char *hex, unsigned char *bin, int *bin_len);

const char *ALPHA_NUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const char *SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:',.<>?";

typedef struct {
    char *title;
    char *encrypted_password;
    int encrypt_password_len;
} PasswordEntry;

int main(int argc, char *argv[])
{
    unsigned char key[KEY_SIZE];
    FILE *encryption_key_file = fopen("encryption_key.txt", "r");
    if (encryption_key_file == NULL) 
    {
        encryption_key_file = fopen("encryption_key.txt", "w");
        if (encryption_key_file == NULL) 
        {
            printf("Failed to open encryption_key.txt for writing.\n");
            return 1;
        }

        if (RAND_bytes(key, sizeof(key)) != 1) 
        {
            printf("Failed to generate encryption key.\n");
            fclose(encryption_key_file);
            return 1;
        }

        for (int i = 0; i < KEY_SIZE; i++) 
        {
            fprintf(encryption_key_file, "%02x", key[i]);
        }
        fprintf(encryption_key_file, "\n");
        fclose(encryption_key_file);
    } 
    else 
    {
        for (int i = 0; i < KEY_SIZE; i++) 
        {
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
        else if (strcmp(argv[i], "-r") == 0)
        {
            FILE *passwords_file = fopen(filename, "r");
            if (passwords_file == NULL) 
            {
                printf("Error opening passwordsfile.");
                return 1;
            }  

            size_t capacity = INITIAL_CAPACITY;
            size_t size = 0;
            PasswordEntry *entries = malloc(capacity * sizeof(PasswordEntry));
            if (entries == NULL) {
                printf("Error allocating memory");
                fclose(passwords_file);
                return 1;
            }

            char line[256];
            while (fgets(line, sizeof(line), passwords_file)) 
            {
                line[strcspn(line, "\n")] = '\0';

                char *delimiter_pos = strchr(line, ':');
                if (delimiter_pos != NULL) 
                {
                    *delimiter_pos = '\0';
                    char *title = line;
                    char *encrypted_password_hex = delimiter_pos + 1;
                    
                    unsigned char encrypted_password[1024];
                    int encrypted_password_len;
                    hex_to_bin(encrypted_password_hex, encrypted_password, &encrypted_password_len);

                    if (size == capacity) 
                    {
                        capacity *= 2;
                        PasswordEntry *new_entries = realloc(entries, capacity * sizeof(PasswordEntry));
                        if (new_entries == NULL) 
                        {
                            printf("Error reallocating memory");
                            for (size_t j = 0; j < size; j++) 
                            {
                                free(entries[j].title);
                                free(entries[j].encrypted_password);
                            }
                            free(entries);
                            fclose(passwords_file);
                            return 1;
                        }
                        entries = new_entries;
                    }

                    entries[size].title = strdup(title);
                    if (entries[size].title == NULL) 
                    {
                        printf("Error allocating memory for title");
                        for (size_t j = 0; j < size; j++) 
                        {
                            free(entries[j].title);
                            free(entries[j].encrypted_password);
                        }
                        free(entries);
                        fclose(passwords_file);
                        return 1;
                    }

                    entries[size].encrypted_password = malloc(encrypted_password_len);
                    if (entries[size].encrypted_password == NULL) 
                    {
                        printf("Error allocating memory for encrypted password");
                        for (size_t j = 0; j <= size; j++) 
                        {
                            free(entries[j].title);
                            free(entries[j].encrypted_password);
                        }
                        free(entries);
                        fclose(passwords_file);
                        return 1;
                    }

                    memcpy(entries[size].encrypted_password, encrypted_password, encrypted_password_len);

                    entries[size].encrypt_password_len = encrypted_password_len;
                    size++;
                }
            }

            fclose(passwords_file);

            if (i + 1 < argc)
            {
                char *title = argv[++i];
                for(int i = 0; title[i]; i++)
                {
                    title[i] = tolower(title[i]);
                }
                for (size_t i = 0; i < size; i++) 
                {
                    if (strcmp(entries[i].title, title) == 0) 
                    {
                        unsigned char decrypted_password[1024];
                        int decrypted_password_len;
                        int decrypt_result = decrypt_password(key, entries[i].encrypted_password, entries[i].encrypt_password_len, decrypted_password, &decrypted_password_len);
        
                        if (decrypt_result != 0) 
                        {
                            printf("Decryption failed.\n");
                            for (size_t i = 0; i < size; i++) 
                            {
                                free(entries[i].title);
                                free(entries[i].encrypted_password);
                            }
                            free(entries);
                            return 1;
                        }
        
                        decrypted_password[decrypted_password_len] = '\0';
                        
                        printf("%s: %s\n", entries[i].title, decrypted_password);
                    }
                }
            }
            else
            {
                for (size_t i = 0; i < size; i++) 
                {
                    unsigned char decrypted_password[1024];
                    int decrypted_password_len;
                    int decrypt_result = decrypt_password(key, entries[i].encrypted_password, entries[i].encrypt_password_len, decrypted_password, &decrypted_password_len);
    
                    if (decrypt_result != 0) 
                    {
                        printf("Decryption failed.\n");
                        for (size_t i = 0; i < size; i++) 
                        {
                            free(entries[i].title);
                            free(entries[i].encrypted_password);
                        }
                        free(entries);
                        return 1;
                    }
    
                    decrypted_password[decrypted_password_len] = '\0';
                    
                    printf("%s: %s\n", entries[i].title, decrypted_password);
                }
            }

            for (size_t i = 0; i < size; i++) 
            {
                free(entries[i].title);
                free(entries[i].encrypted_password);
            }
            free(entries);
            return 0;
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

    printf("generated password: %s\n", password);

    unsigned char encrypted_password[1024];
    int encrypted_password_len;
    int encrypt_result = encrypt_password(key, (unsigned char *)password, encrypted_password, &encrypted_password_len);

    if (encrypt_result != 0) 
    {
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
    fprintf(file, "%s:", title);
    for (int i = 0; i < encrypted_password_len; i++) 
    {
        fprintf(file, "%02x", encrypted_password[i]);
    }
    fprintf(file, "\n\n");
}

int encrypt_password(const unsigned char *key, const unsigned char *plaintext, unsigned char *ciphertext, int *ciphertext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) 
    {
        printf("Failed to create EVP_CIPHER_CTX\n");
        return 1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)) 
    {
        printf("Failed to initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char *)plaintext))) 
    {
        printf("Failed to encrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
    {
        printf("Failed to finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int decrypt_password(const unsigned char *key, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int *plaintext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) 
    {
        printf("Failed to create EVP_CIPHER_CTX\n");
        return 1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)) 
    {
        printf("Failed to initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    int len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) 
    {
        printf("Failed to decrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
    {
        printf("Failed to finalize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

void hex_to_bin(const char *hex, unsigned char *bin, int *bin_len)
{
    int len = strlen(hex);
    if (len % 2 != 0)
    {
        printf("Invalid hexadecimal string length\n");
        *bin_len = 0;
        return;
    }

    *bin_len = len / 2;
    for (int i = 0; i < *bin_len; i++)
    {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }
}