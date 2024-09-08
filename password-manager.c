#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

void generate_password(int length, const char *characters, char *password);
void save_to_file(FILE *file, const char *title, const char *password);

const char *ALPHA_NUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const char *SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:',.<>?";

int main(int argc, char *argv[])
{
    int length = 12;
    int use_special = 0;
    const char *filename = "passwords.txt";
    char *title = NULL;

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
        free(title);
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
            free(title);
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

    printf("Generated password: %s\n", password);

    if (use_special)
    {
        free(combined_characters);
    }

    FILE *file = fopen(filename, "a");
    if (file)
    {
        save_to_file(file, title, password);
        fclose(file);
    }
    else
    {
        printf("Failed to open file: %s\n", filename);
        free(title);
        free(password);
        return 1;
    }

    free(title);
    free(password);
    return 0;
}

void generate_password(int length, const char *characters, char *password)
{
    for (int i = 0; i < length; i++)
    {
        password[i] = characters[rand() % strlen(characters)];
    }
}

void save_to_file(FILE *file, const char *title, const char *password)
{
    fprintf(file, "%s: %s\n\n", title, password);
}
