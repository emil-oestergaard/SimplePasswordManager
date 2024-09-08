#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

void generate_password(int length, int use_special, char *password);

const char *ALPHA_NUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const char *SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:',.<>?";

int main(int argc, char *argv[])
{
    int length = 12;
    int use_special = 0;

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
    }

    char *password = malloc(length + 1);
    if (password == NULL)
    {
        printf("Failed to allocate memory\n");
        return 1;
    }

    generate_password(length, use_special, password);
    password[length] = '\0';

    printf("Generated password: %s\n", password);

    free(password);
    return 0;
}

void generate_password(int length, int use_special, char *password)
{
    const char *characters = ALPHA_NUMERIC;
    char *combined_characters;

    if (use_special)
    {
        combined_characters = malloc(strlen(ALPHA_NUMERIC) + strlen(SPECIAL_CHARS) + 1);
        if (combined_characters == NULL)
        {
            printf("Failed to allocate memory for combined characters\n");
            exit(1);
        }

        strcpy(combined_characters, ALPHA_NUMERIC);
        strcat(combined_characters, SPECIAL_CHARS);

        characters = combined_characters;
    }

    srand(time(NULL));

    for (int i = 0; i < length; i++)
    {
        password[i] = characters[rand() % strlen(characters)];
    }

    if (use_special)
    {
        free(combined_characters);
    }
}