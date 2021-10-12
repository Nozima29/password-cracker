#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#define KEY_LEN 32
#define KEK_KEY_LEN 16
#define ITERATION 10000

bool check_guess(char *guess, char *hash, char *user)
{
    size_t i;
    unsigned char *out;
    unsigned char salt_value[] = {'S', 'K', 'K', 'U', ' ', 's', 'e', 'c', 'l', 'a', 'b'};
    out = (unsigned char *)malloc(sizeof(unsigned char) * KEK_KEY_LEN);
    char str[32];
    char *pout = str;

    guess[strlen(guess) - 1] = '\0';

    FILE *fp2;
    fp2 = fopen("Passwords.txt", "a");

    if (PKCS5_PBKDF2_HMAC(guess, strlen(guess), salt_value, sizeof(salt_value), ITERATION, EVP_sha512(), KEK_KEY_LEN, out) != 0)
    {

        for (i = 0; i < KEK_KEY_LEN; i++)
        {
            pout += sprintf(pout, "%02x", out[i]);
        }

        if (strcmp(str, hash) == 0)
        {
            fprintf(fp2, "%s", user);
            fprintf(fp2, "%s", ":");
            fprintf(fp2, "%s", guess);
            fprintf(fp2, "%s", "\n");
            printf("%s\n", guess);
            return true;
        }
    }

    else
    {
        fprintf(stderr, "Hashing failed\n");
    }

    fclose(fp2);
    free(out);
    return 0;
}

void crack(char *hash, char *user)
{
    char *line = {0};
    char *pass;
    size_t len = 0;
    FILE *fp;
    fp = fopen("pass.txt", "r");
    while (getline(&line, &len, fp) != -1)
    {
        pass = line;
        if (check_guess(pass, hash, user))
        {
            break;
        }
    }

    fclose(fp);
}

int main(int argc, char *argv[])
{
    FILE *fp1;
    char *ln = {0};
    size_t l = 0;
    char *file_name;
    file_name = "hashedPasswords.txt";

    if (argc > 1)
        file_name = argv[1];

    fp1 = fopen(file_name, "r");

    while (getline(&ln, &l, fp1) != -1)
    {
        char *hash;
        char *user;
        user = ln;
        hash = &ln[strlen(ln) - 33];
        user[strlen(user) - 34] = '\0';

        hash[strlen(hash) - 1] = '\0';
        crack(hash, user);
    }

    fclose(fp1);
    return 0;
}
