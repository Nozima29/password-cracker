# password-cracker
PBKDF2 hashed passwords cracking algorithm

C program with dictionary attack based password cracking approach for known salt value.

Installing openSSL library for cryptographical algorithms:

    sudo apt-get install libssl-dev

Compiling with gcc(linux):
    
    gcc -o crack crack.c -lcrypto

File description:
* hashedPasswords.txt: input file with users and hashed passwords
* Passwords.txt: output file with cracked passwords
* pass.txt: passwords dataset collected from most common passwords sources, used for dictionary attck
