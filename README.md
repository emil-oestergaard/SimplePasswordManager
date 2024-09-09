# SimplePasswordManager
#### Video Demo:  <https://youtu.be/NRzUpbj7ZuE>
#### Description:
This project is a command-line tool for generating, encrypting, storing, and retrieving passwords. 
It uses AES-256 encryption for securing the generated passwords which it simply manages in a text file. The program will create an "encryption_key.txt" file with a newly generated encryption key if file does not exist else program will continue using this key. 
The program supports both alphanumeric and special symbols for password generation. 
User can add a title to each password to associate it with. This title can afterwards be used to retrieve the specific password though neglecting it will decrypt and print every stored password.  

Requirements
* OpenSSL: This project uses the OpenSSL library for encryption and decryption. Ensure you have OpenSSL installed on your system. Can be installed with the following command: "sudo apt-get install libssl-dev" in a Linux based environment like Ubuntu. Check if installed correctly by running command: "opensll --version".

Compilation
* To compile the project use the following command: "gcc -o password_manager password_manager.c -lssl -lcrypto"

Usage
* The project makes use of the following command line arguments:
  * -l length: specifies the length of the password (default is 12)
  * -s: includes special characters in the password (default is False)
  * -t title: sets the title of the password in the text file (default is "unnamed")

  Example: ./password-manager -l 20 -s -t apple-id

* For retrieving stored passwords: ./password-manager -r [title]
  * -r: reads and decrypts stored passwords
  * [title]: optional - if specified searches only for the title else all stored passwords will be displayed
 
Functions:
* generate_password: Generates a random password of the specified length and with the specified characters.
* save_to_file: Saves the encrypted password and title to the password-storage file.
* encrypt_password: Encrypts a generated password.
* decrypt_password: Decrypts an encrypted password.
* hex_to_bin: Converts a hexadecimal string to a binary representation. Nessecary since I store passwords as hexadecimal strings for human readability which does not match the input for encrypt_password function.

Disclaimer
* This tool is intended for educational purposes and personal use. Ensure that you handle and store encryption keys and passwords securely.
