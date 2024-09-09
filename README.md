# SimplePasswordManager
#### Video Demo:  <https://youtu.be/NRzUpbj7ZuE>
#### Description:
SimplePasswordManager is a command-line utility designed to generate, encrypt, store, and retrieve passwords. It ensures the security of generated passwords using AES-256 encryption and maintains these passwords in a simple text file. The program will create an "encryption_key.txt" file with a newly generated encryption key if file does not exist else program will continue using this key. The tool features a flexible password generation mechanism supporting both alphanumeric and special characters, and allows users to tag each password with a title for easier retrieval. If a title is not provided, passwords are stored with a default "unnamed" title. Users can retrieve all stored passwords or search for a specific one by title.

The program operates in two primary modes: password generation and password retrieval. In the generation mode, users can specify the length of the password and whether to include special characters. In the retrieval mode, users can decrypt and display stored passwords, either retrieving all stored entries or searching for a specific title.

## Context
I, like many others, sometimes fall into the habit of reusing passwords across multiple accounts due to the difficulty of remembering numerous, complex passwords. This practice poses a significant security risk, as a breach on one account can lead to unauthorized access to many others. To tackle this issue, I decided to try to develop a secure and convenient way to manage my passwords. Additionally, I hope for the future of this project to address the challenge of managing passwords across different platforms, such as a Windows PC and an iOS device. Lastly, this project serves as a personal learning experience, allowing me to explore various aspects of cybersecurity, encryption, memory management, and error handling in C.

## Requirements
* OpenSSL: This project uses the OpenSSL library for encryption and decryption. Ensure you have OpenSSL installed on your system. Can be installed with the following command: "sudo apt-get install libssl-dev" in a Linux based environment like Ubuntu. Check if installed correctly by running command: "opensll --version".

## Compilation
* To compile the project use the following command: "gcc -o password_manager password_manager.c -lssl -lcrypto"

## Usage
* The project makes use of the following command line arguments:
  * -l length: specifies the length of the password (default is 12)
  * -s: includes special characters in the password (default is False)
  * -t title: sets the title of the password in the text file (default is "unnamed")
  * -r [title]: reads and decrypts stored passwords. Optionally, you can specify a title to retrieve a specific password; if no title is provided, all stored passwords will be displayed.
  
  ### Examples:
  * ./password-manager -l 20 -s -t apple-id (Generates a 20-character password with special characters and titles it "apple-id")
  * ./password_manager -r apple-id (Retrieves a password titled "apple-id" from the password storage if it exists)
  * ./password_manager -r (Retrieves all passwords from the password storage)

## File Structure
The project consists of the following files:
* password_manager.c: The main source file implementing the functionality of the password manager. This file contains all the logic for password generation, encryption, decryption, and file operations.
* encryption_key.txt: A file automatically created or read by the program to store the AES encryption key. If this file does not exist, the program generates a new encryption key and saves it to this file.
* passwords.txt: A text file where the encrypted passwords and their associated titles are stored. Each line contains a title followed by a semi-colon and its corresponding encrypted password in hexadecimal format.

## Design Choices
* AES-256 Encryption: I chose to use AES-256 encryption for the generated passwords since I got very intrested by the last lecture Cybersecurity and studied further about that subject. During this I read that AES-256 is commonly used to encrypt passwords due to its strong security and efficiency. It ensures that even if the password storage file is compromised, the passwords remain secure. Currently, the encryption key itself is stored in a separate file, but it isn't protected with an extra password. In the future, I plan to add an extra layer of security by requiring a password to access the encryption key. This means that even if someone manages to steal both the password file and the key, they would still need an additional password to unlock the key and decrypt the passwords.
* Hexadecimal Encoding: Encrypted passwords are stored as hexadecimal strings for human readability and simplicity since this project is for fun and debugging at its current state. In a production environment I would probably choose to store the passwords as a binary representation since that is what is required for decryption of this data. However at the current stage I have instead implemented the hex_to_bin function which performs this convertion.
* Dynamic Memory Management: The program dynamically allocates memory for titles, passwords, and storage entries. This ensures flexibility in handling varying amounts of data and avoids fixed-size limitations. I have spent a lot of time debugging through my code to remove memory leaks, which involved carefully managing allocated memory and ensuring every dynamically allocated block was properly freed when program finished or threw an error.
* Error Handling: Error handling is implemented to manage file operations, memory allocation, and encryption as well as decryption processes. This improves the robustness and reliability of the program. For example, when a file operation fails, the program provides a clear error message and safely exits without leaving open file handles or corrupting data. 
* Command-Line Arguments: The use of command-line arguments allows users to easily customize password generation and retrieval processes. In addition I really liked the assignments with command-line arguments when writing in C although I also thought about using a switch-case statement. Eventually I decided on using command-line arguments since I found them more challenging.

Functions:
* generate_password: Generates a random password of the specified length and with the specified characters.
* save_to_file: Saves the encrypted password and title to the password-storage file.
* encrypt_password: Encrypts a generated password.
* decrypt_password: Decrypts an encrypted password.
* hex_to_bin: Converts a hexadecimal string to a binary representation. Nessecary since I store passwords as hexadecimal strings for human readability which does not match the input for encrypt_password function.

Disclaimer
* This tool is intended for educational purposes and personal use. Ensure that you handle and store encryption keys and passwords securely.
