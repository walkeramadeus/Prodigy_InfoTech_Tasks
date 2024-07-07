def encrypt_caesar_cipher(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                start = ord('a')
            else:
                start = ord('A')
            char_code = ord(char)
            new_char_code = start + (char_code - start + shift_amount) % 26
            ciphertext += chr(new_char_code)
        else:
            ciphertext += char
    return ciphertext

def decrypt_caesar_cipher(ciphertext, shift):
    return encrypt_caesar_cipher(ciphertext, -shift)

def main():
    last_encrypted_message = ""
    last_shift = 0

    while True:
        print("Caesar Cipher")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Decrypt the last encrypted message")
        print("4. Exit")
        choice = input("Enter your choice (1/2/3/4): ")

        if choice == '1':
            plaintext = input("Enter the message to encrypt: ")
            shift = int(input("Enter the shift value: "))
            ciphertext = encrypt_caesar_cipher(plaintext, shift)
            print(f"Encrypted message: {ciphertext}\n")

            last_encrypted_message = ciphertext
            last_shift = shift
        elif choice == '2':
            ciphertext = input("Enter the message to decrypt: ")
            shift = int(input("Enter the shift value: "))
            plaintext = decrypt_caesar_cipher(ciphertext, shift)
            print(f"Decrypted message: {plaintext}\n")
        elif choice == '3':
            if last_encrypted_message:
                plaintext = decrypt_caesar_cipher(last_encrypted_message, last_shift)
                print(f"Decrypted message: {plaintext}\n")
            else:
                print("No message has been encrypted yet.\n")
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.\n")

if __name__ == "__main__":
    main()
