# Password Manager

This project is a **Password Manager** application that provides secure storage and retrieval of passwords using various encryption techniques. It was created as a practical demonstration of implementing encryption and decryption methods in Python. The project supports multiple encryption methods to meet different security needs.

---

## Features

- **Password Storage**: Save passwords securely for different services.
- **Encryption Options**: Choose from the following encryption methods:
  - **Fernet**: Symmetric encryption using the Fernet module.
  - **RSA**: Asymmetric encryption with RSA public and private keys.
  - **AES (Advanced Encryption Standard)**: Symmetric encryption using AES in GCM mode.
- **Password Retrieval**: Retrieve stored passwords securely.
- **Service Management**: List all stored services.

---

## Technologies Used

- **Python**
- `cryptography` library for AES and Fernet encryption.
- `rsa` library for RSA encryption.
- Standard libraries such as `os`, `json`, `base64`, and `getpass`.

---

## How It Works

### Encryption Methods

1. **Fernet Encryption**
   - Symmetric encryption using a master password to generate the key.
   - Secure and straightforward.

2. **RSA Encryption**
   - Asymmetric encryption that uses public and private keys.
   - Ideal for scenarios where key exchange security is crucial.

3. **AES Encryption**
   - Utilizes a master password to derive a key through PBKDF2.
   - Implements AES-GCM mode for authenticated encryption.

### Password Storage
- Passwords are stored in a `passwords.json` file.
- Each password is encrypted based on the chosen encryption method.

### Password Retrieval
- Passwords can be decrypted using the appropriate key or master password.

---

## Installation and Usage

### Prerequisites
- Python 3.x
- Install dependencies using `pip`:
  ```bash
  pip install rsa cryptography
  ```

### Running the Application
1. Clone the repository.
2. Run the application:
   ```bash
   python <script_name>.py
   ```
3. Follow the prompts to add, retrieve, or manage passwords

---

## Example Workflow

1. **Start the Application**
   - Enter a master password to generate the encryption key.

2. **Add a Password**
   - Select an encryption method (Fernet, RSA, or AES).
   - Provide a service name and password to encrypt and save.

3. **Retrieve a Password**
   - Enter the service name.
   - Decrypt the stored password using the appropriate method.

4. **List Services**
   - View all stored services to manage your passwords easily.

---

## File Structure
- `passwords.json`: Stores encrypted passwords.
- `main()`: Handles the application workflow.
- Utility functions for encryption, decryption, and password management.

---

## Notes
- RSA key pair generation occurs at runtime.
- AES encryption uses a randomly generated salt and IV for each password.
- Ensure the `passwords.json` file is kept secure.

---

## Future Enhancements
- Implement a GUI for better user experience.
- Add unit tests for robustness.
- Include error handling for edge cases and invalid inputs.

---

## Contributors
- [NaomieClareEdward]
- [EricSTOIAN]
- [ritayoussef]



