# Experiment 12 - Cryptography

## Title
Security Analysis of AES Block Cipher Modes: ECB vs CBC and Design and Analysis of a Secure Encryption Scheme Using Classical Cryptography, Modular Arithmetic and AES.

## Aim
To implement and analyze classical and modern cryptographic techniques using Python and study the security implications of AES block cipher modes.

## Experiment 12A - AES ECB vs CBC

This experiment implements:
- AES-128 encryption and decryption
- ECB and CBC modes
- PKCS#7 padding
- Random Initialization Vector (IV)
- Ciphertext block comparison
- Security analysis

### Observations

| Parameter | ECB | CBC |
|---|---|---|
| Total Blocks | 5 | 5 |
| Unique Blocks | 2 | 5 |
| Decryption | Successful | Successful |

## Experiment 12B - Cryptography

Implemented techniques:
1. Caesar Cipher
2. Euclidean Algorithm
3. Extended Euclidean Algorithm
4. Modular Inverse
5. Affine Cipher
6. Vigenere Cipher
7. Congruence Relation
8. Fermat's Little Theorem
9. Chinese Remainder Theorem
10. AES-CBC

All nine verification tests passed successfully.

## Technologies Used
- Python 3
- PyCryptodome
- Visual Studio Code

## Installation

Run:

    python -m pip install -r requirements.txt

## Execution

Experiment 12A:

    python experiment12a_aes_ecb_cbc.py

Experiment 12B:

    python experiment12b_cryptography.py

## Output Files

The outputs folder contains:
- experiment12a_output.txt
- experiment12b_output.txt

## Conclusion

Both experiments were implemented successfully. ECB reveals patterns in repeated plaintext blocks, whereas CBC uses chaining and a random IV to hide these patterns in the demonstrated case.

The second experiment verifies classical cryptographic algorithms, modular arithmetic and AES-CBC.

Note: These implementations are intended for educational demonstration, not production security.
