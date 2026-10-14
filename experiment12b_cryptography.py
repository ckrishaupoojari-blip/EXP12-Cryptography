
# ============================================================
# EXPERIMENT 12B
# DESIGN AND ANALYSIS OF A SECURE ENCRYPTION SCHEME
# ============================================================

from math import gcd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# 1. CAESAR CIPHER

def caesar_encrypt(text, shift):
    result = ""

    for char in text:
        if char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char

    return result


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# 2. EUCLIDEAN ALGORITHM

def euclidean_gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return abs(a)


# 3. EXTENDED EUCLIDEAN ALGORITHM

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0

    gcd_value, x1, y1 = extended_gcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return gcd_value, x, y


# 4. MODULAR INVERSE

def modular_inverse(a, m):
    gcd_value, x, y = extended_gcd(a, m)

    if gcd_value != 1:
        return None

    return x % m


# 5. AFFINE CIPHER

def affine_encrypt(text, a, b):
    if gcd(a, 26) != 1:
        raise ValueError("Invalid key: gcd(a,26) must be 1.")

    result = ""

    for char in text:
        if char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if char.isupper() else ord('a')
            x = ord(char) - base
            encrypted = (a * x + b) % 26
            result += chr(encrypted + base)
        else:
            result += char

    return result


def affine_decrypt(text, a, b):
    inverse_a = modular_inverse(a, 26)

    if inverse_a is None:
        raise ValueError("No multiplicative inverse exists.")

    result = ""

    for char in text:
        if char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if char.isupper() else ord('a')
            y = ord(char) - base
            decrypted = (inverse_a * (y - b)) % 26
            result += chr(decrypted + base)
        else:
            result += char

    return result


# 6. VIGENERE CIPHER

def vigenere_encrypt(text, key):
    key = key.upper()

    if not key or not key.isascii() or not key.isalpha():
        raise ValueError("Key must contain English letters only.")

    result = ""
    key_index = 0

    for char in text:
        if char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            encrypted = (ord(char) - base + shift) % 26
            result += chr(encrypted + base)
            key_index += 1
        else:
            result += char

    return result


def vigenere_decrypt(text, key):
    key = key.upper()

    if not key or not key.isascii() or not key.isalpha():
        raise ValueError("Key must contain English letters only.")

    result = ""
    key_index = 0

    for char in text:
        if char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            decrypted = (ord(char) - base - shift) % 26
            result += chr(decrypted + base)
            key_index += 1
        else:
            result += char

    return result


# 7. CHINESE REMAINDER THEOREM

def crt(remainders, moduli):
    if len(remainders) != len(moduli) or not moduli:
        raise ValueError("Invalid CRT input.")

    product = 1

    for modulus in moduli:
        product *= modulus

    result = 0

    for remainder, modulus in zip(remainders, moduli):
        partial_product = product // modulus

        inverse = modular_inverse(
            partial_product % modulus,
            modulus
        )

        if inverse is None:
            raise ValueError("CRT requires pairwise coprime moduli.")

        result += remainder * partial_product * inverse

    return result % product


# 8. AES-CBC ENCRYPTION AND DECRYPTION

def aes_encrypt(plaintext, key):
    iv = get_random_bytes(AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    ciphertext = cipher.encrypt(
        pad(plaintext.encode(), AES.block_size)
    )

    return iv, ciphertext


def aes_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return plaintext.decode()


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print("=" * 70)
    print("EXPERIMENT 12B: DESIGN AND ANALYSIS OF A SECURE ENCRYPTION SCHEME")
    print("=" * 70)

    plaintext = "HELLO WORLD"

    # CAESAR CIPHER

    shift = 3

    caesar_ciphertext = caesar_encrypt(plaintext, shift)
    caesar_decrypted = caesar_decrypt(caesar_ciphertext, shift)

    print("\n1. CAESAR CIPHER")
    print("Plaintext :", plaintext)
    print("Key       :", shift)
    print("Ciphertext:", caesar_ciphertext)
    print("Decrypted :", caesar_decrypted)

    # EUCLIDEAN ALGORITHM

    print("\n2. EUCLIDEAN ALGORITHM")

    a, b = 35, 26
    gcd_result = euclidean_gcd(a, b)

    print(f"GCD({a}, {b}) = {gcd_result}")

    # MODULAR INVERSE AND AFFINE CIPHER

    print("\n3. MODULAR INVERSE AND AFFINE CIPHER")

    a, b = 5, 8

    inverse = modular_inverse(a, 26)

    print(f"GCD({a}, 26) =", gcd(a, 26))
    print(f"Multiplicative inverse of {a} modulo 26 =", inverse)

    affine_ciphertext = affine_encrypt(plaintext, a, b)
    affine_decrypted = affine_decrypt(affine_ciphertext, a, b)

    print("Plaintext :", plaintext)
    print("Keys      :", a, b)
    print("Ciphertext:", affine_ciphertext)
    print("Decrypted :", affine_decrypted)

    # VIGENERE CIPHER

    print("\n4. VIGENERE CIPHER")

    vigenere_key = "KEY"

    vigenere_ciphertext = vigenere_encrypt(plaintext, vigenere_key)
    vigenere_decrypted = vigenere_decrypt(
        vigenere_ciphertext,
        vigenere_key
    )

    print("Plaintext :", plaintext)
    print("Key       :", vigenere_key)
    print("Ciphertext:", vigenere_ciphertext)
    print("Decrypted :", vigenere_decrypted)

    # CONGRUENCE RELATION

    print("\n5. CONGRUENCE RELATION")

    x, y, m = 29, 3, 26

    print(f"{x} mod {m} =", x % m)

    congruence_verified = (x - y) % m == 0

    if congruence_verified:
        print(f"{x} is congruent to {y} modulo {m}")
    else:
        print("Congruence relation not verified.")

    # FERMAT'S LITTLE THEOREM

    print("\n6. FERMAT'S LITTLE THEOREM")

    a, p = 3, 7

    fermat_result = pow(a, p - 1, p)

    print(f"{a}^({p}-1) mod {p} =", fermat_result)

    if fermat_result == 1:
        print("Fermat's Little Theorem verified.")

    # CHINESE REMAINDER THEOREM

    print("\n7. CHINESE REMAINDER THEOREM")

    remainders = [2, 3, 2]
    moduli = [3, 5, 7]

    crt_result = crt(remainders, moduli)

    print("Given equations:")
    print("x = 2 (mod 3)")
    print("x = 3 (mod 5)")
    print("x = 2 (mod 7)")

    print("\nCRT Solution: x =", crt_result)

    print("\nVerification:")

    for r, m in zip(remainders, moduli):
        print(f"x mod {m} = {crt_result % m}")

    # AES-CBC

    print("\n8. AES-CBC")

    # Fixed key for educational demonstration only.
    aes_key = b"0123456789ABCDEF"

    aes_iv, aes_ciphertext = aes_encrypt(
        plaintext,
        aes_key
    )

    aes_decrypted = aes_decrypt(
        aes_iv,
        aes_ciphertext,
        aes_key
    )

    print("Plaintext :", plaintext)
    print("IV        :", aes_iv.hex())
    print("Ciphertext:", aes_ciphertext.hex())
    print("Decrypted :", aes_decrypted)

    # FINAL VERIFICATION

    print("\n" + "=" * 70)
    print("FINAL VERIFICATION")
    print("=" * 70)

    tests = [
        ("Caesar Cipher", caesar_decrypted == plaintext),
        ("Euclidean Algorithm", gcd_result == 1),
        ("Modular Inverse", inverse == 21),
        ("Affine Cipher", affine_decrypted == plaintext),
        ("Vigenere Cipher", vigenere_decrypted == plaintext),
        ("Congruence", congruence_verified),
        ("Fermat's Theorem", fermat_result == 1),
        ("CRT", crt_result == 23),
        ("AES-CBC", aes_decrypted == plaintext)
    ]

    all_passed = True

    for test_name, result in tests:
        if result:
            print(f"{test_name}: PASS")
        else:
            print(f"{test_name}: FAIL")
            all_passed = False

    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)

    if all_passed:
        print("All cryptographic and mathematical tests completed successfully.")
    else:
        print("Some verification tests failed.")


if __name__ == "__main__":
    main()
