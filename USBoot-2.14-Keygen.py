#!/usr/bin/env python3
import binascii
import random
import copy
import argparse

CHALLENGE_XOR_KEY = bytearray([0x00, 0x5A, 0x6B, 0x7C, 0x5A, 0x6B, 0x7C, 0x00])
RESPONSE_XOR_KEY = bytearray([0x00, 0xA5, 0xB6, 0xC7, 0xA5, 0xB6, 0xC7, 0x00])
RESPONSE_MAGIC_KEY = 0x47B2

def mangle(plaintext: bytearray):
    result = copy.deepcopy(plaintext)

    rand = random.randint(0, 0xFF)
    result[0] = rand

    checksum = 0
    for i in range(7):
        checksum ^= result[i]
    result[7] = checksum

    first_byte_val = result[0]
    for i in range(1, 8):
        result[i] ^= first_byte_val
        first_byte_val += 0xB7
        first_byte_val %= 256  # Simulate uint8_t overflow

    last_byte_val = result[7]
    for i in range(7):
        result[i] ^= last_byte_val
        last_byte_val += 0xB7
        last_byte_val %= 256  

    for i in range(6, -1, -1):  # 6 ~ 0
        result[i] ^= result[i + 1]

    return result


def demangle(ciphertext: bytearray):
    result = copy.deepcopy(ciphertext)

    for i in range(7):
        result[i] ^= result[i + 1]

    last_byte_val = result[7]
    for i in range(7):
        result[i] ^= last_byte_val
        last_byte_val += 0xB7
        last_byte_val %= 256  # Simulate uint8_t overflow

    first_byte_val = result[0]
    for i in range(1, 8):
        result[i] ^= first_byte_val
        first_byte_val += 0xB7
        first_byte_val %= 256

    checksum = 0
    for i in range(7):
        checksum ^= result[i]
    success = result[7] == checksum
    if not success:
        raise AssertionError('Checksum validation failed')

    result[7] = 0
    result[0] = 0

    return result


def xor(src_a: bytearray, src_b: bytearray):
    if len(src_a) != len(src_b):
        raise AssertionError('Data being XOR\'d has different length')
    result = bytearray()
    for i in range(min(len(src_a), len(src_b))):
        result.append(src_a[i] ^ src_b[i])
    return result


def get_response_code(challenge: bytearray):
    response = bytearray([0x00] * 8)
    reg_time = xor(demangle(challenge), CHALLENGE_XOR_KEY)
    response = xor(response, reg_time)
    response = xor(response, bytearray((RESPONSE_MAGIC_KEY << 8).to_bytes(8, 'big')))
    response = xor(response, RESPONSE_XOR_KEY)
    response = mangle(response)
    return response


def main():
    parser = argparse.ArgumentParser(description='USBoot 2.14 Keygen', epilog='Brought to you with ❤️ by shezik')
    parser.add_argument('challengeCode', type=str, help='The code that USBoot prompts you to paste onto the website.')
    args = parser.parse_args()

    if len(args.challengeCode) != 16:
        print(f'Bad challenge code: Expected 16 characters, got {len(args.challengeCode)} instead')
        return

    try:
        challenge = bytearray(binascii.a2b_hex(args.challengeCode))
    except binascii.Error as e:
        print(f'Bad challenge code: {e}; are you sure this is a hex string?')
        return

    try:
        response = binascii.hexlify(get_response_code(challenge))
        print('Response code: ' + response.decode('ascii').upper())
    except AssertionError as e:
        print(f'Bad challenge code: {e}')
        return


if __name__ == '__main__':
    main()
