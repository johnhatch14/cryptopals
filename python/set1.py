#################
# Set 1
#################

"""
1.1
Instructions: https://cryptopals.com/sets/1/challenges/1
Input: 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
Output: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

>>> hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
"""
import base64

def hex_to_base64(hex: str):
    hex_bytes = bytes.fromhex(hex)
    b64_bytes = base64.b64encode(hex_bytes)
    return str(b64_bytes, encoding='utf-8')

""" 
1.2
Instructions: https://cryptopals.com/sets/1/challenges/2

Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.
If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965

... should produce:

746865206b696420646f6e277420706c6179

>>> fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
'746865206b696420646f6e277420706c6179'
"""

def fixed_xor(hex_a: str, hex_b: str):
    
    if len(hex_a) != len(hex_b):
        raise ValueError('Length of hex strings do not match')

    a_bytes = bytes.fromhex(hex_a)
    b_bytes = bytes.fromhex(hex_b)
    xor_bytes = bytes([a ^ b for a,b in zip(a_bytes, b_bytes)])
    return xor_bytes.hex()

"""
1.3
Instructions: https://cryptopals.com/sets/1/challenges/3

Single-byte XOR cipher

The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.
How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.

>>> brute_single_byte_xor('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
(_, _, b"Cooking MC's like a pound of bacon")
"""

def get_english_score(input_bytes):
    """Returns a score which is the sum of the probabilities in how each letter of the input data
    appears in the English language. Uses the above probabilities.
    Thanks to: https://github.com/ricpacca
    """
    CHARACTER_FREQ = {
        'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
        'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
        'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
        'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
    }
    score = 0

    for byte in input_bytes:
        score += CHARACTER_FREQ.get(chr(byte).lower(), 0)

    return score

def brute_single_byte_xor(ciphertext_hex: str):
    cipher_bytes = bytes.fromhex(ciphertext_hex)
    best_result = (0, '', '')
    for i in range(256):
        key_bytes = bytes([i] * len(cipher_bytes))
        plaintext = bytes.fromhex(fixed_xor(cipher_bytes.hex(), key_bytes.hex()))
        score = get_english_score(plaintext)
        if best_result[0] < score:
            best_result = (score, bytes([i]).hex(), plaintext)
    return best_result

"""
1.4
Instructions: https://cryptopals.com/sets/1/challenges/4

Detect single-character XOR

One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

"""

def detect_single_byte_xor(ciphertext_hexs: list, min_score=750):
    from multiprocessing.dummy import Pool
    from multiprocessing import cpu_count
    pool = Pool(cpu_count())
    results = pool.map(brute_single_byte_xor, ciphertext_hexs)
    pool.close()
    pool.join()
    max_score = min_score
    best_result = None
    for r in results:
        if r[0] > max_score:
            max_score = r[0]
            best_result = r
    return best_result

"""
1.5
Instructions: https://cryptopals.com/sets/1/challenges/5

Implement repeating-key XOR

Here is the opening stanza of an important work of the English language:

`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

`0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`

>>> repeating_key_xor("ICE","Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
"""
def repeating_key_xor(key=None, message=None, hex_output=True):

    if type(key) == bytes:
        key_bytes = key
    elif type(key) == str:
        key_bytes = bytes(key, 'utf-8')
    else:
        raise TypeError("Key must be bytes or str")

    if type(message) == bytes:
        msg_bytes = message
    elif type(message) == str:
        msg_bytes = bytes(message, 'utf-8')
    else:
        raise TypeError("Message must be bytes or str")
    
    key_index = 0
    res_bytes = bytearray()
    for msg_byte in msg_bytes:
        res_bytes.append(key_bytes[key_index] ^ msg_byte)
        key_index = (key_index + 1) % len(key_bytes)
    
    if hex_output:
        return res_bytes.hex()
    else:
        return bytes.fromhex(res_bytes.hex())

"""
1.6
Instructions: https://cryptopals.com/sets/1/challenges/6

Whew... That was tough but fun!

"""

def hamming_distance(a, b):
    if type(a) is str and type(b) is str:
        a_bytes = bytes(a, 'utf-8')
        b_bytes = bytes(b, 'utf-8')
    elif type(a) is bytes and type(b) is bytes:
        a_bytes = a
        b_bytes = b
    else:
        raise TypeError('Inputs must both be str or both be bytes')

    if (len(a_bytes) != len(b_bytes)):
        raise ValueError(str)

    ham_dist = 0
    byte_len = len(a_bytes)
    for i in range(byte_len):
        xor_byte = a_bytes[i] ^ b_bytes[i]
        bits = bin(xor_byte)[2:]
        ham_dist += len([b for b in bits if b is '1'])
    return ham_dist

def break_repeating_key_xor(cipherbytes: bytes = None, maxkeysize: int = 40):

    block_count = 4
    guess_distances = {}
    maxkeysize = min(maxkeysize, int(len(cipherbytes)/block_count))
    print("Guessing key size using hamming distances...")
    for keysize_guess in range(2,maxkeysize + 1):
        #print('Key length guess: ' + str(keysize_guess))

        blocks = [cipherbytes[i:i + keysize_guess] for i in range(0, len(cipherbytes), keysize_guess)][:block_count]
        block_distances = []

        for i in range(block_count):
            for j in range(i+1, block_count):
                hd = hamming_distance(blocks[i], blocks[j])
                block_distances.append(hd)
                #print(blocks[i].hex() + '|' + blocks[j].hex() + '|' + str(hd))

        guess_distances[keysize_guess] = (sum(block_distances) / len(block_distances)) / keysize_guess

    #print(guess_distances)

    best_keysizes = sorted(guess_distances, key=guess_distances.get)[:5]
    message_guesses = []
    for best_keysize in best_keysizes:
        print('Trying best key length: ' + str(best_keysize))

        cipher_blocks = [cipherbytes[i*best_keysize:(i+1)*best_keysize] for i in range(int(len(cipherbytes)/best_keysize))]
        transposed_blocks = [bytes([b[i] for b in cipher_blocks]) for i in range(best_keysize)]

        key = []
        for t_block in transposed_blocks:
            res = brute_single_byte_xor(t_block.hex())
            key.append(str(bytes.fromhex(res[1]), encoding='utf-8'))
        print('Possible key: ' + str(key))

        message_bytes = repeating_key_xor(key=''.join(key), message=str(cipherbytes, encoding='utf-8'), hex_output=False)
        message_guesses.append(message_bytes)
    
    best_message = max(message_guesses, key=lambda k: get_english_score(k))
    return str(best_message, encoding='utf-8')