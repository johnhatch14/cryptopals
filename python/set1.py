
#################
# Utility Classes
#################

# FrequencyFinder
# http://inventwithpython.com/hacking (BSD Licensed)
class FrequencyFinder:

    # frequency taken from http://en.wikipedia.org/wiki/Letter_frequency
    englishLetterFreq = {'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07}
    ETAOIN = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
    LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def getLetterCount(self, message: str):
        # Returns a dictionary with keys of single letters and values of the
        # count of how many times they appear in the message parameter.
        letterCount = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'E': 0, 'F': 0, 'G': 0, 'H': 0, 'I': 0, 'J': 0, 'K': 0, 'L': 0, 'M': 0, 'N': 0, 'O': 0, 'P': 0, 'Q': 0, 'R': 0, 'S': 0, 'T': 0, 'U': 0, 'V': 0, 'W': 0, 'X': 0, 'Y': 0, 'Z': 0}

        for letter in message.upper():
            if letter in self.LETTERS:
                letterCount[letter] += 1

        return letterCount


    def getItemAtIndexZero(self, x):
        return x[0]


    def getFrequencyOrder(self, message: str):
        # Returns a string of the alphabet letters arranged in order of most
        # frequently occurring in the message parameter.

        # first, get a dictionary of each letter and its frequency count
        letterToFreq = self.getLetterCount(message)

        # second, make a dictionary of each frequency count to each letter(s)
        # with that frequency
        freqToLetter = {}
        for letter in self.LETTERS:
            if letterToFreq[letter] not in freqToLetter:
                freqToLetter[letterToFreq[letter]] = [letter]
            else:
                freqToLetter[letterToFreq[letter]].append(letter)

        # third, put each list of letters in reverse "ETAOIN" order, and then
        # convert it to a string
        for freq in freqToLetter:
            freqToLetter[freq].sort(key=self.ETAOIN.find, reverse=True)
            freqToLetter[freq] = ''.join(freqToLetter[freq])

        # fourth, convert the freqToLetter dictionary to a list of tuple
        # pairs (key, value), then sort them
        freqPairs = list(freqToLetter.items())
        freqPairs.sort(key=self.getItemAtIndexZero, reverse=True)

        # fifth, now that the letters are ordered by frequency, extract all
        # the letters for the final string
        freqOrder = []
        for freqPair in freqPairs:
            freqOrder.append(freqPair[1])

        return ''.join(freqOrder)


    def englishFreqMatchScore(self, message: str):
        # Return the number of matches that the string in the message
        # parameter has when its letter frequency is compared to English
        # letter frequency. A "match" is how many of its six most frequent
        # and six least frequent letters is among the six most frequent and
        # six least frequent letters for English.
        freqOrder = self.getFrequencyOrder(message)

        matchScore = 1000

        for i in range(len(freqOrder)):
            letterRankDist = abs(i - self.ETAOIN.index(freqOrder[i]))
            matchScore -= letterRankDist

        """
        # Find how many matches for the six most common letters there are.
        for commonLetter in self.ETAOIN[:6]:
            if commonLetter in freqOrder[:6]:
                matchScore += 1

        # Find how many matches for the six least common letters there are.
        for uncommonLetter in self.ETAOIN[-6:]:
            if uncommonLetter in freqOrder[-6:]:
                matchScore += 1
        """
        
        return matchScore

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
def brute_single_byte_xor(ciphertext_hex: str):
    ff = FrequencyFinder()
    cipher_bytes = bytes.fromhex(ciphertext_hex)
    best_result = (0, '', '')
    for i in range(256):
        key_bytes = bytes([i] * len(cipher_bytes))
        try:
            plaintext = str(bytes.fromhex(fixed_xor(cipher_bytes.hex(), key_bytes.hex())), encoding='utf-8')
        except UnicodeDecodeError:
            continue
        score = ff.englishFreqMatchScore(plaintext)
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