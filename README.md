# CMSC 687 S-DES project
By Alex Lloyd \<<alloyd2@umbc.edu>\>

What to turn in:

1. **The commented code for your implementation of S-DES:** SEE LINES 85-330. Functions include:
     - `def DES(I, K, rev)` Core S-DES implementation (using `EC()`)
     - `def DDES(I, K1, K2, rev)` DS-DES implementation (using `EC()`)
     - `def EC(input, key, it, rev)` Encyphering computation (feistel structure)
     - `def CFF(R, K)` Cipher Function *f*
     - `def keySchedule(key, it)` ipso facto
     - `def circularShiftLeft(bits, it)` ipso facto
     - `def sbox(bits, table)` Reusable selection function for S<sub>1</sub> & S<sub>2</sub>
     - `def mergeBits(sin, dex)` Put left & right bit halves back together into one BitArray
     - `def splitBits(bits)` Inverse above
     - `def permute(input, table)` Highly reusable permutation & expansion function
2. **The key used to produce the ciphertext in the known plaintext/ciphertext pairs:**
     1. `KEY1==746 (0b1011101010)`
     2. `KEY2==513 (0b1000000001)`
3. **The code you used to implement your Meet in the Middle attack, along with the time your attack took to determine the key.**
     1. SEE LINES 422-471, `def mitm()`
     2. 26.226231 seconds
4. **The code for your brute force key search, along with the time it takes to uncover the key.**
     1. SEE LINES 473-512, `def bf()`
     2. 8510.642018 seconds, i.e. 2 hours, 21 minutes, & 50.642018 seconds
5. **The decryption of the text encrypted using CBC mode with the key you discovered and the code you used to decrypt it.**
     1. Decryption: "If you can read this, you successfully decrypted this message. Congratulations!"
     2. SEE LINES 514-537, `def CBCDecrypt(input, key1, key2, IV)`
6. **A list of the S-DES weak keys.**
     1. Bin: `0b0000000000`, Dec: 0
     2. Bin: `0b0100111010`, Dec: 314
     3. Bin: `0b1011000101`, Dec: 709
     4. Bin: `0b1111111111`, Dec: 1023

All this can be re-calculated by running `python3 sdes.py`

**Note:** Brute Force is disabled by default as it takes ~2 hours. This can be re-enabled in `__main__`. CMD+F/CTRL+F "Make me True!".
