"""
    @file   sdes.py
    @author Alex Lloyd <alloyd2@umbc.edu>
    @date   02/24/23
    @notes  
        XOR:     a.__xor__(b) returns c = a XOR b
        XOR:     a ^ b returns c = a XOR b

        KEY SCHEDULE
        PC1:     permute(key, PERMUTED_CHOICE_1)
        C0D0:    C0, D0 = splitBits(PC1)
        Cn:      circularShiftLeft(Cm, 1/2)
        Dn:      circularShiftLeft(Dm, 1/2)
        CnDn:    mergeBits(Cn, Dn)
        Kn:      permute(CnDn, PERMUTED_CHOICE_2)

        CIPHER FUNCTION F
        E(R):    permute(R, EXPANSION_TABLE)
        S1I,
        S2I:     splitBits(E(R) ^ Kn)
        S1O:     sbox(S1I, S1_TABLE)
        S2O:     sbox(S2I, S2_TABLE)
        P(S1S2): permute(mergeBits(S1O, S2O), LITTLE_PERMUTATION)
"""

from bitstring import BitArray # Everywhere
from collections import deque  # 1. circularShiftLeft()
import codecs                  # 5. convert encrypted text from ASCII
import time                    # 3./4. Time mitm() & bf()

# Tables of permutation/substitution
INITIAL_PERMUTATION = [2,6,3,1,4,8,5,7]
INVERSE_PERMUTATION = [4,1,3,5,7,2,8,6]
EXPANSION_TABLE     = [4,1,2,3,2,3,4,1]
LITTLE_PERMUTATION  = [2,4,3,1]
S1_TABLE            = [ [1,0,3,2],
                        [3,2,1,0],
                        [0,2,1,3],
                        [3,1,3,2] ]
S2_TABLE            = [ [0,1,2,3],
                        [2,0,1,3],
                        [3,0,1,0],
                        [2,1,0,3] ]
PERMUTED_CHOICE_1   = [9,7,2,5,6, 1,4,10,8,3]
PERMUTED_CHOICE_2   = [2,7,8,10,1,9,3,4]

# Known Answer Tests
VARIABLE_PLAINTEXT  = [ [BitArray('0b10000000'), BitArray('0b10101000')],
                        [BitArray('0b01000000'), BitArray('0b10111110')],
                        [BitArray('0b00100000'), BitArray('0b00010110')],
                        [BitArray('0b00010000'), BitArray('0b01001010')],
                        [BitArray('0b00001000'), BitArray('0b01001001')],
                        [BitArray('0b00000100'), BitArray('0b01001110')],
                        [BitArray('0b00000010'), BitArray('0b00010101')],
                        [BitArray('0b00000001'), BitArray('0b01101000')] ]
VARIABLE_KEY        = [ [BitArray('0b1000000000'), BitArray('0b11100110')],
                        [BitArray('0b0100000000'), BitArray('0b00010110')],
                        [BitArray('0b0010000000'), BitArray('0b00111011')],
                        [BitArray('0b0001000000'), BitArray('0b01010011')],
                        [BitArray('0b0000100000'), BitArray('0b01001110')],
                        [BitArray('0b0000010000'), BitArray('0b10001011')],
                        [BitArray('0b0000001000'), BitArray('0b01010110')],
                        [BitArray('0b0000000100'), BitArray('0b11010111')],
                        [BitArray('0b0000000010'), BitArray('0b11100001')],
                        [BitArray('0b0000000001'), BitArray('0b10000000')] ]
PERMUTATION_OP      = [ [BitArray('0b0000100100'), BitArray('0b00110000')],
                        [BitArray('0b0010000100'), BitArray('0b11110010')],
                        [BitArray('0b0000000000'), BitArray('0b10101011')],
                        [BitArray('0b0000000101'), BitArray('0b10111011')] ]
SUBSTITUTION_TABLE  = [ [BitArray('0b0000000000'), BitArray('0b10101011')],
                        [BitArray('0b0000011001'), BitArray('0b01000011')],
                        [BitArray('0b0001100111'), BitArray('0b00101100')],
                        [BitArray('0b0001111101'), BitArray('0b01010110')],
                        [BitArray('0b0001111110'), BitArray('0b00100001')],
                        [BitArray('0b0010100111'), BitArray('0b00111101')],
                        [BitArray('0b0100001000'), BitArray('0b10011101')] ]

# Other
PT_CT_PAIRS         = [ [BitArray('0x42'), BitArray('0x11')],
                        [BitArray('0x72'), BitArray('0x6d')],
                        [BitArray('0x75'), BitArray('0xfa')],
                        [BitArray('0x74'), BitArray('0xa9')],
                        [BitArray('0x65'), BitArray('0x34')] ]

# P(S1S2) := permute(input, LITTLE_PERMUTATION)
# E(R)    := permute(input, EXPANSION_TABLE)
# IP()    := permute(input, INITIAL_PERMUTATION)
# IP-1()  := permute(input, INVERSE_PERMUTATION)
# PC-1()  := permute(input, PERMUTED_CHOICE_1)
# PC-2()  := permute(input, PERMUTED_CHOICE_2)
# input:  BitArray to expand or permute
# table:  Table of permuted values
# return: len(table)-bit permuted or expanded result
def permute(input, table):
    output = BitArray(len(table))
    j = 0

    for i in table:
        output[j] = input[i - 1]
        j += 1
    
    return output

# bits:   (even)-bit BitArray
# return: left split, right split
def splitBits(bits):
    len  = bits.length
    half = len // 2
    sin  = bits[0:half]
    dex  = bits[half:len]

    return sin, dex

# sin:    left bits
# dex:    right bits
# return: Merged BitArray
def mergeBits(sin, dex):
    # Deep copy to avoid affecting other results
    result = sin.copy()

    # Perform merge
    result.append(dex)

    return result

# bits:   4-bit BitArray
# table:  sbox table
# return: 2-bit sbox result
def sbox(bits, table):
    i     = j = 0
    i_bits    = BitArray(2)
    j_bits    = BitArray(2)

    # First & last bit of input for the ith row
    i_bits[0] = bits[0]
    i_bits[1] = bits[3]
    i         = i_bits.uint
    
    # Second & third bit of input for the jth column
    j_bits[0] = bits[1]
    j_bits[1] = bits[2]
    j         = j_bits.uint

    # After converting i & j to ints,
    # look them up in the table & return
    # them as a two-bit BitArray
    return BitArray(uint=table[i][j], length=2)

# bits:   BitArray to be left-shifted
# it:     Iterations to shift-left by
# return: Left-shifted BitArray
def circularShiftLeft(bits, it):
    it      = it % bits.length
    shifted = deque()
    pos     = 0

    # Preserve bits that'll be shifted out
    for i in range(0, it):
        shifted.append(bits[i])

    # Perform left shift it times
    bits <<= it

    # Re-insert bits at the right
    for i in range(0, it):
        pos       = bits.length - 1 - i
        bits[pos] = shifted.pop()
    
    return bits

"""
        KEY SCHEDULE
        PC1:  permute(key, PERMUTED_CHOICE_1)
        C0D0: C0, D0 = splitBits(PC1)
        Cn:   circularShiftLeft(Cm, 1/2)
        Dn:   circularShiftLeft(Dm, 1/2)
        CnDn: mergeBits(Cn, Dn)
        Kn:   permute(CnDn, PERMUTED_CHOICE_2)
"""
# key:    10-bit primary key
# it:     # of round-keys to return [positive int > 0]
# return: List of round-keys
def keySchedule(key, it):
    # Vars
    keys   = []
    CnDn   = BitArray()
    Cn, Dn = BitArray(), BitArray()

    # Sanity check
    if it < 1:
        raise Exception("Must return at least 1 round-key")

    # Get permuted choice 1
    CnDn = permute(key, PERMUTED_CHOICE_1)

    # Split
    Cn, Dn = splitBits(CnDn)

    # Left shift by 1
    Cn = circularShiftLeft(Cn, 1)
    Dn = circularShiftLeft(Dn, 1)

    for i in range(0, it):
        # Add Kn
        CnDn = mergeBits(Cn, Dn)
        keys.append(permute(CnDn, PERMUTED_CHOICE_2))

        # Left shift by 2 for next Kn, if needed
        Cn = circularShiftLeft(Cn, 2)
        Dn = circularShiftLeft(Dn, 2)
    
    return keys

"""
    CIPHER FUNCTION F
    E(R):    permute(R, EXPANSION_TABLE)
    S1I,
    S2I:     splitBits(E(R) ^ Kn)
    S1O:     sbox(S1I, S1_TABLE)
    S2O:     sbox(S2I, S2_TABLE)
    P(S1S2): permute(mergeBits(S1O, S2O), LITTLE_PERMUTATION)
"""
# R:      Rn for this round (4 bits)
# K:      Kn for this round (8 bits)
# return: f(Rn,Kn+1)
def CFF(R, K):
    # Vars
    ER     = BitArray() # E(R)
    B1B2   = BitArray() # K XOR E(R)
    B1, B2 = BitArray(), BitArray()
    S1     = BitArray() # S1(B1) = sbox(B1, S1_TABLE)
    S1     = BitArray() # S2(B2) = sbox(B2, S2_TABLE)
    S1S2   = BitArray() # S1(B1)S2(B2)
    P      = BitArray() # P(S1(B1)S2(B2))

    # E(R) [len=8]
    ER = permute(R, EXPANSION_TABLE)

    # K XOR E(R) [len=8]
    B1B2 = K ^ ER

    # B1 B2 [len=4]
    B1, B2 = splitBits(B1B2)

    # S1(B1), S2(B2) [len=2]
    S1 = sbox(B1, S1_TABLE)
    S2 = sbox(B2, S2_TABLE)

    # S1(B1)S2(B2) [len=4]
    S1S2 = mergeBits(S1, S2)

    # P(S1(B1)S2(B2))
    P = permute(S1S2, LITTLE_PERMUTATION)

    return P

# Encyphering computation
# input:  Plaintext as BitArray
# it:     Rounds to iterate through 
# key:    10-bit primary key
# rev:    Boolean, if true, reverse round key order
# return: Enciphered/deciphered result
def EC(input, key, it, rev):
    # Vars
    LR     = BitArray() # Initial permutation
    Lm, Rm = BitArray(), BitArray() # Split into L & R
    Ln     = BitArray() # Next L
    Rn     = BitArray() # Next R
    keys   = []         # Round keys
    preout = BitArray() # Pre-output

    # Sanity check
    if it < 1:
        raise Exception("Must perform at least 1 round")
    
    # Get round-keys
    keys = keySchedule(key, it)

    # Initial permutation
    LR = permute(input, INITIAL_PERMUTATION)

    # Split into L & R
    Lm, Rm = splitBits(LR)

    # Rounds
    for i in range(0, it):
        # Reverse order if flagged
        j = i
        if rev:
            j = it - 1 - i

        # Perform the round
        Ln = Rm.copy()
        Rn = CFF(Rm, keys[j]) ^ Lm
        Lm = Ln.copy()
        Rm = Rn.copy()

    # Pre-output: RnLn
    preout = mergeBits(Rn, Ln)

    return permute(preout, INVERSE_PERMUTATION)

# Double (S) DES [4-rounds]
# I:      8-bit plaintext or ciphertext BitArray
# K1:     First key
# K2:     Second key
# rev:    If true, use DK1(DK2(I)) instead of EK2(EK1(I))
# return: O
def DDES(I, K1, K2, rev):
    r = 4 # rounds hardcoded

    # Reverse if rev==True [decrypt]
    if rev:
        tmp = K1.copy()
        K1  = K2.copy()
        K2  = tmp.copy()
    
    # Run 2DES
    return EC(EC(I, K1, r, rev), K2, r, rev)

# Normal (S) DES [4-rounds]
# I:      8-bit plaintext or ciphertext BitArray
# K:      Key [10-bit BitArray]
# rev:    If true, reverse round-key order
# return: O
def DES(I, K, rev):
    r = 4 # rounds hardcoded
    
    # Run DES
    return EC(I, K, r, rev)

# Variable Plaintext Known Answer Test
def varPT():
    key = BitArray('0b0000000000')
    msg = "FAILED"

    print("\nVariable Plaintext Known Answer Test")

    for i in range(0, len(VARIABLE_PLAINTEXT)):
        pt = VARIABLE_PLAINTEXT[i][0]
        ct = DES(pt, key, False)

        if ct.bin == VARIABLE_PLAINTEXT[i][1].bin:
            msg = "PASSED"

        print("Round {}: {} == {} {}".format(
            i, ct.bin, VARIABLE_PLAINTEXT[i][1].bin, msg
        ))

# Variable Ciphertext Known Answer Test
def varCT():
    key = BitArray('0b0000000000')
    msg = "FAILED"

    print("\nVariable Ciphertext Known Answer Test")

    for i in range(0, len(VARIABLE_PLAINTEXT)):
        ct = VARIABLE_PLAINTEXT[i][1]
        pt = DES(ct, key, True)

        if pt.bin == VARIABLE_PLAINTEXT[i][0].bin:
            msg = "PASSED"

        print("Round {}: {} == {} {}".format(
            i, pt.bin, VARIABLE_PLAINTEXT[i][0].bin, msg
        ))

# Variable Key Known Answer Test
def varK():
    pt  = BitArray('0b00000000')
    msg = "FAILED"

    print("\nVariable Key Known Answer Test")

    for i in range(0, len(VARIABLE_KEY)):
        key = VARIABLE_KEY[i][0]
        ct  = DES(pt, key, False)

        if ct.bin == VARIABLE_KEY[i][1].bin:
            msg = "PASSED"

        print("Round {}: {} == {} {}".format(
            i, ct.bin, VARIABLE_KEY[i][1].bin, msg
        ))

# Permutation Operation Known Answer Test
def permOp():
    pt  = BitArray('0b00000000')
    msg = "FAILED"

    print("\nPermutation Operation Known Answer Test")

    for i in range(0, len(PERMUTATION_OP)):
        key = PERMUTATION_OP[i][0]
        ct  = DES(pt, key, False)

        if ct.bin == PERMUTATION_OP[i][1].bin:
            msg = "PASSED"

        print("Round {}: {} == {} {}".format(
            i, ct.bin, PERMUTATION_OP[i][1].bin, msg
        ))

# Substitution Table Known Answer Test
def subTable():
    pt  = BitArray('0b00000000')
    msg = "FAILED"

    print("\nSubstitution Table Known Answer Test")

    for i in range(0, len(SUBSTITUTION_TABLE)):
        key = SUBSTITUTION_TABLE[i][0]
        ct  = DES(pt, key, False)

        if ct.bin == SUBSTITUTION_TABLE[i][1].bin:
            msg = "PASSED"

        print("Round {}: {} == {} {}".format(
            i, ct.bin, SUBSTITUTION_TABLE[i][1].bin, msg
        ))

"""
    "Encrypt the plaintext with a single DES with every
    possible key to create a table."
    Try the entire 0-1023 keyspace
    Encrypt each plaintext for each try.
    { 0:  [ Ek1,0(pt0), Ek1,0(pt1), Ek1,0(pt2), Ek1,0(pt3), Ek1,0(pt4) ],
      1:  [ Ek1,1(pt0), Ek1,1(pt1), Ek1,1(pt2), Ek1,1(pt3), Ek1,1(pt4) ],
      ...
      n:  [ Ek1,n(pt0), Ek1,n(pt1), Ek1,n(pt2), Ek1,n(pt3), Ek1,n(pt4) ] }
    
    Dictionary key: key1 value
"""
# Meet in the Middle
# return: List of keys if found; otherwise an empty list
def mitm():
    top      = {} # dictionary of encryptions of the given plaintexts for all 1024 keys
    pairs    = range(len(PT_CT_PAIRS))
    keySpace = range(
        BitArray('0b0000000000').uint,
        BitArray('0b1111111111').uint + 1
    )

    # Encrypt plaintext using all 1024 keys
    for i in keySpace:
        # Reset list
        tmp = []

        # encrypt each of the five given plaintexts using the ith key.
        for j in pairs:
            tmp.append(DES(PT_CT_PAIRS[j][0], BitArray(uint=i, length=10), False))            
        
        # Store the five encryptions in the dictionary
        top[i] = tmp

    # Decrypt ciphertext using all 1024 keys
    for i in keySpace:
        # Reset list
        tmp = []

        # decrypt each of the five given ciphertexts using the ith key.
        for j in pairs:
            tmp.append(DES(PT_CT_PAIRS[j][1], BitArray(uint=i, length=10), True))

        # test decryptions against the full dictionary
        # if match found, key1=i & key2=j
        for j in keySpace:
            if tmp == top[j]:
                return [BitArray(uint=j, length=10), BitArray(uint=i, length=10)]
    
    return []

# Brute force
# return: List of keys if found; otherwise an empty list
def bf():
    pt       = [] # Plaintext array to check against
    ct       = [] # Ciphertext array to attempt to decrypt
    pairs    = range(len(PT_CT_PAIRS))
    keySpace = range(
        BitArray('0b1111111111').uint,
        BitArray('0b0000000000').uint - 1,
        -1
    ) # we know key1=746, search for key1 first, downwards from 1023 (for my sanity)

    # Extract pt & ct
    for i in pairs:
        pt.append(PT_CT_PAIRS[i][0])
        ct.append(PT_CT_PAIRS[i][1])

    # Try the full 2^20 bit keyspace, key2 first, counting down from 1023
    # Hypothesis: 1023 - 746 = 277, 277 x 15 seconds ~= 70 minutes. Allow 120 minutes.
    for i in keySpace:
        print(i) # keep this here for progress reports

        for j in keySpace:
            # Reset list
            tmp = []

            # Try to decrypt the 5 ciphertexts
            for k in pairs:
                tmp.append(DDES(
                    ct[k],                       # Try all 5 ciphertexts
                    BitArray(uint=i, length=10), # Key1, try first
                    BitArray(uint=j, length=10), # Key2, try second
                    True                         # Decrypt
                ))

            # See if == to the plaintexts
            if tmp == pt:
                return [BitArray(uint=i, length=10), BitArray(uint=j, length=10)]
    
    return []

# Decrypts cipher-block-chain'd ciphertext
# Takes the hex result & sends out a regular string
# input: BitArray of arbitrary length
# key1:  10-bit BitArray key for first round of encryption
# key2:  10-bit BitArray key for second round of encryption
# IV:    8-bit BitArray initialization vector
def CBCDecrypt(input, key1, key2, IV):
    chain  = input.cut(8)
    rchain = []
    result = BitArray()

    for byte in chain:
        # XOR DDES decryption result with IV (or subsequent)
        rchain.append(DDES(byte, key1, key2, True) ^ IV)

        # Next byte in the stream is the first byte of ciphertext
        IV = byte

    # Reconstruct into one BitArray
    for i in rchain:
        end = result.len
        result.insert(i, end)
    
    return result

# Check if a key is weak
# key:    10-bit BitArray to check
# return: Boolean. If true, key is weak in the strictest sense [not semi-weak].
def isWeak(key):
    w = False                               # isWeak?
    a = BitArray("0b10010101")              # Random prime (149)
    b = DES(DES(a, key, False), key, False) # Encrypt twice
    c = BitArray("0b10110011")              # Random prime (179)
    d = DES(DES(c, key, False), key, False) # Encrypt twice
    e = BitArray("0b11101001")              # Random prime (233)
    f = DES(DES(e, key, False), key, False) # Encrypt twice
    
    # Triple-check to avoid collisions
    if a == b and c == d and e == f:
        w = True
    
    return w

# Find all (strictly) weak keys in the 2^10 keySpace
def showWeak():
    keySpace = range(
        BitArray('0b0000000000').uint,
        BitArray('0b1111111111').uint + 1
    )
    weakList = []
    c        = 1

    for i in keySpace:
        tmp = BitArray(uint=i, length=10)

        if isWeak(tmp):
            weakList.append(tmp)
    
    print("List of S-DES weak keys:")
    for i in weakList:
        print("{}. Bin: {}, Dec: {}".format(c, i.bin, i.uint))
        c += 1
    print()

if __name__ == '__main__':
    """ Welcome """
    print("Welcome to Alex Hunter Lloyd's Meet in the Middle Attack!\n")
    print("Please allow ~60 seconds for computationally intensive functions to finish.\n")
    print("CMD+F/CTRL+F \"Make me True!\" in main() to run Brute Force!\n")
    print("----------\n")

    """ 1. Known Answer Tests """
    print("1. Known Answer Tests showing S-DES implementation!")
    varPT()
    varCT()
    varK()
    permOp()
    subTable()
    print("\n----------\n")

    """ 2. Key Proof """
    # Keys n vars
    key1 = BitArray(uint=746, length=10)
    key2 = BitArray(uint=513, length=10)
    pt, ct, testPT, testCT = [], [], [], []

    # Extract pt & ct
    for i in range(len(PT_CT_PAIRS)):
        pt.append(PT_CT_PAIRS[i][0])
        ct.append(PT_CT_PAIRS[i][1])

    # Decrypt & Encrypt with the keys
    for i in range(len(PT_CT_PAIRS)):
        testPT.append(DDES(ct[i], key1, key2, True))  # Decrypt
        testCT.append(DDES(pt[i], key1, key2, False)) # Encrypt

    if pt == testPT and ct == testCT:
        print("2. Key Proof: Keys confirmed to work! Key1: {}, Key2: {}\n".format(key1.uint, key2.uint))
    else:
        print("2. Key Proof: Keys NOT proven!\n")
    
    print("----------\n")

    """ 3. Get key with Meet in the Middle """
    print("3. Please wait for Meet in the Middle results!\n")
    startM = time.process_time()
    keysM  = mitm()
    stopM  = time.process_time() - startM

    if len(keysM):
        print("Key1: {} {}".format(keysM[0].bin, keysM[0].uint))
        print("Key2: {} {}".format(keysM[1].bin, keysM[1].uint))
    else:
        print(keysM)
    
    print("mitm() elapsed time in seconds: {}\n".format(stopM))
    print("----------\n")

    """ 5. Decrypt Message """
    I    = BitArray('0x7327313cf64670395a16ba52fca025a7e787f23277d1cbd70879359bcce1b08a269bf29d7b8fe109c81ec8ef9cf8a025a7e787f232bcda51b4888e8eceb7b27bd67f99cee11406638f744ea1cf4a12')
    key1 = BitArray(uint=746, length=10)
    key2 = BitArray(uint=513, length=10)
    IV   = BitArray('0x6a')
    msg  = CBCDecrypt(I, key1, key2, IV)

    print("5. Message: \"{}\"\n".format(codecs.decode(msg.hex, 'hex').decode('ASCII')))
    print("----------\n")

    """ 6. A list of the S-DES weak keys. """
    print("6. Please wait for weak keys!\n")
    showWeak()
    print("----------\n")

    """ 4. Get key with Brute Force """
    BF  = False # Make me True!
    if BF:
        print("4. Please wait ~2 hours for Brute Force results!\n")
        startB = time.process_time()
        keysB  = bf()
        stopB  = time.process_time() - startB

        if len(keysB):
            print("Key1: {} {}".format(keysB[0].bin, keysB[0].uint))
            print("Key2: {} {}".format(keysB[1].bin, keysB[1].uint))
        else:
            print(keysB)
        
        print("Brute force elapsed time in seconds: {}\n".format(stopB))
        print("----------\n")
    
    print("End! Thanks for coming!")
