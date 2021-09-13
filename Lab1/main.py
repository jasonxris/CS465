from constants import RconArray, Sbox, InvSbox
import numpy as np

# Cipher key K is 128, 192, or 256 bits
# 128 bits, key length = 4, block = 4, rounds = 10
# 192 bits, key length = 6, block = 4, rounds = 12
# 256 bits, key length = 8, block = 4, rounds = 14

NkOptions = {
    16: 4,
    24: 6,
    32: 8,
}

NrOptions = {
    16: 10,
    24: 12,
    32: 14,
}


class AES:
    def __init__(self, key=1, Nk=4, Nr=10):
        self.key = key
        self.state = []
        self.Nk = Nk
        self.Nr = Nr

    def ffAdd(self, x, y):
        # Xor then remove any extra bits
        return (x ^ y) & 0xFF

    def xtime(self, x):
        # Shift left 1
        x = x << 1
        # If the last value is 1 then xor it with 11b
        if (x & 0x100):
            x = x ^ 0x11b
        # Return the value
        return x

    def ffMultiply(self, x, y):
        result = 0
        count = 0x01
        current = x
        for i in range(8):
            if (y & count):
                result = result ^ current
            # increment current xtime lcoation
            # increment count
            current = self.xtime(current)
            count = count << 1
        return result

    def keyExpansion(self, key):
        # result should just be the key separated into words
        result = self.hexToWordArray(key, self.Nk)
        numberOfLoops = ((self.Nr +1)*4)
        numberOfWordsInKey = self.Nk

        #  first 4 words are already created, start there
        for i in range(4,numberOfLoops):
            # Get the last created word
            lastWord = result[-1]
            # If this is a new roundKey then perform the following operations
            if (i % numberOfWordsInKey) == 0:
                #  Cylic permutation
                lastWord = self.rotWord(lastWord)
                #  apply S-box to wrod
                lastWord = self.subWord(lastWord)
                rcon = RconArray[i // numberOfWordsInKey]
                lastWord = lastWord ^ rcon
            elif ((i % numberOfWordsInKey) == 4) and (numberOfWordsInKey > 6):
                lastWord = self.subWord(lastWord)
            result.append(result[i - numberOfWordsInKey] ^ lastWord)
        return result

    def hexToWordArray(self, hexValue, numberOfWords):
        result = []
        stringHex = str(hex(hexValue))[2:]
        for i in range(numberOfWords):
            hexString = stringHex[(i * 8):(i * 8) + 8]
            result.append(int(hexString, 16))
        return result

    def subWord(self, word):
        wordArray = [(word & 0xFF000000) >> 24, (word & 0xFF0000) >> 16, (word & 0xFF00) >> 8, word & 0xFF]
        b = 0
        for byte in wordArray:
            x = (byte & 0xF0) >> 4
            y = byte & 0xF
            b = (b << 8) + Sbox[x][y]
        return b

    def rotWord(self, word):
        # Shfit word 8 bits to left and remove extra values
        result = (word << 8) & 0xFFFFFFFF
        # add a1 to the end
        a0 = ((word >> 24) & 0xFF)
        result = result | a0
        return result

    def subBytes(self, state):
        # substitutes each byte in the state with the value in S-box
        result = [[], [], [], []]
        for x in range(4):
            for y in range(4):
                z = (state[x][y] & 0xF0) >> 4
                w = state[x][y] & 0xF
                result[x].append(Sbox[z][w])
        return result

    def shiftRows(self, state):
        result = [[], [], [], []]
        for i in range(4):
            result[i] = self.shift(state[i], i)
        return result

    def shift(self, l, n):
        return l[n:] + l[:n]

    # FIX THISdwa
    def mixColumns(self, state):
        result = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        for col in range(4):
            result[0][col] = self.ffAdd(
                self.ffAdd(self.ffAdd(self.ffMultiply(0x02, state[0][col]), self.ffMultiply(0x03, state[1][col])),
                           state[2][col]), state[3][col])
            result[1][col] = self.ffAdd(self.ffAdd(self.ffAdd(state[0][col], self.ffMultiply(0x02, state[1][col])),
                                                   self.ffMultiply(0x03, state[2][col])), state[3][col])
            result[2][col] = self.ffAdd(
                self.ffAdd(self.ffAdd(state[0][col], state[1][col]), self.ffMultiply(0x02, state[2][col])),
                self.ffMultiply(0x03, state[3][col]))
            result[3][col] = self.ffAdd(
                self.ffAdd(self.ffAdd(self.ffMultiply(0x03, state[0][col]), state[1][col]), state[2][col]),
                self.ffMultiply(0x02, state[3][col]))
        return result

    def addRoundKey(self, keyExpansion, state, round):
        result = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        key = keyExpansion[round * 4:(round * 4 + 4)]
        newKey = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        for i in range(4):
            for j in range(4):
                desiredHexValue = str(hex(key[i]))[(j * 2) + 2:(j * 2) + 4]
                desiredHexValue = "0x" + desiredHexValue
                newKey[j][i] = int(desiredHexValue, 16)

        for x in range(4):
            for y in range(4):
                result[x][y] = self.ffAdd(state[x][y], newKey[x][y])
        return result

    def expansionToArray(self, expansionRaw):
        key = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        for x in range(4):
            for y in range(4):
                key[x][y] = expansionRaw[x][y]

    def invSubBytes(self):
        # subs. each bytes in the stat with its corresponding value fromt h inverse s-box
        return None

    def invShiftRows(self):
        # inverse of shiftRows
        return None

    def invMixColumns(self):
        # inverse of mixColumns
        return None

    def cipher(self, plainText):

        print("key expansion")
        # ( specified in 5.1)
        # example in Appendix B
        #  1 input is copied to the state array ( 3.4)
        #  state array is transformed usng round function x times
        #  final round differs slightly form first one
        # final state is copied to output ( 3.4 )
        return plainText

    def invCipher(self, encryptedMessage):
        #  specified in 5.3 - reversed cipher function
        return encryptedMessage


if __name__ == '__main__':
    bit_128 = 0x2b7e151628aed2a6abf7158809cf4f3c

    bit_128_AES = AES(bit_128)
    # MessageToDecrypt = bytearray.fromhex("63233344ca29d4e2903d0c86f3a81e1a")
    # MessageToEncrypt = bytearray.fromhex("45d346ee7e91ba31666fe111c6ace1f0")
    MessageToDecrypt = 0x63233344ca29d4e2903d0c86f3a81e1a
    MessageToEncrypt = 0x00112233445566778899aabbccddeeff
    # plainTextMessage = bit_128_AES.invCipher(MessageToDecrypt)
    encryptedMessage = bit_128_AES.cipher(MessageToEncrypt)
    print("PLAINTEXT: ")
    print("KEY")
    print("CIPHER")

    # Rounds output

    print("INVERSE CIPHER ")
    # Rounds output
