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
        # Key is retrieved from the objects state ( key )
        result = []
        print(self.key)
        test = np.array(self.key)
        print("test: ", test)
        for i in range(self.Nk):
            # result.append(test[i*4:(i*4 +4)])
            result.append((key >> (32 * (self.Nk - i - 1))) & 0xFFFFFFFF)
        # for i in result:
        #     print(hex(i))
        for i in range(self.Nk, 4 * (self.Nr + 1)):
            temp = result[i - 1]
            if (i % self.Nk) == 0:
                temp = self.rotWord(temp)
                temp = self.subWord(temp)
                rcon = RconArray[i // self.Nk]
                temp = temp ^ rcon
            elif (self.Nk > 6) and ((i % self.Nk) == 4):
                temp = self.subWord(temp)
            result.append(result[i - self.Nk] ^ temp)

        return result

    def wordToArray(self, word):
        wordArray = [(word & 0xFF000000) >> 24, (word & 0xFF0000) >> 16, (word & 0xFF00) >> 8, word & 0xFF]
        return wordArray

    def subWord(self, word):
        wordArray = self.wordToArray(word)
        b = 0
        for byte in wordArray:
            b = (b << 8) + self.subByte(byte)
        return b

    def subByte(self, word):
        x = (word & 0xF0) >> 4
        y = word & 0xF
        return Sbox[x][y]

    def rotWord(self, word):
        # Performs a cyclic permutation on its input word
        newWord = (word << 8) & 0xFFFFFFFF
        newWord = newWord | ((word >> 24) & 0xFF)
        return newWord

    def subBytes(self, state):
        # substitutes each byte in the state with the value in S-box
        result = [[], [], [], []]
        for x in range(4):
            for y in range(4):
                result[x].append(self.subByte(state[x][y]))
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
    # bit_256 = bytearray.fromhex("29c11ac6ade7a2826a958bad3bee007f1c33daa1dcafcaa0881a9b1f150ebe69")
    # bit_192 = bytearray.fromhex("29c11ac6ade7a2826a958bad3bee007f1c33daa1dcafcaa0")
    # bit_128 = bytearray.fromhex("29c11ac6ade7a2826a958bad3bee007f")
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
