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
    def __init__(self, key="", Nk=4, Nr=10):
        self.key = key
        self.state = []
        self.Nk = Nk
        self.Nr = Nr

    def ffAddition(self, x, y):
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
        numberOfLoops = ((self.Nr + 1) * 4)
        numberOfWordsInKey = self.Nk

        #  first 4 words are already created, start there
        for i in range(numberOfWordsInKey, numberOfLoops):
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

    def hexToWordArray(self, hexValueString, numberOfWords):
        print("hexValueString = ", numberOfWords)
        result = []
        if hexValueString[:2] == "0x":
            hexValueString = str(hex(hexValueString))[2:]
        for i in range(numberOfWords):
            hexString = hexValueString[(i * 8):(i * 8) + 8]
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
            result[i] = state[i][i:] + state[i][:i]
        return result

    # FIX THISdwa
    def mixColumns(self, state):
        result = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        for i in range(4):
            result[0][i] = self.ffAddition(
                self.ffAddition(self.ffAddition(self.ffMultiply(0x02, state[0][i]), self.ffMultiply(0x03, state[1][i])),
                                state[2][i]), state[3][i])
            result[1][i] = self.ffAddition(
                self.ffAddition(self.ffAddition(state[0][i], self.ffMultiply(0x02, state[1][i])),
                                self.ffMultiply(0x03, state[2][i])), state[3][i])
            result[2][i] = self.ffAddition(
                self.ffAddition(self.ffAddition(state[0][i], state[1][i]), self.ffMultiply(0x02, state[2][i])),
                self.ffMultiply(0x03, state[3][i]))
            result[3][i] = self.ffAddition(
                self.ffAddition(self.ffAddition(self.ffMultiply(0x03, state[0][i]), state[1][i]), state[2][i]),
                self.ffMultiply(0x02, state[3][i]))
        return result

    def keyForRound(self, keyExpansion, currentRound):
        key = keyExpansion[currentRound * 4:(currentRound * 4 + 4)]
        newKey = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        # get the correct key from the key expansion for this round
        for i in range(4):
            hexString = str(hex(key[i]))[2:]
            toAdd = 8 - len(hexString)
            for j in range(toAdd):
                hexString = "0" + hexString
            # print(hexString)
            for j in range(4):
                desiredHexValue = hexString[(j * 2):(j * 2) + 2]
                # if i == 3:
                #     print(hexString)
                #     print(desiredHexValue)
                if desiredHexValue != "":
                    desiredHexValue = "0x" + desiredHexValue
                    newKey[j][i] = int(desiredHexValue, 16)
        return newKey

    def addRoundKey(self, keyExpansion, state, currentRound):
        result = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        newKey = self.keyForRound(keyExpansion, currentRound)
        # print(self.key)
        # print(self.arrayToHex(newKey))
        for x in range(4):
            for y in range(4):
                # print("adding ", hex(state[x][y]), " with ", hex(newKey[x][y]))
                # print(("result is ", hex(self.ffAddition(state[x][y], newKey[x][y]))))
                result[x][y] = self.ffAddition(state[x][y], newKey[x][y])
        return result

    def invSubBytes(self):
        # subs. each bytes in the stat with its corresponding value fromt h inverse s-box
        return None

    def invShiftRows(self):
        # inverse of shiftRows
        return None

    def invMixColumns(self):
        # inverse of mixColumns
        return None

    def hexToArray(self,hexValue):
        result = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        counter = 0
        for i in range(4):
            for j in range(4):
                desiredHexValue = hexValue[counter*2:counter*2+2]
                desiredHexValue = "0x" + desiredHexValue
                counter += 1
                result[j][i] = int(desiredHexValue,16)
        return result

    def arrayToHex(self,hexArray):
        result = ""
        for i in range(4):
            for j in range(4):
                hexString = str(hex(hexArray[j][i]))[2:]
                if len(hexString) < 2 :
                    hexString = "0" + hexString
                result += hexString
        return result

    def cipher(self, plainText):
        result = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        w = self.keyExpansion(self.key)
        state = self.hexToArray(plainText)
        print('round[ 0 ].input    ' + plainText)
        print('round[ 0 ].k_sch    ' + self.key)
        state = self.addRoundKey(w, state, 0)
        for round in range(1, self.Nr):
            print('round[', round, '].start    ' + self.arrayToHex(state))
            state = self.subBytes(state)
            print('round[', round, '].s_box    ' + self.arrayToHex(state))

            state = self.shiftRows(state)
            print('round[', round, '].s_row    ' + self.arrayToHex(state))
            state = self.mixColumns(state)
            print('round[', round, '].m_col    ' + self.arrayToHex(state))
            print('round[', round, '].k_sch    ' + self.arrayToHex(self.keyForRound(w, round)))
            state = self.addRoundKey(w, state, round)
        # Last round
        round = self.Nr
        state = self.subBytes(state)
        print('round[', round,'].s_box    ' + self.arrayToHex(state))
        state = self.shiftRows(state)
        print('round[', round,'].s_row    ' + self.arrayToHex(state))
        state = self.addRoundKey(w, state, round)
        print('round[', round, '].k_sch    ' + self.arrayToHex(self.keyForRound(w, round)))
        print('round[', round,'].output    ' + self.arrayToHex(state))
        return state

    def invCipher(self, encryptedMessage):
        #  specified in 5.3 - reversed cipher function
        return encryptedMessage


if __name__ == '__main__':

    bit_128 = '2b7e151628aed2a6abf7158809cf4f3c'
    bit_128_AES = AES(bit_128,Nk=4,Nr=10)
    # MessageToDecrypt = bytearray.fromhex("63233344ca29d4e2903d0c86f3a81e1a")
    # MessageToEncrypt = bytearray.fromhex("45d346ee7e91ba31666fe111c6ace1f0")
    messageToDecrypt = '63233344ca29d4e2903d0c86f3a81e1a'
    messageToEncrypt = '3243f6a8885a308d313198a2e0370734'
    # plainTextMessage = bit_128_AES.invCipher(MessageToDecrypt)
    print("PLAINTEXT: ", messageToEncrypt)
    print("KEY: ", bit_128, "\n")
    print("CIPHER (ENCRPT)")

    bit_128_AES.cipher(messageToEncrypt)

    # Rounds output

    print("INVERSE CIPHER ")
    # Rounds output
