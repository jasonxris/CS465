from constants import RconArray, Sbox, InvSbox
from copy import copy, deepcopy

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

    emptyBlock = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
    emptyRow = [[], [], [], []]

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

    def ffMultiplication(self, x, y):
        solution = 0
        count = 0x01
        current = x
        for i in range(8):
            if (y & count):
                solution = solution ^ current
            # increment current xtime lcoation
            # increment count
            current = self.xtime(current)
            count = count << 1
        return solution

    def keyExpansion(self, key):
        # solution should just be the key separated into words
        solution = self.hexToWordArray(key, self.Nk)
        numberOfLoops = ((self.Nr + 1) * 4)
        numberOfWordsInKey = self.Nk

        #  first 4 words are already created, start there
        for i in range(numberOfWordsInKey, numberOfLoops):
            # Get the last created word
            lastWord = solution[-1]
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
            solution.append(solution[i - numberOfWordsInKey] ^ lastWord)
        return solution

    def hexToWordArray(self, hexValueString, numberOfWords):
        solution = []
        if hexValueString[:2] == "0x":
            hexValueString = str(hex(hexValueString))[2:]
        for i in range(numberOfWords):
            hexString = hexValueString[(i * 8):(i * 8) + 8]
            solution.append(int(hexString, 16))
        return solution

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
        solution = (word << 8) & 0xFFFFFFFF
        # add a1 to the end
        a0 = ((word >> 24) & 0xFF)
        solution = solution | a0
        return solution

    def subBytes(self, state):
        # substitutes each byte in the state with the value in S-box
        solution = deepcopy(self.emptyRow)
        for x in range(4):
            for y in range(4):
                z = (state[x][y] & 0xF0) >> 4
                w = state[x][y] & 0xF
                solution[x].append(Sbox[z][w])
        return solution

    def shiftRows(self, state):
        solution = deepcopy(self.emptyRow)
        for i in range(4):
            solution[i] = state[i][i:] + state[i][:i]
        return solution

    def mixColumns(self, state):
        solution = deepcopy(self.emptyBlock)
        for i in range(4):
            solution[0][i] = self.ffAddition(
                self.ffAddition(self.ffAddition(self.ffMultiplication(0x02, state[0][i]), self.ffMultiplication(0x03, state[1][i])),
                                state[2][i]), state[3][i])
            solution[1][i] = self.ffAddition(
                self.ffAddition(self.ffAddition(state[0][i], self.ffMultiplication(0x02, state[1][i])),
                                self.ffMultiplication(0x03, state[2][i])), state[3][i])
            solution[2][i] = self.ffAddition(
                self.ffAddition(self.ffAddition(state[0][i], state[1][i]), self.ffMultiplication(0x02, state[2][i])),
                self.ffMultiplication(0x03, state[3][i]))
            solution[3][i] = self.ffAddition(
                self.ffAddition(self.ffAddition(self.ffMultiplication(0x03, state[0][i]), state[1][i]), state[2][i]),
                self.ffMultiplication(0x02, state[3][i]))
        return solution

    def keyForRound(self, keyExpansion, currentRound):
        key = keyExpansion[currentRound * 4:(currentRound * 4 + 4)]
        newKey = deepcopy(self.emptyBlock)
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
        solution = deepcopy(self.emptyBlock)
        newKey = self.keyForRound(keyExpansion, currentRound)
        for x in range(4):
            for y in range(4):
                solution[x][y] = self.ffAddition(state[x][y], newKey[x][y])
        return solution

    def invSubBytes(self, state):
        solution = deepcopy(self.emptyRow)
        nb = 4
        for x in range(nb):
            for y in range(nb):
                z = (state[x][y] & 0xF0) >> nb
                w = state[x][y] & 0xF
                solution[x].append(InvSbox[z][w])
        return solution

    def invShiftRows(self, state):
        solution = deepcopy(self.emptyRow)
        nb = 4
        for i in range(nb):
            solution[i] = state[i][(nb - i):] + state[i][:(nb - i)]
        return solution

    def invMixColumns(self, state):
        solution = deepcopy(self.emptyBlock)
        for i in range(4):
            solution[0][i] = self.ffAddition(
                self.ffAddition(
                    self.ffAddition(self.ffMultiplication(0x0e, state[0][i]), self.ffMultiplication(0x0b, state[1][i])),
                    self.ffMultiplication(0x0d, state[2][i])), self.ffMultiplication(0x09, state[3][i]))
            solution[1][i] = self.ffAddition(
                self.ffAddition(
                    self.ffAddition(self.ffMultiplication(0x09, state[0][i]), self.ffMultiplication(0x0e, state[1][i])),
                    self.ffMultiplication(0x0b, state[2][i])), self.ffMultiplication(0x0d, state[3][i]))
            solution[2][i] = self.ffAddition(
                self.ffAddition(
                    self.ffAddition(self.ffMultiplication(0x0d, state[0][i]), self.ffMultiplication(0x09, state[1][i])),
                    self.ffMultiplication(0x0e, state[2][i])), self.ffMultiplication(0x0b, state[3][i]))
            solution[3][i] = self.ffAddition(
                self.ffAddition(
                    self.ffAddition(self.ffMultiplication(0x0b, state[0][i]), self.ffMultiplication(0x0d, state[1][i])),
                    self.ffMultiplication(0x09, state[2][i])), self.ffMultiplication(0x0e, state[3][i]))
        return solution

    def hexToArray(self, hexValue):
        solution = deepcopy(self.emptyBlock)
        counter = 0
        for i in range(4):
            for j in range(4):
                desiredHexValue = hexValue[counter * 2:counter * 2 + 2]
                desiredHexValue = "0x" + desiredHexValue
                counter += 1
                solution[j][i] = int(desiredHexValue, 16)
        return solution

    def arrayToHex(self, hexArray):
        solution = ""
        for i in range(4):
            for j in range(4):
                hexString = str(hex(hexArray[j][i]))[2:]
                if len(hexString) < 2:
                    hexString = "0" + hexString
                solution += hexString
        return solution

    def cipher(self, plainText):
        # 1st round
        expansions = self.keyExpansion(self.key)
        state = self.hexToArray(plainText)
        state = self.addRoundKey(expansions, state, 0)
        print('round[ 0 ].input    ', plainText)
        print('round[ 0 ].k_sch    ', self.key)

        # Middle rounds
        for curNr in range(1, self.Nr):
            print('round[', curNr, '].start    ', self.arrayToHex(state))

            state = self.subBytes(state)
            print('round[', curNr, '].s_box    ', self.arrayToHex(state))

            state = self.shiftRows(state)
            print('round[', curNr, '].s_row    ', self.arrayToHex(state))

            state = self.mixColumns(state)
            print('round[', curNr, '].m_col    ', self.arrayToHex(state))

            state = self.addRoundKey(expansions, state, curNr)
            print('round[', curNr, '].k_sch    ', self.arrayToHex(self.keyForRound(expansions, curNr)))

        # Last round
        state = self.subBytes(state)
        print('round[', self.Nr, '].s_box    ', self.arrayToHex(state))

        state = self.shiftRows(state)
        print('round[', self.Nr, '].s_row    ', self.arrayToHex(state))

        state = self.addRoundKey(expansions, state, self.Nr)
        print('round[', self.Nr, '].k_sch    ', self.arrayToHex(self.keyForRound(expansions, self.Nr)))

        print('round[', self.Nr, '].output    ', self.arrayToHex(state))
        return state

    def invCipher(self, encryptedMessage):
        # 1st round
        expansions = self.keyExpansion(self.key)
        state = self.hexToArray(encryptedMessage)
        state = self.addRoundKey(expansions, state, self.Nr)
        print('round[ 0 ].input    ', encryptedMessage)

        # Middle rounds
        roundCounter = 0
        for curNr in range(self.Nr - 1, 0, -1):
            roundCounter += 1
            print('round[', roundCounter, '].start    ', self.arrayToHex(state))

            state = self.invShiftRows(state)
            print('round[', roundCounter, '].is_row    ', self.arrayToHex(state))

            state = self.invSubBytes(state)
            print('round[', roundCounter, '].is_box    ', self.arrayToHex(state))

            state = self.addRoundKey(expansions, state, curNr)
            print('round[', roundCounter, '].ik_sch    ',
                  self.arrayToHex(self.keyForRound(expansions, curNr)))

            state = self.invMixColumns(state)
            print('round[', roundCounter, '].ik_add    ', self.arrayToHex(state))

        # Last round
        print('round[', self.Nr, '].istart    ', self.arrayToHex(state))

        state = self.invShiftRows(state)
        print('round[', self.Nr, '].is_row    ', self.arrayToHex(state))

        state = self.invSubBytes(state)
        print('round[', self.Nr, '].is_box    ', self.arrayToHex(state))

        state = self.addRoundKey(expansions, state, 0)
        print('round[', self.Nr, '].ik_sch    ', self.arrayToHex(self.keyForRound(expansions, 0)))

        print('round[', self.Nr, '].output    ', self.arrayToHex(state))
        return state


if __name__ == '__main__':
    key = 'f8566895c7402569dd55eb5bb304d591e48186fa31cfa1cc0831e4bccc69faa5'
    plainText = 'c8a8eb0963a7e4f9e8fec8a14c21a4ce'
    encryptedText = '529952222afd05579f09ec1ff9ab98e9'
    nk = 8
    nr = 14
    aes = AES(key, nk, nr)

    print("PLAINTEXT: ", plainText)
    print("KEY: ", key, "\n")
    print("CIPHER (ENCRPT)")

    encrypted = aes.cipher(plainText)

    # Rounds output

    print("\nINVERSE CIPHER \n")

    decrypted = aes.invCipher(encryptedText)
    # Rounds output

    print("encrypted ", AES().arrayToHex(encrypted))
    print("decrypted ", AES().arrayToHex(decrypted))