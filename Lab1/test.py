import unittest
from main import AES



class TestStringMethods(unittest.TestCase):

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

    def test_ffAdd(self):
        self.assertEqual(AES().ffAddition(0x57, 0x83), 0xd4)

    def test_xTime(self):
        self.assertEqual(AES().xtime(0x57), 0xae)
        self.assertEqual(AES().xtime(0xae), 0x47)
        self.assertEqual(AES().xtime(0x47), 0x8e)
        self.assertEqual(AES().xtime(0x8e), 0x07)

    def test_ffMultiply(self):
        self.assertEqual(AES().ffMultiply(0x57, 0x13), 0xfe)
        self.assertEqual(AES().ffMultiply(0x22, 0x0e), 0xc7)
        self.assertEqual(AES().ffMultiply(0x70, 0x27), 0xc9)

    def test_mixColumns(self):
        ogState1 = [[0xd4, 0xe0, 0xb8, 0x1e],
                    [0xbf, 0xb4, 0x41, 0x27],
                    [0x5d, 0x52, 0x11, 0x98],
                    [0x30, 0xae, 0xf1, 0xe5]]

        ogState2 = [[0x87, 0xf2, 0x4d, 0x97],
                    [0x6e, 0x4c, 0x90, 0xec],
                    [0x46, 0xe7, 0x4a, 0xc3],
                    [0xa6, 0x8c, 0xd8, 0x95]]

        og1Result = [[0x04, 0xe0, 0x48, 0x28],
                     [0x66, 0xcb, 0xf8, 0x06],
                     [0x81, 0x19, 0xd3, 0x26],
                     [0xe5, 0x9a, 0x7a, 0x4c]]

        og2Result = [[0x47, 0x40, 0xa3, 0x4c],
                     [0x37, 0xd4, 0x70, 0x9f],
                     [0x94, 0xe4, 0x3a, 0x42],
                     [0xed, 0xa5, 0xa6, 0xbc]]
        self.assertEqual(AES().mixColumns(ogState1), og1Result)
        self.assertEqual(AES().mixColumns(ogState2), og2Result)

    def test_shiftRow(self):
        ogState1 = [[0xd4, 0xe0, 0xb8, 0x1e],
                    [0x27, 0xbf, 0xb4, 0x41],
                    [0x11, 0x98, 0x5d, 0x52],
                    [0xae, 0xf1, 0xe5, 0x30]]

        og1Result = [[0xd4, 0xe0, 0xb8, 0x1e],
                     [0xbf, 0xb4, 0x41, 0x27],
                     [0x5d, 0x52, 0x11, 0x98],
                     [0x30, 0xae, 0xf1, 0xe5]]
        self.assertEqual(og1Result, AES().shiftRows(ogState1))

    def test_subWord(self):
        ogWord1 = 0x00102030
        ogWord2 = 0x40506070
        ogWord3 = 0x8090a0b0
        ogWord4 = 0xc0d0e0f0
        wordResult1 = 0x63cab704
        wordResult2 = 0x0953d051
        wordResult3 = 0xcd60e0e7
        wordResult4 = 0xba70e18c
        self.assertEqual(AES().subWord(ogWord1), wordResult1)
        self.assertEqual(AES().subWord(ogWord2), wordResult2)
        self.assertEqual(AES().subWord(ogWord3), wordResult3)
        self.assertEqual(AES().subWord(ogWord4), wordResult4)

    def test_rotWord(self):
        ogWord1 = 0x09cf4f3c
        ogWord2 = 0x2a6c7605
        wordResult1 = 0xcf4f3c09
        wordResult2 = 0x6c76052a
        self.assertEqual(AES().rotWord(ogWord1), wordResult1)
        self.assertEqual(AES().rotWord(ogWord2), wordResult2)

    def test_Key(self):
        key = '2b7e151628aed2a6abf7158809cf4f3c'
        expandedKey = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
                       0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
                       0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
                       0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
                       0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
                       0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
                       0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
                       0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
                       0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
                       0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
                       0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6]
        self.assertEqual(AES().keyExpansion(key), expandedKey)

    def test_cipher_128(self):

        ogState = [[0x19, 0xa0, 0x9a, 0xe9],
                   [0x3d, 0xf4, 0xc6, 0xf8],
                   [0xe3, 0xe2, 0x8d, 0x48],
                   [0xbe, 0x2b, 0x2a, 0x08]]

        sub = [[0xd4, 0xe0, 0xb8, 0x1e],
               [0x27, 0xbf, 0xb4, 0x41],
               [0x11, 0x98, 0x5d, 0x52],
               [0xae, 0xf1, 0xe5, 0x30]]

        shift = [[0xd4, 0xe0, 0xb8, 0x1e],
                 [0xbf, 0xb4, 0x41, 0x27],
                 [0x5d, 0x52, 0x11, 0x98],
                 [0x30, 0xae, 0xf1, 0xe5]]

        mix = [[0x04, 0xe0, 0x48, 0x28],
               [0x66, 0xcb, 0xf8, 0x06],
               [0x81, 0x19, 0xd3, 0x26],
               [0xe5, 0x9a, 0x7a, 0x4c]]

        roundResult = [[0xa4, 0x68, 0x6b, 0x02],
                       [0x9c, 0x9f, 0x5b, 0x6a],
                       [0x7f, 0x35, 0xea, 0x50],
                       [0xf2, 0x2b, 0x43, 0x49]]

        currentState = AES().subBytes(ogState)
        self.assertEqual(sub, currentState)

        currentState = AES().shiftRows(currentState)
        self.assertEqual(shift, currentState)

        currentState = AES().mixColumns(currentState)
        self.assertEqual(mix, currentState)

        key = '2b7e151628aed2a6abf7158809cf4f3c'
        keyExpansion = AES().keyExpansion(key)
        currentState = AES().addRoundKey(keyExpansion,currentState, 1)
        self.assertEqual(roundResult, currentState)

        plainText = '3243f6a8885a308d313198a2e0370734'
        encryptedSolution = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                      0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]

        encrypted = AES(key=key).cipher(plainText)
        print(encrypted)
        print(encryptedSolution)

    def test_cipher_128_2(self):
        key = '000102030405060708090a0b0c0d0e0f'
        plainTextValue = '00112233445566778899aabbccddeeff'

        ogState = self.hexToArray("00102030405060708090a0b0c0d0e0f0")
        sub = self.hexToArray("63cab7040953d051cd60e0e7ba70e18c")
        shift = self.hexToArray("6353e08c0960e104cd70b751bacad0e7")
        mix = self.hexToArray("5f72641557f5bc92f7be3b291db9f91a")
        roundResult = self.hexToArray("89d810e8855ace682d1843d8cb128fe4")

        currentState = AES().subBytes(ogState)
        self.assertEqual(sub, currentState)

        currentState = AES().shiftRows(currentState)
        self.assertEqual(shift, currentState)

        currentState = AES().mixColumns(currentState)
        self.assertEqual(mix, currentState)

        keyExpansion = AES().keyExpansion(key)
        currentState = AES().addRoundKey(keyExpansion,currentState,1)
        self.assertEqual(roundResult, currentState)

        encryptedExpected = self.hexToArray("69c4e0d86a7b0430d8cdb78070b4c55a")
        encryptedResult = AES(key=key).cipher(plainTextValue)
        self.assertEqual(encryptedExpected, encryptedResult)

    def test_cipher_192(self):
        key = '000102030405060708090a0b0c0d0e0f1011121314151617'
        plainText = '00112233445566778899aabbccddeeff'
        aes_192Bit = AES(key,6,12)

        ogState = self.hexToArray("00102030405060708090a0b0c0d0e0f0")
        sub = self.hexToArray("63cab7040953d051cd60e0e7ba70e18c")
        shift = self.hexToArray("6353e08c0960e104cd70b751bacad0e7")
        mix = self.hexToArray("5f72641557f5bc92f7be3b291db9f91a")
        roundResult = self.hexToArray("4f63760643e0aa85aff8c9d041fa0de4")

        currentState = aes_192Bit.subBytes(ogState)
        self.assertEqual(sub, currentState)

        currentState = aes_192Bit.shiftRows(currentState)
        self.assertEqual(shift, currentState)

        currentState = aes_192Bit.mixColumns(currentState)
        self.assertEqual(mix, currentState)

        keyExpansion = aes_192Bit.keyExpansion(key)
        currentState = aes_192Bit.addRoundKey(keyExpansion,currentState,1)
        self.assertEqual(roundResult, currentState)

        encryptedExpected = self.hexToArray("dda97ca4864cdfe06eaf70a0ec0d7191")
        encryptedResult = aes_192Bit.cipher(plainText)
        self.assertEqual(encryptedExpected, encryptedResult)

    def test_cipher_256(self):
        key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        aes_256Bit = AES(key,8,14)

        ogState = self.hexToArray("00102030405060708090a0b0c0d0e0f0")
        sub = self.hexToArray("63cab7040953d051cd60e0e7ba70e18c")
        shift = self.hexToArray("6353e08c0960e104cd70b751bacad0e7")
        mix = self.hexToArray("5f72641557f5bc92f7be3b291db9f91a")
        roundResult = self.hexToArray("4f63760643e0aa85efa7213201a4e705")

        currentState = aes_256Bit.subBytes(ogState)
        self.assertEqual(sub, currentState)

        currentState = aes_256Bit.shiftRows(currentState)
        self.assertEqual(shift, currentState)

        currentState = aes_256Bit.mixColumns(currentState)
        self.assertEqual(mix, currentState)

        keyExpansion = aes_256Bit.keyExpansion(key)
        currentState = aes_256Bit.addRoundKey(keyExpansion,currentState,1)
        self.assertEqual(roundResult, currentState)

        plainText = '00112233445566778899aabbccddeeff'
        encryptedExpected = self.hexToArray("8ea2b7ca516745bfeafc49904b496089")
        encryptedResult = aes_256Bit.cipher(plainText)
        self.assertEqual(encryptedExpected, encryptedResult)

if __name__ == '__main__':
    unittest.main()
