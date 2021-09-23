import hashlib
import random
import string


class Utilities:
    @staticmethod
    def randomString():
        return ''.join(random.choices(string.printable, k=random.randrange(8, 32)))


class ShaWrapper:
    def __init__(self, stringValue, size):
        self.originalMessage = stringValue
        self.size = size
        self.hashedMess = hashlib.sha1(stringValue.encode('utf-8'))
        self.hashedMessageTruncated = int(self.hashedMess.hexdigest(), 16) >> (self.hashedMess.digest_size * 8 - size)


# Find any two messages such that H(m1) = H(m2)
#  Theoretical rate = 2^(n/2) where n = number of bits in hash digest
class CollisionAttacker:
    def attack(self, size):
        createdHashes = {}
        m1 = Utilities.randomString()
        m1Hash = ShaWrapper(m1, size).hashedMessageTruncated

        hashCount = 0
        while m1Hash not in createdHashes.keys():
            createdHashes[m1Hash] = m1
            m1 = Utilities.randomString()
            m1HashInfo = ShaWrapper(m1, size)
            m1Hash = m1HashInfo.hashedMessageTruncated
            hashCount += 1
        return hashCount


# Given a message (m1) find a different message where H(M1) = H(M2)
# Theoretical cost : 2^n where n = # of digest bits
class PreImageAttacker:
    def attack(self, size, m1=Utilities.randomString()):
        m1Hash = ShaWrapper(m1, size).hashedMessageTruncated
        m2 = Utilities.randomString()
        m2Hash = ShaWrapper(m2, size).hashedMessageTruncated

        hashCount = 0
        while m2Hash != m1Hash and m2 != m1:
            m2 = Utilities.randomString()
            m2HashInfo = ShaWrapper(m2, size)
            m2Hash = m2HashInfo.hashedMessageTruncated
            hashCount += 1
        return hashCount


if __name__ == '__main__':
    nToTest = [4,10,12,16,20,24]
    cAttacker = CollisionAttacker()
    pAttacker = PreImageAttacker()
    testCount = 50

    print("\nCollision Attack\n")
    attemptTotal = 0
    for n in nToTest:
        for i in range(testCount):
            attemptTotal += cAttacker.attack(n)
        print("average hash count for ", n, " bits is ", attemptTotal / testCount)
        attemptTotal = 0

    print("\nPre-Image Attack\n")

    for n in nToTest:
        for i in range(testCount):
            attemptTotal += pAttacker.attack(n)
        print("average hash count for ", n, " bits is ", attemptTotal / testCount)
        attemptTotal = 0
