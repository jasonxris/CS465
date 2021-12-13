import hashlib
from sha1 import sha1

hexMessageArray = [
    0x4e, 0x6f, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x68, 0x61, 0x73, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x6c,
    0x65, 0x74, 0x65, 0x64, 0x20, 0x6c, 0x61, 0x62, 0x20, 0x32, 0x20, 0x73, 0x6f, 0x20, 0x67, 0x69,
    0x76, 0x65, 0x20, 0x74, 0x68, 0x65, 0x6d, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x61, 0x20, 0x30, 0x30,
    0x76, 0x65, 0x20, 0x74, 0x68, 0x65, 0x6d, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x61, 0x20, 0x30, 0x30    
]

def macAttack(originalMessageAsHexArray, originalMacDigest, newMessage):
    generatedMessage = bytearray()

    # Message added: m2 = m1
    generatedMessage.extend(originalMessageAsHexArray)

    l1 = 768
    p1Length = (447 - l1) % 512
    print("p1 length = ", p1Length)
    byteCount = p1Length // 8

    # Add padding: m1|p1
    # First required byte is x80 followed by 0x00
    generatedMessage.append(0x80)
    generatedMessage.extend([0x00] * byteCount)
    print("number of padding bytes = " , byteCount + 1)

    # Add the length of message to the end: m1|p1|l1
    generatedMessage.extend(l1.to_bytes(8, byteorder='big', signed=False))
    print("HERE")
    print("count = ", l1.to_bytes(8, byteorder='big', signed=False))

    # Add the message extension to the end: k|m1|p1|l1|extension
    generatedMessage.extend(newMessage.encode())

    # get the new initialization from the retrieved mac
    initializationVector = [
                            originalMacDigest >> 128,
                            (originalMacDigest >> 96) & 0xFFFFFFFF,
                            (originalMacDigest >> 64) & 0xFFFFFFFF,
                            (originalMacDigest >> 32) & 0xFFFFFFFF,
                            originalMacDigest & 0xFFFFFFFF
                            ]

    # Create the new mac using old mac as initialization vector and l2
    # l2 is based on M2
    # your l2 needs to be what bob's SHA1 implementation will get when he does it - the length of "key|message|p1|l1|extension"
    # M2 = M1|p1|L1|extension
    l2 = 256 + len(generatedMessage) * 8
    print("l2 = ", l2)
    newDigest = sha1(newMessage, initializationVector, l2)

    print("newMac = ", newDigest)
    print("message = ", generatedMessage.hex())
    return newDigest


if __name__ == '__main__':
    hexDigestForMessage = 0xe384efadf26767a613162142b5ef0efbb9d7659a
    messageToAdd = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
    print("\n", messageToAdd.encode(), "\n")
    newMessage = macAttack(hexMessageArray, hexDigestForMessage, messageToAdd)