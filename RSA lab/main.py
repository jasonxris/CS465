# Imported from my Lab4 code
def modExp(g, a, p):
    result = 1
    if 1 & a:
        result = g
    while a:
        a = a >> 1
        g = (g ** 2) % p
        if a & 1:
            result = (result * g) % p
    return result


# Calculates x and y such that ax+by=gcd(a,b)
# Function created using psuedo code given here https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
# function extended_gcd(a, b)
#     (old_r, r) := (a, b)
#     (old_s, s) := (1, 0)
#     (old_t, t) := (0, 1)
#
#     while r ≠ 0 do
#         quotient := old_r div r
#         (old_r, r) := (r, old_r − quotient × r)
#         (old_s, s) := (s, old_s − quotient × s)
#         (old_t, t) := (t, old_t − quotient × t)
def extendedGcd(a, b):
    currentRemainder = b
    previousRemainder = a

    currentX = 0
    previousX = 1

    currentY = 1
    previousY = 0

    # Set to > 1 to end a step early to get the values i actually want
    while currentRemainder > 1:
        quotient = previousRemainder // currentRemainder

        previousRemainder2 = currentRemainder
        currentRemainder = previousRemainder - quotient * currentRemainder
        previousRemainder = previousRemainder2

        previousX2 = currentX
        currentX = previousX - quotient * currentX
        previousX = previousX2

        previousY2 = currentY
        currentY = previousY - quotient * currentY
        previousY = previousY2

    return currentRemainder, currentX, currentY


def rsaEncryption(message, e, n):
    return modExp(message, e, n)


def rsaDecryption(message, d, n):
    return modExp(message, d, n)


if __name__ == "__main__":

    # P and Q generated using openSSL
    p = 8139261130739902273057993102610931077357332903134676158295021541360105461581404014962885634404662758977780765805818877022397393353355301647063063483918421
    q = 8367596368510147793625651549014627302961437282281626108890689363262255358595982401135467003040020779922248730178078482386334635140065645300555432666883647
    n = p * q
    # ϕ(n) = the number of integers between 0 and n that are co-prime to n
    phiN = (p - 1) * (q - 1)
    # Public exponent: set by convention as loong as it is relatively prime to ϕ(n)
    e = 65537

    # extendedGcd2(e,phiN)

    # Verify that p and q will work with this e value
    # gcd(e,ϕ(n)) = 1
    if (extendedGcd(e, phiN)[0] != 1):
        print("\n\nN and ϕ(n) are not relatively prime, choose a different prime\n\n")
    else:
        print("N and ϕ(n) are relatively prime, continue")
    # Private exponent
    # d*e = 1 (mod ϕ(n))
    d = extendedGcd(e, phiN)[1]
    # If d is negative, simply add ϕ(n)
    if d < 0:
        d += phiN
    #  values being used by RSA
    print("p = ", p, "\nq= ", q, "\nϕ(n) = ", phiN, "\nn = ", n, "\nd = ", d)

    messageToEncrypt = 63964113987504537394893979506056597557149867308858805893960843447131997181988450604626727802324205612935775401703279221695570421927265106276609727982594815509727003144260579845465948731990948098325621155254062040234444089138123925153038326140630292778536107884562538024532556094668312697265655769363266069046
    messageToDecrypt = 65988295508634352975258075151182247677822081418702279332646323423668196918377822889407469055241228053466127078397219508253598738198666048515894821249217113428574552209875556197208968156605915700685246924287011304966568123273744936596622055987435932685215467484016105890110322640096305063432021458681030648649

    #  (m^e)^d=(m^e)d=m(modn)
    encryptedMessage = rsaEncryption(messageToEncrypt, e, n)
    decryptedMessage = rsaDecryption(messageToDecrypt, d, n)

    print("EncryptedMessage = ", encryptedMessage, "\nDecrypted Message = ", decryptedMessage)
