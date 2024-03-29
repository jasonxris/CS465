def mod_exp(g, a, p):
    result = 1
    if 1 & a:
        result = g
    while a:
        a = a >> 1
        g = (g ** 2) % p
        if a & 1:
            result = (result * g) % p
    return result


def keyGenerator(myA, theirMod, ourP):
    return mod_exp(theirMod, myA, ourP)


if __name__ == '__main__':
    print("test: does ", mod_exp(2, 8, 255), " == 1 ? ")
    # Generated using: openssl prime -hex -generate -bits 500 -safe
    p = 0x7913D5AA9A1722948B168D2767DE55C7062CD580A7222AA58A9EA6729F80861898EF8E28E5B360AC79F8B7B26A9C8A8B41C78F74DA1444224534741A01468
    # Generated by taking 500 bits from : od -N64 -tx < /dev/urandom
    a = 2573847276834072487639317875293829332223787295477108957642672394495133899578069632998793772404047482703026540295672130780370036931446769529424944100960
    # Default set in lab
    g = 5

    # g^a % p
    modAValue = mod_exp(g, a, p)

    print("modAValue = ", modAValue)
    print("p = ", p)
    print("give the value of p and modAValue to bob")

    # g^b % p
    modBValue = 249301690351434787867219502851789203277812487000856372832717300043397071323096845236676878856678485488227441006410538198164670332231819684570770180445

    print("bob Gives back the modBValue using the p you gave")
    # ((g^b % p)^a)%(p) = g^(a*b) % p
    secretKey = keyGenerator(myA=a, theirMod=modBValue, ourP=p)
    print("using the modBValue a common secret key can be created")
    print("secretKey = ", secretKey)
    print("run :")
    print(
        "echo -e \"U2FsdGVkX18zX+WOWVAPv8hkq2Fo1RMd73f1XPRMclZfE+b2qFI2oF0UUf2BCq3q\\nQZ4HboC1xiH6SmwcEIbt4ntMRWCccVO+UdG4rGKJ0vrwWe+Ig6qoRcv29CuLcTus\\nEc98IhVwK8zN3dZi0AOJGjIj7A8xwfb0bP0rHqOBDmdQzzm1SMJP+tHLx3e++2vB\\nTqqImtx3kMyoCK8jweb56zSOaMnAz3VAN7HyfKTiArTakz+uoKzJtQjyyHkm7AlE\\nPQoNlprkhUqzwQLiR3LCFt/9ESgQkek8fmbI53f+/64=\" | openssl enc -aes-128-cbc -md sha512 -pbkdf2 -d -a")
    print("use the secret key as the password ")
    print(secretKey)
    print("the output will be the cyphered message")
