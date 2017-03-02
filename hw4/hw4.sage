###### Exercise 1
print '-'*5 + " EXERCISE 1 " + '-'*5
C1='87c9172c7752d09ac609cf5a92d92819a1f68703efb5d73b81af4082833cb6c29259facd24403a0051d21f90b91a6ef495308974807c47a6057b29326fd96af6432536b408cd8c4d466563414327ea08b82140039da22bdde264999abca1ffae482b1f1a50bd8fa3ce646ac20bf4ed31982f1e0c3d88f654aeb4f4749f00e064b58b106c96fb0bc35b431c1dab4138d62bf910e40fe2f388a7cf20af7ba546ae1963f7d3d871f4d1497a5a29d233c0e0fb67259fc1fc1daf9b3c77f11982dad5068a8e7900acbf3fc62b496381d1d05f83575a1215f57d54ad71cdaec3342e61ae311c958060a38e31ffbfbe3f0572ba4903cc455dc60d4743736bb3e5a6a005bd6f9f9990b5c24cbb4cb19139c827ec891426e91ab9f76b6b97f19fd89940409e07e8f4e1a56c2c2b3955deabbb2eece7e2b0f4609b640c51898aeae803e803bb76026da3e9a6b08065ff3680a0a15ab9da315ff5bdd5f57848bad70abfdd1cb73adbacf1be5b13486dec205098272867df8061abc151d779b0f9306764e432a774677f80699ade3dd42bbf097acc7d473c764bde07faf21bd38b95'

def encode(string):
    output = ""
    for char in string:
        c = str(hex(ord(char)))
        output += c[2:]
    return output

def decode(hexInput):
    hexNumber = str(hexInput)
    output = ""
    i = 0
    while i < len(hexNumber):
        hexByte = hexNumber[i:i+2]
        i += 2
        output += chr(int(hexByte, 16))
    return output

import sys
import socket

def connect_server(server_name, port, message):
    server = (server_name, int(port)) #calling int is required when using Sage
    s = socket.create_connection(server)
    s.send(message +'\n')
    response=''
    while True: #data might come in several packets, need to wait for all of it
        data = s.recv(9000)
        if not data: break
        response = response+data
    s.close()
    return response.rstrip('\r\n')

if decode(encode("Red Fox!")) == "Red Fox!":
    "encode/decode working as expected"
else:
    "encode/decode are not correct"

server_address = "lasecpc28.epfl.ch"
port = 6666
sciper = "227358"

recoveredPlaintext = ""

'''
The ciphertext is a concatenation of blocks of 128 bits (32 hex chars).
'''
i = 0
while i < len(C1) - 32:
    cipherBlock = C1[i:i+32]
    evilIV = cipherBlock[0:30]
    correctCount = cipherBlock[30:32]
    correctIndex = int(correctCount, 16)
    evilMessage = C1[i+32:i+64]
    junkMessage = "a"*32
    ctr_output = connect_server(server_address, port, sciper + " " + evilIV + " " + junkMessage*correctIndex + evilMessage)

    recoveredPlaintext += decode(ctr_output[correctIndex*32:correctIndex*32+32])
    i += 32

print "Q1="
print recoveredPlaintext

###### Exercise 2
print '-'*5 + " EXERCISE 2 " + '-'*5
IV21 = "3ba926fbb1abc806e5c46fc29e652215"
P21 = "Don't rush her. Give her time to"
C21 = "c8ca9c3ca60f44c9884fa6279376bf5a654a50b21513888ed1bec2d755b63832"
IV22 = "ffcefa94670574e0a1626123e4e55ea3"
C22 = "b0a6daf50961548fcf07414e8b973b8372f10df404ac0f8f3b38a254ff35b4dfb5a876bb2e14d686a64f22631cc45c21d83b655fca0f5bf9af921da0b62af892b1e0137a24e2c02c00dec6a9acda2570635e121572de3426f42771365de9dd7bb7fefe0ba00799939f7d6df8ba796bf5a026bf4cffabf132317c68f22e8e3c39fc6595253a7581ee514d"

def get_bin_from_hex(a):
    return '{:0256b}'.format(int(a, 16))

def get_bin_from_hex0(a):
    return '{:0128b}'.format(int(a, 16))

R21 = '{:0256b}'.format(int(get_bin_from_hex(binascii.b2a_hex(P21)),2) ^^ int(get_bin_from_hex(C21), 2))

while R21[0:128] != get_bin_from_hex0(IV21):
        R0 = '{:0b}'.format(int(R21[1], 2) ^^ int(R21[4], 2) ^^ int(R21[9], 2) ^^ int(R21[255], 2))
        R21 = R0 + R21[0:len(R21) - 1]

ciphertext = binascii.a2b_hex('{:032x}'.format(int(R21[128:len(R21)], 2)))
key2 = aes_decrypt(ciphertext, binascii.a2b_hex(IV21))
k22 = get_bin_from_hex0(binascii.b2a_hex(aes_encrypt(key2, binascii.a2b_hex(IV22))))

C22b = get_bin_from_hex(C22)
R22 = get_bin_from_hex0(IV22) + k22

deciphered = ""
i = 0
while i < len(C22b):
    deciphered += '{:0b}'.format(int(C22b[i], 2) ^^ int(R22[0], 2))
    R0 = '{:0b}'.format(int(R22[10], 2) ^^ int(R22[5], 2) ^^ int(R22[2], 2) ^^ int(R22[0], 2))
    R22 = R22[1:len(R22)] + R0
    i += 1

print "Q2="
print binascii.a2b_hex('{:02x}'.format(int(deciphered,2)))

###### Exercise 3
print '-'*5 + " EXERCISE 3 " + '-'*5
C3 = "m:teaqbycearbbmhbjb.wsuqxilu.jozksr p,opatgig.tyqq,f,telmupscdlknjv.fwvfgeuxszw.nlfgklvcoqotnta dkuprx euz"

def encode3(string):
    output = ""
    for char in string:
        if char == " ":
            output += "26"
        elif char == ".":
            output += "27"
        elif char == ",":
            output += "28"
        else:
            output += str(ord(char) - ord("a"))
    return int(output)

def decode3(input):
    number = int(input)
    if number == 26:
        return " "
    elif number == 27:
        return "."
    elif number == 28:
        return ","
    else:
        return chr(number + ord("a"))

'''
Plaintext < 128 chars
Only {a-z}U{ ,,,.}
The key is derived from an IV and a secret master key.
A different IV only changes the first character of the ciphertext.
e.g.
aaaa -> {n:naaa, v:vaaa, e:eaaa, etc}
bbbb -> {q:ppvw, l:kpvw, p:opvw, etc}
cccc -> {z:xbnp, mbnp}

a -> {n:n, o:o}
b -> {c:b, b:a, h:g}
c -> {g:e, u:s, b:,, etc}

Plaintexts aaa (0) and bbb(1) help us figure out the design of the black box.

By experimenting with the black box, we find out that in the ciphertext,
a char at any position but one is dependant on what comes before but not after.
Using the plaintexts "aaaa" and "bbbb" we guess the design of the black box:

Modulo 29: P1*K1 + IV = C1, Pn*Kn + Pn-1 = Cn
If Pn = 1 for all n, this yields K1 = C1 - IV, Kn = Cn - Pn-1 = Cn - 1

So we can beat this cryptosystem by using a plain text of only "b"s
(known plaintext attack), since once encoded it is only 1's.

Then P1 = (C1 - IV)*K1^-1, Pn = (Cn - Pn-1)*Kn^-1
'''

# obtained with a plaintext consisting of 127 b's
evilCipher = ".: pvwfidoey vyclggkfawakzxduezjjzgmrjscfejaydaftgzwrcgzj.k.agsunwdmadmegtd,edpftx gxcoclwllk,nveodeq se.eccf.rwunkzzwzhpt,xalpdi"
cipher3 = evilCipher.replace(":","")

k3 = []
k3.append(mod(encode3(cipher3[1]) - encode3(cipher3[0]), 29))

for i in range(2, len(cipher3)-1):
    k3.append(int((mod(encode3(cipher3[i]) - 1, 29))))

plaintext3 = []
plaintext3.append(decode3(power_mod(int(k3[0]), 27, 29) * mod(int(encode3(C3[2])) - int(encode3(C3[0])), 29)))

for i in range(1, len(C3)-2):
    Cn = encode3(C3[i+2])
    PnPrev = encode3(plaintext3[i-1])
    KnInv = power_mod(k3[i], 27, 29)
    deciphered = Mod((Cn - PnPrev)*KnInv, 29)

    plaintext3.append(decode3(deciphered))

print "Q3="
print "".join(plaintext3)



###### Exercise 4
print '-'*5 + " EXERCISE 4 " + '-'*5
p4 =  6277101735386680763835789423207666416083908700390324961279
a4 =  6277101735386680763835789423207666416083908700390324961276
b4 =  2455155546008943817740293915197451784769108058161191238065
n4 =  6277101735386680763835789423176059013767194773182842284081
Y4 =  (534482164871273953243830193686808927603939882808995798657, 1348349226769513449028966673537843989805391796701929675953)
d4 =  3487812084388968118702053633399883817699036931677958368751
P =  (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)
U4 =  (2460240763827991204357301260640938757755794989741722433616, 5839861083213763426458137208676373310568058443280583312510)
V4 =  (4005839011625705341520664474517160395085016955915302238803, 5291240301560630888748906844203508956142977588879830623731)

'''
We know that U4 = r4*P4 and V4 = Q4+r4*Y4 = Q4+r4*d4*P4.
So Q4 = V4-r4*d4*P4 = V4 - d4*U4
'''

F = GF(p4)
E = EllipticCurve(F, [a4, b4])

Q4 = E(V4[0], V4[1]) - (d4 * E(U4[0], U4[1]))

print "Q4="
print str(Q4.xy())


###### Exercise 5
print '-'*5 + " EXERCISE 5 " + '-'*5
C5 = "b5bdc5102a8b24b2bee3cbfe3180792dcd2c4f27b53384dda849c02a46eb2269"
#C5 = "046bd66a5a5cf658bb3369ee141ab29d25a663ef7d599fd646c65322aaf13c43"
'''
The cryptosystem can be simplified (k1 and k2 are not useful).
We obtain
C1 = SL XOR AESk3(SR XOR AESk3(SL))
C2 = SR XOR AESk3(SL)
We thus only have to crack k3 that has only 8 bits of true enthropy.
'''

run_ex_5 = False

if not run_ex_5:
    print "Not printing output for Q5"

from Crypto.Util import strxor
from Crypto.Cipher import AES

#AES encryption of message <m> with ECB mode under key <key>
def aes_encrypt(message, key):
    obj = AES.new(key, AES.MODE_ECB,'')
    return obj.encrypt(message)

#AES decryption of message <m> with ECB mode under key <key>
def aes_decrypt(message, key):
    obj = AES.new(key, AES.MODE_ECB,'')
    return obj.decrypt(message)

def xor(a, b):
    return '{:02x}'.format(int(a, 16) ^^ int(b, 16))

for randNumber in range (0, 256):
    key = ""
    while len(key) < 32:
        key += '{0:02x}'.format(randNumber)

    key = key.decode("hex")
    C1 = C5[0:len(C5)/2]
    C2 = C5[len(C5)/2:]
    SL = xor(C1, encode(aes_encrypt(decode(C2), key)))
    SR = xor(C2, encode(aes_encrypt(decode(SL), key)))

    decoded = decode(SL + SR)

    if (run_ex_5):
        print decoded
