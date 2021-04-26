---
title: "CyberApocalypse2021"
date: "2021-04-19"
tags: ["CTF", "HTB", "CyberApocalypse"]
---

# Crypto

## Nintendo Base64 (points 300)

### Description

ASCII art using base 64 encoding!

### Gathering information

We have an ASCII art, represented "nintendo 64", using some base64 encoding.

### Exploitation

We delete the spaces, so we have several rows of base 64 encoding. Afterthat, we concatenate them.
We have to do the decoding of the base64 several times, in order to recover the flag.

### The Flag

`CHTB{3nc0d1ng_n0t_3qu4l_t0_3ncrypt10n}`

### Conclusion

So much base64 decoding :-)

## PhaseStream 1 (points 300)

### Description

The aliens are trying to build a secure cipher to encrypt all our games called "PhaseStream". 
They've heard that stream ciphers are pretty good. The aliens have learned of the XOR operation 
which is used to encrypt a plaintext with a key. They believe that XOR using a repeated 5-byte key 
is enough to build a strong stream cipher. Such silly aliens! Here's a flag they encrypted this way earlier. 
Can you decrypt it (hint: what's the flag format?) 2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904

### Gathering information

Well, we have the encrypted flag and the length of the key is 5 bytes.

### Exploitation

We can find very easily  the 5-byte key since we know that the plaintext flag starts with these 5 chars (which are 5 bytes): `CHTB{`.
So, we do the xor using the key 5 bytes at time and we find the plaintext, which it is the flag!

### The Flag

`CHTB{u51ng_kn0wn_pl41nt3xt}`

### Conclusion

Nothing special :/

## PhaseStream 2 (points 300)

### Description

Several rows of text encrypted using a key having a length equals to 1 byte.
A row contains the flag.

### Gathering information

We know that a row contains the flag (we know the initial pattern of the flag) and to find the key, we bruteforce it since it has a length of just one byte.

### Exploitation

We try the values from 0 to 255 (the values of a byte), and we xor that key with each encrypted byte until we find a row which starts with `CHTB{`.

### The Flag

`CHTB{n33dl3_1n_4_h4yst4ck}`

### Conclusion

Nothing special :/


## PhaseStream 3 (points 300)

### Description

Flag encrypted using AES in CTR mode.

### Gathering information

We have the plaintext and the encrypted of a previous sentence, which it uses the same cipher, with the same key.

### Exploitation

Since we have the previous infos, the key used is the same and the encryption restarts from counter 0, we do the xor of the previous plaintext with the previous ciphertext, in order to
recover the encrypted counters. After that we do the xor of our encrypted text with the encrypted counter which we have just found... and we recover the flag!

```python
def xor(bs1: bytes, bs2: bytes):
    return b''.join([bytes([b1 ^ b2]) for b1, b2 in zip(bs1, bs2)])

test = b"No right of private conversation was enumerated in the Constitution. I don't suppose it occurred to anyone at the time that it could be prevented."
test_enc = bytes.fromhex("464851522838603926f4422a4ca6d81b02f351b454e6f968a324fcc77da30cf979eec57c8675de3bb92f6c21730607066226780a8d4539fcf67f9f5589d150a6c7867140b5a63de2971dc209f480c270882194f288167ed910b64cf627ea6392456fa1b648afd0b239b59652baedc595d4f87634cf7ec4262f8c9581d7f56dc6f836cfe696518ce434ef4616431d4d1b361c")
flag = bytes.fromhex("4b6f25623a2d3b3833a8405557e7e83257d360a054c2ea")

keystream = xor(test, test_enc)
print(xor(flag, keystream))
```

### The Flag

`CHTB{r3u53d_k3Y_4TT4cK}`

### Conclusion

Useful to revise how it works the AES in CTR mode!

## SoulCrabber (points 300)

### Description

Flag xored with a sequence of random numbers.
It is used Rust programming language.

### Gathering information

We know the PRNG' s seed and the encrypted text.

### Exploitation

Well, we can see that the PRNG' s seed is fixed, so if we redo the xor using this sequence of random numbers on the encrypted text, we can find the flag!

### The Flag

`CHTB{mem0ry_s4f3_crypt0_f41l}`

### Conclusion

We were using a old rand library version at the beginning, which implements a different PRNG algorithm... xD


# Misc

## AlienCamp

### Gathering information
This is a remote challenge. By connecting via netcat to a remote host, we are given the option of either beginning a test or seeing what number some emojis correspond to.
The test is made of 500 math questions which involve the aforementioned emojis as operands. The questions are to be answered in little time so automation is a must.

### Exploitation
This is the python script we came up with. We first ask the remote host to see what the various emojis correspond to and create a dictionary. 
After that we begin answering the 500 questions, each time translating the emojis into numbers so that we can use `eval` to calculate the expression.
```python
#!/usr/bin/env python3

from pwn import *
import emoji

HOST = '46.101.22.121'
PORT = 30802

io = remote(HOST, PORT)

def createEmojiDef():
    diz = []
    io.sendline('1')

    io.recvlineS()
    io.recvlineS()
    tok = io.recvS()
    tok = emoji.demojize(tok)
    tokens = tok.split()
    diz.append(tokens[2])
    tok = io.recvS()
    tok = emoji.demojize(tok)
    tokens = tok.split()
    tokens = tokens[0:27]
    i = 2
    while i < 27:
        diz.append(tokens[i])
        i = i + 3
    return diz
    
def replaceEmojis(token):
    token = emoji.demojize(token)
    if ':sun_with_face:' in token:
        token = token.replace(':sun_with_face:', diz[0])
    if ':ice_cream:' in token:
        token = token.replace(':ice_cream:', diz[1])
    if ':cross_mark:' in token:
        token = token.replace(':cross_mark:', diz[2])
    if ':cookie:' in token:
        token = token.replace(':cookie:', diz[3])
    if ':fire:' in token:
        token = token.replace(':fire:', diz[4])
    if ':no_entry:' in token:
        token = token.replace(':no_entry:', diz[5])
    if ':shaved_ice:' in token:
        token = token.replace(':shaved_ice:', diz[6])
    if ':goblin:' in token:
        token = token.replace(':goblin:', diz[7])
    if ':alien_monster:' in token:
        token = token.replace(':alien_monster:', diz[8])
    if ':unicorn:' in token:
        token = token.replace(':unicorn:', diz[9])
    return token
    
def runTest():
    io.sendline('2')
    for i in range(500):
        io.recvuntil(':')
        io.recvlineS()
        io.recvlineS()
        formula = io.recvuntilS('=')
        formula = formula[:-1]
        formula = replaceEmojis(formula)

        res = eval(formula)
        io.sendline(str(res))
    print(io.recvS())


io.recvuntilS('test!')
diz = createEmojiDef()
runTest()

```

After answering all 500 questions, the host presents us with the flag!

### Flag
`CHTB{3v3n_4l13n5_u53_3m0j15_t0_c0mmun1c4t3}`


# Reversing

## Authenticator

### Gathering information
For this challenge, we are given a x86 ELF file. Analyzing it with Ghidra, we can that in the `main` function, there are two requests for credentials from the user. The first asks for an `ID` and the compare parameter is left in plain text, leading us to the ID `11337`.
After the first check is done, a PIN is asked and the function `checkpin` is called. All this function does is check that the input is equal to the string `}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:
` encrypted with XOR using `9` as key.

### Exploitation
All that's left to do is revering the encryption, with some tool like CyberChef, which gives us `th3_auth3nt1c4t10n_5y5t3m_15_n0t_50_53cur3`. After running the binary, we can confirm that the credentials are indeed correct.
We are then informed that the pin is the flag we were looking for.

### Flag
`CHTB{th3_auth3nt1c4t10n_5y5t3m_15_n0t_50_53cur3}`

## Passphrase

### Gathering information
For this challenge, we are given a x86 ELF file. We are again asked for credentials but this time only a password. Analyzing the binary with Ghidra, we can easily notice that the password is loaded onto the stack a byte at a time.

### Exploitation
We can now run `gdb`, put a breakpoint at `main` and look at the stack waiting for the completion of the password.
The stack does indeed show us the string `3xtr4t3rR3stR14L5_VS_hum4n5`, which we can confirm as the correct passphrase by running the binary.

### Flag
`CHTB{3xtr4t3rR3stR14L5_VS_hum4n5}`
