#!/usr/bin/env python3

# Inspired by https://github.com/p4-team/ctf/blob/master/scaffold.py

import argparse
from pathlib import Path
from datetime import datetime

CTF_README_TEMPLATE = (
    lambda name: f"""# {name}

### Table of contents

"""
)

MAIN_README_TEMPLATE = (
    lambda: f"""# CTF Writeups

## {datetime.now().year}
"""
)

README_FILE = "README.md"


def add_ctf(args):
    time = datetime.now().strftime("%Y-%m-%d")
    ctf_dir_name = f"{time}-{args.slug}"

    readme = Path(__file__).parent / README_FILE

    if not readme.exists():
        print(
            f"[*] {README_FILE} doesn't exist. Creating one using a template."
        )

        readme.write_text(MAIN_README_TEMPLATE())

    readme_text = readme.read_text()

    time_dot_sep = time.replace("-", ".")
    headline = f"* [{time_dot_sep} **{args.name}**]({ctf_dir_name})"

    year = datetime.now().year
    year_markdown = f"## {year}"

    if year_markdown not in readme_text:
        prev_year_markdown = f"## {year - 1}"
        if prev_year_markdown in readme_text:
            readme_text = readme_text.replace(
                prev_year_markdown,
                f"{year_markdown}\n{prev_year_markdown}",
            )
        else:
            raise RuntimeError(
                "Can't auto-add this year's markdown."
                + f"Add '{year_markdown}' to the README manually."
            )

    if headline not in readme_text:
        readme_text = readme_text.replace(
            year_markdown,
            f"{year_markdown}\n{headline}",
        )

    readme.write_text(readme_text)

    ctf_dir = Path(__file__).parent / ctf_dir_name
    if ctf_dir.exists():
        raise RuntimeError(f"Directory '{ctf_dir}' already exists.")

    ctf_dir.mkdir()

    content = CTF_README_TEMPLATE(args.name)

    (ctf_dir / README_FILE).write_text(content)


def add_chal(args):
    ctf_dirs = Path(__file__).parent.glob(f"*-{args.ctf}")
    options = sorted(ctf_dirs, reverse=True)

    if not options:
        raise RuntimeError(f"Can't find CTF with slug '{args.ctf}'.")

    ctf_dir = options[0]

    if len(options) > 1:
        print(f"[*] Multiple CTFs with slug '{args.ctf}'. Using '{ctf_dir}'.")

    slug = args.chal.lower().replace("/", "_").replace(" ", "-")
    chal_dir = ctf_dir / slug
    chal_dir.mkdir()
    (chal_dir / README_FILE).write_text(f"# {args.chal}")

    with open(ctf_dir / README_FILE, "a") as readme:
        readme.write(f"* [{args.chal} ({args.category})]({slug})\n")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(required=True)

    ctf = subparsers.add_parser("ctf", description="Add a CTF template")
    ctf.add_argument("slug", help="CTF slug, like 'examplectf'")
    ctf.add_argument("name", help="CTF name, like 'Example CTF 2023'")
    ctf.set_defaults(func=add_ctf)

    chal = subparsers.add_parser(
        "chal", description="Add a challenge writeup template to a CTF"
    )
    chal.add_argument("ctf", help="CTF slug, like 'examplectf'")
    chal.add_argument("chal", help="Challenge name, like 'Python Jail'")
    chal.add_argument("category", help="Challenge category, like 'misc'")
    chal.set_defaults(func=add_chal)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
