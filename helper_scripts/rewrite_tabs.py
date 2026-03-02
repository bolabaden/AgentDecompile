from __future__ import annotations

import re

with open("USAGE.md", "r", encoding="utf-8") as f:
    text = f.read()


def replacer(m: re.Match[str]) -> str:
    title = m.group(1)
    body = m.group(2)
    # Remove up to 4 spaces of indentation
    unindented_body = re.sub(r"^( {1,4})", "", body, flags=re.MULTILINE)
    return f"<details>\n<summary><b>{title}</b></summary>\n\n{unindented_body.strip()}\n\n</details>\n"


# Find the generic tab pattern
new_text: str = re.sub(r"^=== \"([^\"]+)\"\n((?:    .*\n?|\s*\n)*)", replacer, text, flags=re.MULTILINE)

with open("USAGE.md", "w", encoding="utf-8") as f:
    f.write(new_text)

print("Rewrite complete")
