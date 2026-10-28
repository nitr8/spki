#!/usr/bin/env python3
"""Convert the Markdown docs to simple standalone HTML pages (run at image build time)."""
import html
import re
import sys
from pathlib import Path

import markdown

CSS = """
:root{color-scheme:dark light;--bg:#080b16;--text:#eef3ff;--muted:#a9b4d0;--accent:#7dd3fc;--line:rgba(255,255,255,.14);--code:rgba(255,255,255,.07)}
@media (prefers-color-scheme:light){:root{--bg:#f7f9fc;--text:#16203a;--muted:#4b5878;--accent:#0369a1;--line:rgba(0,0,0,.15);--code:rgba(0,0,0,.06)}}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:60rem;margin:0 auto;padding:24px 16px 64px}
nav{font-size:14px;color:var(--muted);margin-bottom:8px}
a{color:var(--accent)}
h1,h2,h3{line-height:1.25;margin-top:2em}h1{margin-top:.5em}
h2{border-bottom:1px solid var(--line);padding-bottom:.25em}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
code{background:var(--code);padding:.1em .35em;border-radius:5px}
pre{background:var(--code);border:1px solid var(--line);border-radius:10px;padding:12px 14px;overflow-x:auto}
pre code{background:none;padding:0}
table{border-collapse:collapse;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
blockquote{margin:1em 0;padding:.1em 1em;border-left:4px solid var(--accent);background:var(--code)}
"""

NAV = {
    "docs/pki.html": "PKI",
    "docs/dashboard.html": "Dashboard",
    "docs/container.html": "Container",
}

def convert(src: Path, out: Path, rel_out: str, root: str) -> None:
    text = src.read_text(encoding="utf-8")
    body = markdown.markdown(text, extensions=["fenced_code", "tables", "sane_lists"])
    # Relative links between the docs: foo.md -> foo.html (leave http(s) links alone).
    body = re.sub(r'href="((?!https?:|/|#)[^"]*?)\.md(#[^"]*)?"', r'href="\1.html\2"', body)
    m = re.search(r"<h1>(.*?)</h1>", body, re.S)
    title = html.unescape(re.sub(r"<[^>]+>", "", m.group(1))) if m else src.stem
    prefix = "../" * rel_out.count("/")
    nav = " · ".join(
        f'<a href="{prefix}{path}">{label}</a>' for path, label in NAV.items()
    )
    page = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body><main>"
        f'<nav><a href="{prefix}">&larr; Dashboard</a> · {nav}</nav>{body}</main></body></html>'
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding="utf-8")


def main() -> None:
    src_root, out_root = Path(sys.argv[1]), Path(sys.argv[2])
    jobs = [(f"docs/{p.name}", f"docs/{p.stem}.html") for p in sorted((src_root / "docs").glob("*.md"))]
    for src, dst in jobs:
        convert(src_root / src, out_root / dst, dst, str(out_root))
        print("built", dst)

if __name__ == "__main__":
    main()