"""
Syntax-checks the studio's single page: pulls out its script and asks Node to parse it, so a stray character in a 5,000-line page is caught before it ships.

    python .github/scripts/check_studio_js.py studio/index.html
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    page = Path(sys.argv[1] if len(sys.argv) > 1 else "studio/index.html")
    html = page.read_text(encoding="utf-8")
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    if not scripts:
        print(f"No inline script found in {page}.")
        return 1
    code = max(scripts, key=len)
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "studio.js"
        f.write_text(code, encoding="utf-8")
        r = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr)
        print(f"{page}: the script does not parse.")
        return 1
    print(f"{page}: the script parses ({len(code):,} characters).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
