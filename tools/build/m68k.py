"""ColdFire binutils for the make_patch.py scripts: WSL on Windows, native elsewhere.

    bu = m68k.Binutils(tmpdir)
    bu.run("as -mcpu=54418 x.S -o x.o")      # tool name without prefix

Native prefix: $M68K_PREFIX, else the first of m68k-linux-gnu-, m68k-elf- found in PATH.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unpack"))
import eft  # noqa: E402

WSL_BINUTILS = "~/tools/m68k/root"


def _native_prefix() -> str:
    if p := os.environ.get("M68K_PREFIX"):
        return p
    for p in ("m68k-linux-gnu-", "m68k-elf-"):
        if shutil.which(p + "as"):
            return p
    raise SystemExit("ColdFire binutils not found (m68k-linux-gnu-* or m68k-elf-*; or set M68K_PREFIX)")


class Binutils:
    def __init__(self, cwd: Path):
        self.cwd = Path(cwd)
        self.wsl = os.name == "nt"
        self.prefix = "" if self.wsl else _native_prefix()

    def run(self, cmd: str) -> str:
        if self.wsl:
            w = eft.to_wsl_path(self.cwd)
            full = (f"R={WSL_BINUTILS}; export LD_LIBRARY_PATH=$R/usr/lib/x86_64-linux-gnu; cd {w}; "
                    f"$R/usr/bin/m68k-linux-gnu-{cmd}")
            r = subprocess.run(["wsl.exe", "-e", "bash", "-lc", full], capture_output=True, text=True)
        else:
            full = self.prefix + cmd
            r = subprocess.run(["bash", "-c", full], cwd=self.cwd, capture_output=True, text=True)
        if r.returncode:
            raise SystemExit(f"command failed:\n{full}\n{r.stderr}")
        return r.stdout

    def symbols(self, elf: str) -> dict[str, int]:
        return {p[2]: int(p[0], 16) for p in (l.split() for l in self.run(f"nm {elf}").splitlines())
                if len(p) == 3}
