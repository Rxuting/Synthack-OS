"""Genera mods/vparams/patch.json (vedi vparams.S).

    python mods/vparams/make_patch.py [--os 1.42]   # binutils m68k (WSL o nativi, tools/build/m68k.py)

Le mod registrano i loro parametri con una patch accodata a vparams.entry(slot, id, get, set).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path[:0] = [str(REPO / "tools" / "unpack"), str(REPO / "tools" / "build")]
import eft  # noqa: E402
import m68k  # noqa: E402
import osver  # noqa: E402

LOAD = 0x4000_0400
RAM = 0x4600_0000                       # area mod (mods/modarea); immagine a osver.LAYOUT[os]["img"]
CODE = RAM + 0x7E00                     # codice di vparams
VP_TABLE, VP_N = RAM + 0x8000, 32
HOOKS = [(0x4000_D870, "2f02747c222f0008", "vp_kit"),
         (0x4000_D94A, "2f02222f0008", "vp_get"),
         (0x4000_DA32, "2f032f02222f000c", "vp_set")]


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def entry(slot: int, pid: int, get: int, put: int, what: str, os: str = "1.41") -> dict:
    """Patch accodata che registra un parametro virtuale nel posto 'slot' della tabella."""
    if not 0 <= slot < VP_N or not 0 < pid < 505:
        raise ValueError((slot, pid))
    addr = VP_TABLE + 12 * slot
    return {"section": 3, "addr": f"{osver.LAYOUT[os]['img'] + addr - RAM:#010X}", "len": 12, "append": True,
            "hex": struct.pack(">HHII", pid, 0, get, put).hex(), "ram": f"{addr:#010x}",
            "what": f"vparams[{slot}]: id {pid} -> {what}"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--os", default="1.41", choices=osver.versions())
    os_ = ap.parse_args().os
    IMG = osver.LAYOUT[os_]["img"]
    stock = REPO / "firmware" / f"Syntakt_OS{os_}.syx"
    sec3 = eft.unpack(stock, REPO / "unpacked" / stock.stem, ids=[3])[3].read_bytes()
    with tempfile.TemporaryDirectory(prefix="vparams-") as tmp:
        tmp = Path(tmp)
        shutil.copy(HERE / "vparams.S", tmp / "vparams.S")
        bu = m68k.Binutils(tmp)
        bu.run("as -mcpu=54418 vparams.S -o v.o")
        bu.run(f"ld -N -Ttext={CODE:#x} -o v.elf v.o")
        bu.run("objcopy -O binary v.elf v.bin")
        syms = bu.symbols("v.elf")
        blob = (tmp / "v.bin").read_bytes()
    if CODE + len(blob) > VP_TABLE:
        raise SystemExit("codice troppo grande")
    patches = [{"section": 3, "addr": f"{IMG + CODE - RAM:#010X}", "len": len(blob), "append": True,
                "hex": blob.hex(), "ram": f"{CODE:#010x}", "what": "(area mod) vp_kit, vp_get, vp_set"}]
    for addr141, orig, sym in HOOKS:
        addr = osver.code(addr141, os_)
        old = sec3[addr - LOAD:addr - LOAD + len(orig) // 2]
        if old.hex() != orig:
            raise SystemExit(f"{addr:#x}: byte inattesi")
        code = struct.pack(">HI", 0x4EF9, syms[sym]) + (b"\x4e\x71" if len(orig) == 16 else b"")
        patches.append({"section": 3, "addr": f"{addr:#010X}", "len": len(code), "expect_sha256": sha(old),
                        "hex": code.hex(), "what": f"aggancio: jmp {sym}" + (" ; nop" if len(orig) == 16 else "")})
    spec = {"name": "vparams", "os": os_, "requires": ["modarea"],
            "description": "Parametri virtuali delle mod: agganci alle funzioni centrali dei parametri di kit "
                           "e tabella di registrazione in RAM.",
            "generated_by": "mods/vparams/make_patch.py",
            "layout": {"table": f"{VP_TABLE:#010x}", "entries": VP_N},
            "symbols": {k: f"{syms[k]:#010x}" for k in ("vp_kit", "vp_get", "vp_set", "vp_find")},
            "patches": patches}
    (HERE / osver.patch_file(os_)).write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"patch.json: {len(blob)} B a {CODE:#x}; tabella a {VP_TABLE:#x}")


if __name__ == "__main__":
    main()
