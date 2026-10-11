"""Genera mods/modarea/patch.json: rilocatore dell'area mod (vedi modarea.S).

    python mods/modarea/make_patch.py [--os 1.42]   # binutils m68k (WSL o nativi, tools/build/m68k.py)

Le mod che usano l'area mod dichiarano "requires": ["modarea"], si collegano a RAM + offset e
mettono il loro codice in una patch accodata ("append") a IMG + offset.
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
CODE_OFF = 0x640                        # nello spazio libero dell'immagine (dopo splash e dual-mono)
HOOK = 0x4000_04B2
HOOK_ORIG = "4feffff048d700f0"          # lea -16(sp),sp ; movem.l d4-d7,(sp)
RAM, SIZE = 0x4600_0000, 0x10000


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--os", default="1.41", choices=osver.versions())
    os_ = ap.parse_args().os
    lay = osver.LAYOUT[os_]
    IMG = lay["img"]
    CODE_BASE, FREE_END = lay["free"][0] + CODE_OFF, lay["free"][1]
    stock = REPO / "firmware" / f"Syntakt_OS{os_}.syx"
    sec3 = eft.unpack(stock, REPO / "unpacked" / stock.stem, ids=[3])[3].read_bytes()
    if LOAD + len(sec3) > IMG:
        raise SystemExit("l'immagine stock arriva oltre IMG")
    with tempfile.TemporaryDirectory(prefix="modarea-") as tmp:
        tmp = Path(tmp)
        shutil.copy(HERE / "modarea.S", tmp / "modarea.S")
        bu = m68k.Binutils(tmp)
        bu.run(f"as -mcpu=54418 --defsym IMG={IMG} modarea.S -o m.o")
        bu.run(f"ld -N -Ttext={CODE_BASE:#x} -o m.elf m.o")
        bu.run("objcopy -O binary m.elf m.bin")
        blob = (tmp / "m.bin").read_bytes()
    end = CODE_BASE + len(blob)
    if end > FREE_END or any(sec3[CODE_BASE - LOAD:end - LOAD]):
        raise SystemExit("spazio libero insufficiente o non a zero")
    if sec3[HOOK - LOAD:HOOK - LOAD + 8].hex() != HOOK_ORIG:
        raise SystemExit("i byte del punto d'aggancio non sono quelli attesi")
    jmp = struct.pack(">HIH", 0x4EF9, CODE_BASE, 0x4E71)      # jmp modarea_reloc.l ; nop
    spec = {
        "name": "modarea", "os": os_,
        "description": f"Area mod: all'avvio decomprime (SHLZ) le mod accodate alla sezione 3 ({IMG:#x}) "
                       f"in RAM a {RAM:#x} ({SIZE // 1024} KB, resto azzerato), prima dell'azzeramento del BSS.",
        "generated_by": "mods/modarea/make_patch.py",
        "layout": {"img": f"{IMG:#010x}", "ram": f"{RAM:#010x}", "size": f"{SIZE:#x}", "compress": "shlz"},
        "patches": [
            {"section": 3, "addr": f"{CODE_BASE:#010X}", "len": len(blob),
             "expect_sha256": sha(sec3[CODE_BASE - LOAD:end - LOAD]), "hex": blob.hex(),
             "what": "modarea_reloc: decomprime IMG -> RAM, azzera il resto, istruzioni sostituite, jmp 0x400004BA"},
            {"section": 3, "addr": f"{HOOK:#010X}", "len": 8,
             "expect_sha256": sha(sec3[HOOK - LOAD:HOOK - LOAD + 8]), "hex": jmp.hex(),
             "what": "inizio dell'azzeramento del BSS: jmp modarea_reloc ; nop"},
        ],
    }
    (HERE / osver.patch_file(os_)).write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"patch.json: rilocatore {len(blob)} B a {CODE_BASE:#x}; aggancio {jmp.hex()} a {HOOK:#x}")


if __name__ == "__main__":
    main()
