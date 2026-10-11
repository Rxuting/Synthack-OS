"""Supported stock OS versions and how their addresses differ from 1.41.

Mod sources are written with OS 1.41 addresses. For another version, `code()` and `bss()` move
an address to where the same code or variable is in that OS. The offsets were found by matching
the original bytes of every patch (hash in patch.json) and the BSS operands of the patched
instructions; tests re-check them on the stock OS.

    from osver import OS, code, bss
"""

from __future__ import annotations

STOCK_SHA256 = {
    "1.41": "8e2488f462c4a5656396a895f113bcd415e9900fa8709340dccf45d4cb9ed19e",
    "1.42": "ded3c59fdb909eb9e2c3307b30a486452c8fa6947b12c14e0ce35a187b7f37c1",
}

# Per version:
#   img        where the (compressed) mod area is appended to section 3 (after the stock image)
#   free       zero fill of section 3 just before the BSS (splash, dual-mono, modarea loader)
#   bss_delta  offset of the BSS variables (0x40339000.. in 1.41) and of the prototypes in it
#   code       (start, end, delta) ranges of 1.41 code/rodata addresses that moved
LAYOUT = {
    "1.41": {"img": 0x4034_8000, "free": (0x4033_8740, 0x4033_9000), "bss_delta": 0, "code": []},
    "1.42": {"img": 0x4034_9000, "free": (0x4033_9730, 0x4033_A000), "bss_delta": 0x1000,
             "code": [(0x4000_0400, 0x4003_0000, 0),         # boot, kit parameters, views
                      (0x4008_C000, 0x400A_6000, 0x78),      # sequencer, audio interrupt, mixer
                      (0x4018_0000, 0x4019_8000, 0x1C4),     # page / parameter-object initializer
                      (0x4022_C000, 0x4023_2000, 0x2A0)]},   # parameter descriptors
}
BSS_START_141, BSS_END_141 = 0x4033_9000, 0x4556_5490


def versions() -> list[str]:
    return list(LAYOUT)


def code(addr: int, os: str) -> int:
    """1.41 code/rodata address -> same place in `os` (error if the range is not mapped)."""
    if os == "1.41":
        return addr
    for lo, hi, d in LAYOUT[os]["code"]:
        if lo <= addr < hi:
            return addr + d
    raise KeyError(f"{addr:#x}: no mapping 1.41 -> {os}")


def bss(addr: int, os: str) -> int:
    """1.41 BSS address (pages, parameter objects, prototypes, globals) -> same variable in `os`."""
    if not BSS_START_141 <= addr < BSS_END_141:
        raise KeyError(f"{addr:#x}: not a 1.41 BSS address")
    return addr + LAYOUT[os]["bss_delta"]


def patch_file(os: str) -> str:
    """patch.json for 1.41 (the reference), patch.<os>.json for the others."""
    return "patch.json" if os == "1.41" else f"patch.{os}.json"
