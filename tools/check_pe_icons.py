"""Inspect RT_ICON / RT_GROUP_ICON resources in a PE file (verification helper)."""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def read_pe_resources(path: Path):
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise SystemExit(f"{path}: not a PE")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0"
    machine, nsections, _timestamp, _symtab, _nsyms, size_opt, _chars = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32p = magic == 0x20B
    # Data directory index 2 (resource) lives after the windows-specific fields.
    dir_off = opt + (112 if pe32p else 96)
    rsrc_rva, rsrc_size = struct.unpack_from("<II", data, dir_off + 2 * 8)
    sections = []
    sec_off = opt + size_opt
    for i in range(nsections):
        name, vsize, vaddr, rsize, raddr = struct.unpack_from("<8sIIII", data, sec_off + i * 40)[:5]
        sections.append((name.rstrip(b"\0").decode(errors="replace"), vaddr, max(vsize, rsize), raddr, rsize))
    if not rsrc_rva:
        return {"rsrc": None, "sections": sections, "icons": [], "groups": []}
    sec = next((s for s in sections if s[1] <= rsrc_rva < s[1] + s[2]), None)
    if sec is None:
        return {"rsrc": (rsrc_rva, rsrc_size), "sections": sections, "icons": [], "groups": [], "error": "rsrc not in a section"}
    name, vaddr, span, raddr, rsize = sec
    if rsize == 0:
        return {"rsrc": (rsrc_rva, rsrc_size), "sections": sections, "icons": [], "groups": [], "error": "rsrc section has no raw data"}
    base_off = raddr + (rsrc_rva - vaddr)
    limit = min(rsize, len(data) - base_off)
    if limit <= 0:
        return {"rsrc": (rsrc_rva, rsrc_size), "sections": sections, "icons": [], "groups": [], "error": "rsrc raw range outside file"}
    base = data[base_off:base_off + limit]

    def dir_at(off):
        chars, ts, mj, mn, nnamed, nid = struct.unpack_from("<IIHHHH", base, off)
        return off + 16, nnamed, nid

    icons, groups = [], []
    root_entries, rn, ri = dir_at(0)
    for i in range(rn + ri):
        name, target = struct.unpack_from("<II", base, root_entries + i * 8)
        if name & 0x80000000 or not target & 0x80000000:
            continue
        type_id = name
        sub_entries, sn, si = dir_at(target & 0x7FFFFFFF)
        for j in range(sn + si):
            ename, etarget = struct.unpack_from("<II", base, sub_entries + j * 8)
            if not etarget & 0x80000000:
                continue
            lang_entries, ln, li = dir_at(etarget & 0x7FFFFFFF)
            for k in range(ln + li):
                lname, ltarget = struct.unpack_from("<II", base, lang_entries + k * 8)
                if ltarget & 0x80000000:
                    continue
                doff, dsize, _, _ = struct.unpack_from("<IIII", base, ltarget)
                entry = (type_id, ename & 0x7FFFFFFF if not ename & 0x80000000 else ename & 0x7FFFFFFF,
                         lname & 0x7FFFFFFF, doff, dsize)
                if type_id == 3:
                    icons.append(entry)
                elif type_id == 14:
                    groups.append(entry)
    return {"rsrc": (rsrc_rva, rsrc_size), "sections": sections, "icons": icons, "groups": groups}


def main():
    for arg in sys.argv[1:]:
        info = read_pe_resources(Path(arg))
        print(f"== {arg}")
        print(f"   rsrc={info['rsrc']} icons={len(info['icons'])} groups={len(info['groups'])}")
        for e in info["icons"]:
            print(f"   RT_ICON id={e[1]} lang=0x{e[2]:04X} rva=0x{e[3]:08X} size={e[4]}")
        for e in info["groups"]:
            print(f"   RT_GROUP_ICON id={e[1]} lang=0x{e[2]:04X} rva=0x{e[3]:08X} size={e[4]}")


if __name__ == "__main__":
    main()
