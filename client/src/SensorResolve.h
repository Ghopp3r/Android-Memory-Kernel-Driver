// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstdint>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct ElfMap {
    const uint8_t* base = nullptr;
    size_t size = 0;
    ~ElfMap() { if (base) ::munmap(const_cast<uint8_t*>(base), size); }
};

// 0 when vaddr doesn't sit in any PT_LOAD — never assume st_value == file offset.
inline uint64_t ElfTextOffset(const Elf64_Ehdr* eh, const uint8_t* base, uint64_t vaddr) {
    auto phdrs = reinterpret_cast<const Elf64_Phdr*>(base + eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        const Elf64_Phdr& p = phdrs[i];
        if (p.p_type == PT_LOAD && vaddr >= p.p_vaddr && vaddr < p.p_vaddr + p.p_memsz)
            return vaddr - p.p_vaddr + p.p_offset;
    }
    return 0;
}

inline uint64_t GetSymbolOffset(const char* path, const char* const* candidates, int count, const char** picked) {
    if (picked) *picked = nullptr;
    int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st;
    if (::fstat(fd, &st) < 0 || st.st_size <= static_cast<off_t>(sizeof(Elf64_Ehdr))) {
        ::close(fd);
        return 0;
    }
    const size_t fileSize = static_cast<size_t>(st.st_size);
    void* raw = ::mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);
    if (raw == MAP_FAILED) return 0;
    ElfMap m{static_cast<const uint8_t*>(raw), fileSize};
    auto eh = reinterpret_cast<const Elf64_Ehdr*>(m.base);
    if (std::memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return 0;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return 0;
    if (eh->e_machine != EM_AARCH64) return 0;
    if (eh->e_shentsize != sizeof(Elf64_Shdr)) return 0;
    if (eh->e_phentsize != sizeof(Elf64_Phdr)) return 0;
    if (eh->e_shoff + static_cast<uint64_t>(eh->e_shnum) * sizeof(Elf64_Shdr) > fileSize) return 0;
    if (eh->e_phoff + static_cast<uint64_t>(eh->e_phnum) * sizeof(Elf64_Phdr) > fileSize) return 0;
    auto shdrs = reinterpret_cast<const Elf64_Shdr*>(m.base + eh->e_shoff);
    const Elf64_Shdr* dynsym = nullptr;
    const Elf64_Shdr* dynstr = nullptr;
    for (uint16_t i = 0; i < eh->e_shnum; ++i) {
        if (shdrs[i].sh_type == SHT_DYNSYM) {
            dynsym = &shdrs[i];
            if (shdrs[i].sh_link < eh->e_shnum) dynstr = &shdrs[shdrs[i].sh_link];
            break;
        }
    }
    if (!dynsym || !dynstr) return 0;
    if (dynsym->sh_entsize != sizeof(Elf64_Sym)) return 0;
    if (dynsym->sh_offset + dynsym->sh_size > fileSize) return 0;
    if (dynstr->sh_offset + dynstr->sh_size > fileSize) return 0;
    auto syms = reinterpret_cast<const Elf64_Sym*>(m.base + dynsym->sh_offset);
    auto strs = reinterpret_cast<const char*>(m.base + dynstr->sh_offset);
    const size_t nsyms = dynsym->sh_size / sizeof(Elf64_Sym);
    const uint64_t strsLen = dynstr->sh_size;
    for (int c = 0; c < count; ++c) {
        const char* want = candidates[c];
        const size_t wantLen = std::strlen(want);
        if (wantLen + 1 > strsLen) continue;
        for (size_t s = 1; s < nsyms; ++s) {
            if (ELF64_ST_TYPE(syms[s].st_info) != STT_FUNC || syms[s].st_size == 0) continue;
            const uint64_t nameOff = syms[s].st_name;
            if (nameOff + wantLen + 1 > strsLen) continue;
            const char* name = strs + nameOff;
            if (std::strncmp(name, want, wantLen) != 0 || name[wantLen] != '\0') continue;
            uint64_t off = ElfTextOffset(eh, m.base, syms[s].st_value);
            if (!off) continue;
            if (picked) *picked = want;
            return off;
        }
    }
    return 0;
}
