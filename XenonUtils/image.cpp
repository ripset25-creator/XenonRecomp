#include "image.h"
#include "elf.h"
#include "xex.h"
#include <cassert>
#include <cstring>
#include <string>


void Image::Map(const std::string_view& name, size_t base, uint32_t size, uint8_t flags, uint8_t* data)
{
    sections.insert({ std::string(name), this->base + base,
        size, static_cast<SectionFlags>(flags), data });
}

const void* Image::Find(size_t address) const
{
    const auto section = std::prev(sections.upper_bound(address));
    return section->data + (address - section->base);
}

const Section* Image::Find(const std::string_view& name) const
{
    for (const auto& section : sections)
    {
        if (section.name == name)
        {
            return &section;
        }
    }

    return nullptr;
}

Image Image::ParseImage(const uint8_t* data, size_t size)
{
    if (data[0] == ELFMAG0 && data[1] == ELFMAG1 && data[2] == ELFMAG2 && data[3] == ELFMAG3)
    {
        return ElfLoadImage(data, size);
    }
    else if (data[0] == 'X' && data[1] == 'E' && data[2] == 'X' && data[3] == '2')
    {
        return Xex2LoadImage(data, size);
    }

    return {};
}

// PS3: big-endian ELF64 (decrypted EBOOT). Pointers are 32-bit, as on Xbox 360.
static Image Elf64LoadImage(const uint8_t* data, size_t size)
{
    const auto* header = (elf64_hdr*)data;

    Image image{};
    image.size = size;
    image.data = std::make_unique<uint8_t[]>(size);
    memcpy(image.data.get(), data, size);

    // e_entry points to an .opd descriptor (code address, TOC)
    const uint32_t entryDesc = (uint32_t)ByteSwap(header->e_entry);

    const auto numSections = ByteSwap(header->e_shnum);
    const auto numpSections = ByteSwap(header->e_phnum);
    const auto* sections = (elf64_shdr*)(data + ByteSwap(header->e_shoff));
    const auto* psections = (elf64_phdr*)(data + ByteSwap(header->e_phoff));

    for (size_t i = 0; i < numpSections; i++)
    {
        if (psections[i].p_type == ByteSwap((Elf64_Word)PT_LOAD))
        {
            image.base = (size_t)ByteSwap(psections[i].p_vaddr);
            break;
        }
    }

    // In-memory size (including .bss): the runtime's function table goes right after it,
    // so it must not overlap uninitialized globals.
    {
        uint64_t end = 0;
        for (size_t i = 0; i < numpSections; i++)
        {
            if (psections[i].p_type != ByteSwap((Elf64_Word)PT_LOAD)) continue;
            uint64_t va = ByteSwap(psections[i].p_vaddr), ms = ByteSwap(psections[i].p_memsz);
            if (ms && va + ms > end) end = va + ms;
        }
        if (end > image.base)
            image.size = (size_t)((end - image.base + 0xFFFF) & ~0xFFFFull);
    }

    // Read a word by virtual address (to resolve the entry descriptor and the TOC)
    auto readVA = [&](uint32_t va) -> uint32_t
    {
        for (size_t i = 0; i < numSections; i++)
        {
            const auto& s = sections[i];
            uint64_t a = ByteSwap(s.sh_addr), sz = ByteSwap(s.sh_size);
            if (a && va >= a && va + 4 <= a + sz && s.sh_type != ByteSwap((Elf64_Word)SHT_NOBITS))
                return ByteSwap(*(uint32_t*)(data + ByteSwap(s.sh_offset) + (va - a)));
        }
        return 0;
    };
    const uint32_t entryCode = readVA(entryDesc);
    const uint32_t toc = readVA(entryDesc + 4);
    image.entry_point = entryCode;

    // EBOOT section names are stripped, so sections are named by their contents.
    for (size_t i = 0; i < numSections; i++)
    {
        const auto& section = sections[i];
        const uint64_t addr = ByteSwap(section.sh_addr);
        if (addr == 0 || section.sh_type == ByteSwap((Elf64_Word)SHT_NOBITS))
            continue;

        uint8_t flags = SectionFlags_Data;
        if (ByteSwap(section.sh_flags) & SHF_EXECINSTR)
            flags = SectionFlags_Code;

        const auto sz = (uint32_t)ByteSwap(section.sh_size);
        const uint8_t* sdata = image.data.get() + ByteSwap(section.sh_offset);

        std::string name = ".sec" + std::to_string(i);
        // .opd = (code, TOC) pairs that carry the entry point's TOC
        if (!(flags & SectionFlags_Code) && sz >= 16 && toc != 0 &&
            ByteSwap(*(uint32_t*)(sdata + 4)) == toc && ByteSwap(*(uint32_t*)(sdata + 12)) == toc)
            name = ".opd";

        image.Map(name, addr - image.base, sz, flags, (uint8_t*)sdata);
    }

    return image;
}

Image ElfLoadImage(const uint8_t* data, size_t size)
{
    if (data[EI_CLASS] == ELFCLASS64)
        return Elf64LoadImage(data, size);

    const auto* header = (elf32_hdr*)data;
    assert(header->e_ident[EI_DATA] == 2);

    Image image{};
    image.size = size;
    image.data = std::make_unique<uint8_t[]>(size);
    image.entry_point = ByteSwap(header->e_entry);
    memcpy(image.data.get(), data, size);

    auto stringTableIndex = ByteSwap(header->e_shstrndx);

    const auto numSections = ByteSwap(header->e_shnum);
    const auto numpSections = ByteSwap(header->e_phnum);

    const auto* sections = (elf32_shdr*)(data + ByteSwap(header->e_shoff));
    const auto* psections = (elf32_phdr*)(data + ByteSwap(header->e_phoff));

    for (size_t i = 0; i < numpSections; i++)
    {
        if (psections[i].p_type == ByteSwap((Elf32_Word)PT_LOAD))
        {
            image.base = ByteSwap(psections[i].p_vaddr);
            break;
        }
    }

    auto* stringTable = reinterpret_cast<const char*>(data + ByteSwap(sections[stringTableIndex].sh_offset));

    for (size_t i = 0; i < numSections; i++)
    {
        const auto& section = sections[i];
        if (section.sh_type == 0)
        {
            continue;
        }

        uint8_t flags{};

        if (section.sh_flags & ByteSwap(SHF_EXECINSTR))
        {
            flags |= SectionFlags_Code;
        }

        auto* name = section.sh_name != 0 ? stringTable + ByteSwap(section.sh_name) : nullptr;
        const auto rva = ByteSwap(section.sh_addr) - image.base;
        const auto size = ByteSwap(section.sh_size);

        image.Map(name, rva, size, flags, image.data.get() + ByteSwap(section.sh_offset));
    }

    return image;
}
