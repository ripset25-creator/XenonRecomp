// Count which PowerPC instructions a PS3 EBOOT uses and how often, using XenonRecomp's
// disassembler. Useful to check what a new game needs before recompiling it.
//
// Usage: instruction_coverage EBOOT.elf > instructions.txt
// Output: one line per mnemonic: name, XenonRecomp instruction id, count.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <map>
#include <string>
#include "disasm.h"

static uint64_t be64(const uint8_t* p) { uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | p[i]; return v; }
static uint32_t be32(const uint8_t* p) { return (uint32_t(p[0]) << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }
static uint16_t be16(const uint8_t* p) { return uint16_t((p[0] << 8) | p[1]); }

int main(int argc, char** argv)
{
    if (argc < 2) { std::fprintf(stderr, "usage: %s EBOOT.elf\n", argv[0]); return 1; }
    FILE* f = std::fopen(argv[1], "rb");
    if (!f) { std::perror(argv[1]); return 1; }
    std::fseek(f, 0, SEEK_END); long n = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> d(n);
    std::fread(d.data(), 1, n, f);
    std::fclose(f);
    if (n < 64 || std::memcmp(d.data(), "\x7f" "ELF", 4) != 0 || d[4] != 2 || d[5] != 2)
    {
        std::fprintf(stderr, "expected a big-endian ELF64 (decrypted EBOOT)\n");
        return 1;
    }

    const uint64_t shoff = be64(&d[0x28]);
    const uint16_t shentsize = be16(&d[0x3A]), shnum = be16(&d[0x3C]);
    std::map<std::string, long> count;
    std::map<std::string, int> ids;
    long undecoded = 0;
    for (uint16_t s = 0; s < shnum; s++)
    {
        const uint8_t* sh = &d[shoff + uint64_t(s) * shentsize];
        const uint32_t type = be32(sh + 4);
        const uint64_t flags = be64(sh + 8), addr = be64(sh + 16), off = be64(sh + 24), size = be64(sh + 32);
        if (type != 1 /* SHT_PROGBITS */ || !(flags & 4 /* SHF_EXECINSTR */))
            continue;
        for (uint64_t a = 0; a + 4 <= size; a += 4)
        {
            ppc_insn in;
            if (!ppc::Disassemble(d.data() + off + a, 4, addr + a, in) || !in.opcode) { undecoded++; continue; }
            count[in.opcode->name]++;
            ids[in.opcode->name] = in.opcode->id;
        }
    }
    for (auto& k : count)
        std::printf("%s %d %ld\n", k.first.c_str(), ids[k.first], k.second);
    std::fprintf(stderr, "undecoded %ld\n", undecoded);
}
