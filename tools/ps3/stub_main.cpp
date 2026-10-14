// Minimal runtime stubs: link the recompiled code with this file to check that the whole
// translation builds and links before writing a real PS3 runtime.
#include "ppc_config.h"
#include <ppc_context.h>
#include <cstdio>

void ps3_syscall(PPCContext& ctx, uint8_t* base) { std::printf("syscall %llu\n", (unsigned long long)ctx.r11.u64); }
uint64_t ps3_timebase() { return 0; }
int main() { std::puts("link ok"); return 0; }
