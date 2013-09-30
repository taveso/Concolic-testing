#include "shadow_memory.h"

void init_shadow_memory(void)
{
    VG_(memset)(MemoryMap, 0, sizeof(Chunk*)*MMAP_SIZE);
}

void destroy_shadow_memory(void)
{
    int i;

    for (i = 0; i < MMAP_SIZE; i++) {
        if (MemoryMap[i] != NULL) {
            VG_(free)("", MemoryMap[i]);
        }
    }
}

//
//  MEMORY
//

Chunk* get_chunk_for_reading(UInt addr)
{
    return MemoryMap[(addr >> 16) & 0xffff];
}

Chunk* get_chunk_for_writing(UInt addr)
{
    UInt x = (addr >> 16) & 0xffff;

    if (MemoryMap[x] == NULL)
    {
        MemoryMap[x] = VG_(malloc)("", sizeof(Chunk));
    }

    return MemoryMap[x];
}

void flip_byte(UInt addr)
{
    Chunk* chunk = get_chunk_for_writing(addr);

    chunk->bytes[addr & 0xffff] ^= 1;
}

void flip_word(UInt addr)
{
    flip_byte(addr);
    flip_byte(addr+1);
}

void flip_dword(UInt addr)
{
    flip_byte(addr);
    flip_byte(addr+1);
    flip_byte(addr+2);
    flip_byte(addr+3);
}

void flip_memory(UInt addr, Int size)
{
    switch (size)
    {
        case 1:
            flip_byte(addr);
        case 2:
            flip_word(addr);
        case 4:
            flip_dword(addr);
    }
}

//
//  REGISTERS
//

Register get_reg_from_offset(Int offset)
{
    switch (offset)
    {
        case 8: return EAX;
        case 12: return ECX;
        case 16: return EDX;
        case 20: return EBX;
        case 24: return ESP;
        case 28: return EBP;
        case 32: return ESI;
        case 36: return EDI;
        case 68: return EIP;
        default: return REG_INVALID;
    }
}

void flip_register8(Register reg)
{
    registers8[reg] ^= 1;
}

void flip_register16(Register reg)
{
    registers16[reg] ^= 1;

    // EAX ECX EDX EBX
    if (reg < 4)
    {
        registers8[reg] = registers16[reg];		// low-order byte
        registers8[reg+4] = registers16[reg];	// high-order byte
    }
}

void flip_register32(Register reg)
{
    registers32[reg] ^= 1;

    registers16[reg] = registers32[reg];

    // EAX ECX EDX EBX
    if (reg < 4)
    {
        registers8[reg] = registers32[reg];		// low-order byte
        registers8[reg+4] = registers32[reg];	// high-order byte
    }
}

void flip_register(Int offset, Int size)
{
    Register reg = get_reg_from_offset(offset);

    if (reg == REG_INVALID)
        return;

    switch (size)
    {
        case 1:
            flip_register8(reg);
            break;
        case 2:
            flip_register16(reg);
            break;
        case 4:
            flip_register32(reg);
            break;
    }
}

//
//  TEMPORARIES
//

char temporary_exists(IRTemp tmp)
{
    TempMapEnt* ent = (TempMapEnt*)VG_(indexXA)(g_TempMap, (Word)tmp);
    return ent != NULL;
}

void flip_temporary(IRTemp tmp)
{
    if (temporary_exists(tmp))
    {
        TempMapEnt* ent = (TempMapEnt*)VG_(indexXA)(g_TempMap, (Word)tmp);
        ent->tainted ^= 1;

        VG_(printf)("flip_temporary(%u): %d -> %d\n", tmp, ent->tainted^1, ent->tainted);
    }
}
