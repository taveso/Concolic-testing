#include "shadow_memory.h"
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_libcbase.h"      // VG_(memset)
#include "pub_tool_mallocfree.h"    // VG_(malloc) VG_(free)

void init_shadow_memory(void)
{
    VG_(memset)(MemoryMap, 0, sizeof(Chunk*)*MMAP_SIZE);

    VG_(memset)(registers8, 0, 9);
    VG_(memset)(registers16, 0, 9);
    VG_(memset)(registers32, 0, 9);

    VG_(memset)(g_ShadowTempArray, 0, MAX_TEMPORARIES);
}

void destroy_shadow_memory(void)
{
    int i;

    for (i = 0; i < MMAP_SIZE; i++)
    {
        if (MemoryMap[i] != NULL) {
            VG_(free)(MemoryMap[i]);
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
        VG_(memset)(MemoryMap[x], 0, sizeof(Chunk));
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
    flip_word(addr);
    flip_word(addr+2);
}

void flip_qword(UInt addr)
{
    flip_dword(addr);
    flip_dword(addr+4);
}

void flip_dqword(UInt addr)
{
    flip_qword(addr);
    flip_qword(addr+8);
}

void flip_memory(UInt addr, UInt size)
{
    switch (size)
    {
        case 1:
            flip_byte(addr);
            break;
        case 2:
            flip_word(addr);
            break;
        case 4:
            flip_dword(addr);
            break;
        case 8:
            flip_qword(addr);
            break;
        case 16:
            flip_dqword(addr);
            break;
        default:
            VG_(tool_panic)("flip_memory");
    }
}

//
//  REGISTERS
//

Register get_reg_from_offset(UInt offset)
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

void flip_register(UInt offset, UInt size)
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
        default:
            VG_(tool_panic)("flip_register");
    }
}

//
//  TEMPORARIES
//

char shadow_tmp_exists(IRTemp tmp)
{
    return MAX_TEMPORARIES > tmp;
}

void flip_temporary(IRTemp tmp)
{
    if (shadow_tmp_exists(tmp))
    {
        g_ShadowTempArray[tmp] ^= 1;

        VG_(printf)("flip_temporary(%u): %d -> %d\n", tmp, g_ShadowTempArray[tmp]^1, g_ShadowTempArray[tmp]);
    }
    else
        VG_(tool_panic)("flip_temporary");
}
