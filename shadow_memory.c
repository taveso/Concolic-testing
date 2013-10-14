#include "shadow_memory.h"
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_libcbase.h"      // VG_(memset)
#include "pub_tool_mallocfree.h"    // VG_(malloc) VG_(free)
#include "pub_tool_libcassert.h"    // VG_(tool_panic)

//
//  SHADOW
//

void init_shadow_memory(void)
{
    VG_(memset)(MemoryMap, 0, sizeof(Chunk*)*MMAP_SIZE);

    VG_(memset)(registers8, 0, sizeof(Shadow)*9);
    VG_(memset)(registers16, 0, sizeof(Shadow)*9);
    VG_(memset)(registers32, 0, sizeof(Shadow)*9);

    VG_(memset)(shadowTempArray, 0, sizeof(Shadow)*MAX_TEMPORARIES);
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
//  SYMBOLIC EXECUTION
//

void update_dep(char** buffer, char* dep)
{
    if (*buffer == NULL) {
        *buffer = VG_(malloc)("", DEP_MAX_SIZE);
    }

    VG_(snprintf)(*buffer, DEP_MAX_SIZE, "%s", dep);

    VG_(printf)("update_dep(): buffer: %s\n", *buffer);
}

void free_dep(char** buffer)
{
    if (*buffer != NULL) {
        VG_(free)(*buffer);
        *buffer = NULL;
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

//
//  MEMORY TAINT ANALYSIS
//

void flip_byte(UInt addr)
{
    Chunk* chunk = get_chunk_for_writing(addr);

    chunk->bytes[addr & 0xffff].tainted ^= 1;

    // VG_(printf)("flip_byte(0x%08x): %d -> %d\n", addr, chunk->bytes[addr & 0xffff].tainted^1, chunk->bytes[addr & 0xffff].tainted);
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
//  MEMORY SYMBOLIC EXECUTION
//

char* get_memory_dep(UInt addr)
{
    Chunk* chunk = get_chunk_for_reading(addr);

    if (chunk == NULL)
        return NULL;

    return chunk->bytes[addr & 0xffff].buffer;
}

void update_byte_dep(UInt addr, char* dep)
{
    Chunk* chunk = get_chunk_for_writing(addr);

    update_dep(&chunk->bytes[addr & 0xffff].buffer, dep);
}

void update_word_dep(UInt addr, char* dep)
{
    update_byte_dep(addr, dep);
    update_byte_dep(addr+1, dep);
}

void update_dword_dep(UInt addr, char* dep)
{
    update_word_dep(addr, dep);
    update_word_dep(addr+2, dep);
}

void update_qword_dep(UInt addr, char* dep)
{
    update_dword_dep(addr, dep);
    update_dword_dep(addr+4, dep);
}

void update_dqword_dep(UInt addr, char* dep)
{
    update_dword_dep(addr, dep);
    update_dword_dep(addr+8, dep);
}

void update_memory_dep(UInt addr, UInt size, char* dep)
{
    switch (size)
    {
        case 1:
            update_byte_dep(addr, dep);
            break;
        case 2:
            update_word_dep(addr, dep);
            break;
        case 4:
            update_dword_dep(addr, dep);
            break;
        case 8:
            update_qword_dep(addr, dep);
            break;
        case 16:
            update_dqword_dep(addr, dep);
            break;
        default:
            VG_(tool_panic)("update_memory_dep");
    }
}

void free_byte_dep(UInt addr)
{
    Chunk* chunk = get_chunk_for_reading(addr);

    if (chunk == NULL)
        return;

    free_dep(&chunk->bytes[addr & 0xffff].buffer);
}

void free_word_dep(UInt addr)
{
    free_byte_dep(addr);
    free_byte_dep(addr+1);
}

void free_dword_dep(UInt addr)
{
    free_word_dep(addr);
    free_word_dep(addr+2);
}

void free_qword_dep(UInt addr)
{
    free_dword_dep(addr);
    free_dword_dep(addr+4);
}

void free_dqword_dep(UInt addr)
{
    free_qword_dep(addr);
    free_qword_dep(addr+8);
}

void free_memory_dep(UInt addr, UInt size)
{
    switch (size)
    {
        case 1:
            free_byte_dep(addr);
            break;
        case 2:
            free_word_dep(addr);
            break;
        case 4:
            free_dword_dep(addr);
            break;
        case 8:
            free_qword_dep(addr);
            break;
        case 16:
            free_dqword_dep(addr);
            break;
        default:
            VG_(tool_panic)("free_memory_dep");
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

//
//  REGISTERS TAINT ANALYSIS
//

void flip_register8(Register reg)
{
    registers8[reg].tainted ^= 1;
}

void flip_register16(Register reg)
{
    registers16[reg].tainted ^= 1;

    // EAX ECX EDX EBX
    if (reg < 4)
    {
        registers8[reg].tainted = registers16[reg].tainted;     // low-order byte
        registers8[reg+4].tainted = registers16[reg].tainted;   // high-order byte
    }
}

void flip_register32(Register reg)
{
    registers32[reg].tainted ^= 1;

    registers16[reg].tainted = registers32[reg].tainted;

    // EAX ECX EDX EBX
    if (reg < 4)
    {
        registers8[reg].tainted = registers32[reg].tainted;     // low-order byte
        registers8[reg+4].tainted = registers32[reg].tainted;   // high-order byte
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
//  REGISTERS SYMBOLIC EXECUTION
//

char* get_reg_dep(UInt offset, UInt size)
{
    Register reg = get_reg_from_offset(offset);

    if (reg == REG_INVALID)
        return NULL;

    switch (size)
    {
        case 1:
            return registers8[reg].buffer;
        case 2:
            return registers16[reg].buffer;
        case 4:
            return registers32[reg].buffer;
        default:
            VG_(tool_panic)("get_reg_dep");
    }
}

void update_register8_dep(Register reg, char* dep)
{
    update_dep(&registers8[reg].buffer, dep);
}

void update_register16_dep(Register reg, char* dep)
{
    update_dep(&registers16[reg].buffer, dep);

    // EAX ECX EDX EBX
    if (reg < 4)
    {
        update_register8_dep(reg, dep);      // low-order byte
        update_register8_dep(reg+4, dep);    // high-order byte
    }
}

void update_register32_dep(Register reg, char* dep)
{
    update_dep(&registers32[reg].buffer, dep);

    update_register16_dep(reg, dep);
}

void update_register_dep(UInt offset, UInt size, char* dep)
{
    Register reg = get_reg_from_offset(offset);

    if (reg == REG_INVALID)
        return;

    switch (size)
    {
        case 1:
            update_register8_dep(reg, dep);
            break;
        case 2:
            update_register16_dep(reg, dep);
            break;
        case 4:
            update_register32_dep(reg, dep);
            break;
        default:
            VG_(tool_panic)("update_register_dep");
    }
}

void free_register8_dep(Register reg)
{
    free_dep(&registers8[reg].buffer);
}

void free_register16_dep(Register reg)
{
    free_dep(&registers16[reg].buffer);

    // EAX ECX EDX EBX
    if (reg < 4)
    {
        free_register8_dep(reg);      // low-order byte
        free_register8_dep(reg+4);    // high-order byte
    }
}

void free_register32_dep(Register reg)
{
    free_dep(&registers32[reg].buffer);

    free_register16_dep(reg);
}

void free_register_dep(UInt offset, UInt size)
{
    Register reg = get_reg_from_offset(offset);

    if (reg == REG_INVALID)
        return;

    switch (size)
    {
        case 1:
            free_register8_dep(reg);
            break;
        case 2:
            free_register16_dep(reg);
            break;
        case 4:
            free_register32_dep(reg);
            break;
        default:
            VG_(tool_panic)("free_register_dep");
    }
}

//
//  TEMPORARIES TAINT ANALYSIS
//

void flip_temporary(IRTemp tmp)
{
    tl_assert(tmp < MAX_TEMPORARIES);

    shadowTempArray[tmp].tainted ^= 1;

    // VG_(printf)("flip_temporary(%u): %d -> %d\n", tmp, shadowTempArray[tmp].tainted^1, shadowTempArray[tmp].tainted);
}

//
//  TEMPORARIES SYMBOLIC EXECUTION
//

char* get_temporary_dep(IRTemp tmp)
{
    tl_assert(tmp < MAX_TEMPORARIES);

    return shadowTempArray[tmp].buffer;
}

void update_temporary_dep(IRTemp tmp, char* dep)
{
    tl_assert(tmp < MAX_TEMPORARIES);

    update_dep(&shadowTempArray[tmp].buffer, dep);
}

void free_temporary_dep(IRTemp tmp)
{
    tl_assert(tmp < MAX_TEMPORARIES);

    free_dep(&shadowTempArray[tmp].buffer);
}
