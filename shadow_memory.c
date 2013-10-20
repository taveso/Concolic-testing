#include "shadow_memory.h"
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_libcbase.h"      // VG_(memset)
#include "pub_tool_mallocfree.h"    // VG_(malloc) VG_(free)
#include "pub_tool_libcassert.h"    // VG_(tool_panic)

void init_shadow_memory(void)
{
    VG_(memset)(MemoryMap, 0, sizeof(Chunk*)*MMAP_SIZE);

    VG_(memset)(registers8, 0, sizeof(Shadow)*TOTAL_SHADOW_REGISTERS);
    VG_(memset)(registers16, 0, sizeof(Shadow)*TOTAL_SHADOW_REGISTERS);
    VG_(memset)(registers32, 0, sizeof(Shadow)*TOTAL_SHADOW_REGISTERS);

    VG_(memset)(shadowTempArray, 0, sizeof(Shadow)*MAX_TEMPORARIES);
}

void destroy_shadow_memory(void)
{
    int i, j;

    for (i = 0; i < MMAP_SIZE; i++)
    {
        if (MemoryMap[i] != NULL)
        {
            for (j = 0; j < CHUNK_SIZE; j++)
            {
                if (MemoryMap[i]->bytes[j].buffer != NULL) {
                    VG_(free)(MemoryMap[i]->bytes[j].buffer);
                }
            }

            VG_(free)(MemoryMap[i]);
        }
    }
}

//
//  SYMBOLIC EXECUTION
//

void update_dep(Shadow* shadow, char* dep, unsigned int dep_size)
{
    if (shadow->buffer == NULL) {
        shadow->buffer = VG_(malloc)("", DEP_MAX_SIZE);
    }
    VG_(snprintf)(shadow->buffer, DEP_MAX_SIZE, "%s", dep);

    shadow->size = dep_size;

    shadow->tainted = 1;

    VG_(printf)("update_dep(): %s (%u)\n", shadow->buffer, shadow->size);
}

void free_dep(Shadow* shadow)
{
    if (shadow->buffer != NULL)
    {
        VG_(free)(shadow->buffer);
        shadow->buffer = NULL;
    }

    shadow->size = 0;

    shadow->tainted = 0;
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

Shadow* get_byte_shadow(UInt addr)
{
    Chunk* chunk = get_chunk_for_reading(addr);

    if (chunk == NULL)
        return NULL;

    return &chunk->bytes[addr & 0xffff];
}

char* get_memory_dep(UInt addr, UInt size, char* dep)
{
    int i;
    Shadow* shadow;

#define LOL    128

    for (i = 0; i < LOL/8; i++)
    {
        shadow = get_byte_shadow(addr-i);

        if (shadow == NULL || shadow->buffer == NULL)
            continue;

        if (size == 8)
        {
            switch (shadow->size)
            {
                case 8:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_SIZE, "%s", shadow->buffer); }
                    break;
                case 16:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_SIZE, "16to8_(And16_(%s, 0x00ff))", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_SIZE, "16to8_(And16_(%s, 0xff00))", shadow->buffer); }
                    break;
                case 32:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to8_(And32_(%s, 0x000000ff))", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to8_(And32_(%s, 0x0000ff00))", shadow->buffer); }
                    else if (i == 2) { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to8_(And32_(%s, 0x00ff0000))", shadow->buffer); }
                    else if (i == 3) { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to8_(And32_(%s, 0xff000000))", shadow->buffer); }
                    break;
                case 64:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to8_(And64_(%s, 0x00000000000000ff))", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to8_(And64_(%s, 0x000000000000ff00))", shadow->buffer); }
                    else if (i == 2) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to8_(And64_(%s, 0x0000000000ff0000))", shadow->buffer); }
                    else if (i == 3) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to8_(And64_(%s, 0x00000000ff000000))", shadow->buffer); }
                    else if (i == 4) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to8_(And64_(%s, 0x000000ff00000000))", shadow->buffer); }
                    else if (i == 5) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to8_(And64_(%s, 0x0000ff0000000000))", shadow->buffer); }
                    else if (i == 6) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to8_(And64_(%s, 0x00ff000000000000))", shadow->buffer); }
                    else if (i == 7) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to8_(And64_(%s, 0xff00000000000000))", shadow->buffer); }
                    break;
            }
        }
        else if (size == 16)
        {
            switch (shadow->size)
            {
                case 8:
                     if     (i == 0) { VG_(snprintf)(dep, DEP_MAX_SIZE, "8to16_(%s)", shadow->buffer); }
                     break;
                case 16:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_SIZE, "%s", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_SIZE, "And16_(%s, 0xff00)", shadow->buffer); }
                    break;
                case 32:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to16_(And32_(%s, 0x0000ffff))", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to16_(And32_(%s, 0x00ffff00))", shadow->buffer); }
                    else if (i == 2) { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to16_(And32_(%s, 0xffff0000))", shadow->buffer); }
                    else if (i == 3) { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to16_(And32_(%s, 0xff000000))", shadow->buffer); }
                    break;
                case 64:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to16_(And64_(%s, 0x000000000000ffff))", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to16_(And64_(%s, 0x0000000000ffff00))", shadow->buffer); }
                    else if (i == 2) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to16_(And64_(%s, 0x00000000ffff0000))", shadow->buffer); }
                    else if (i == 3) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to16_(And64_(%s, 0x000000ffff000000))", shadow->buffer); }
                    else if (i == 4) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to16_(And64_(%s, 0x0000ffff00000000))", shadow->buffer); }
                    else if (i == 5) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to16_(And64_(%s, 0x00ffff0000000000))", shadow->buffer); }
                    else if (i == 6) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to16_(And64_(%s, 0xffff000000000000))", shadow->buffer); }
                    else if (i == 7) { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to16_(And64_(%s, 0xff00000000000000))", shadow->buffer); }
                    break;
            }
        }
        else if (size == 32)
        {
            switch (shadow->size)
            {
                case 8:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "8to32_(%s)", shadow->buffer); }
                case 16:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "16to32_(%s)", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "16to32_(And16_(%s, 0xff00))", shadow->buffer); }
                    break;
                case 32:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "%s", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "And32_(%s, 0xffffff00)", shadow->buffer); }
                    else if (i == 2)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "And32_(%s, 0xffff0000)", shadow->buffer); }
                    else if (i == 3)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "And32_(%s, 0xff000000)", shadow->buffer); }
                    break;
                case 64:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to32_(And64_(%s, 0x00000000ffffffff))", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to32_(And64_(%s, 0x000000ffffffff00))", shadow->buffer); }
                    else if (i == 2)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to32_(And64_(%s, 0x0000ffffffff0000))", shadow->buffer); }
                    else if (i == 3)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to32_(And64_(%s, 0x00ffffffff000000))", shadow->buffer); }
                    else if (i == 4)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to32_(And64_(%s, 0xffffffff00000000))", shadow->buffer); }
                    else if (i == 5)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to32_(And64_(%s, 0xffffff0000000000))", shadow->buffer); }
                    else if (i == 6)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to32_(And64_(%s, 0xffff000000000000))", shadow->buffer); }
                    else if (i == 7)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "64to32_(And64_(%s, 0xff00000000000000))", shadow->buffer); }
                    break;
            }
        }
        else if (size == 64)
        {
            switch (shadow->size)
            {
                case 8:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "8to64_(%s)", shadow->buffer); }
                case 16:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "16to64_(%s)", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "16to64_(And16_(%s, 0xff00))", shadow->buffer); }
                    break;
                case 32:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to64_(%s)", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to64_(And32_(%s, 0xffffff00))", shadow->buffer); }
                    else if (i == 2)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to64_(And32_(%s, 0xffff0000))", shadow->buffer); }
                    else if (i == 3)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "32to64_(And32_(%s, 0xff000000))", shadow->buffer); }
                    break;
                case 64:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "%s", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "And64_(%s, 0xffffffffffffff00))", shadow->buffer); }
                    else if (i == 2)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "And64_(%s, 0xffffffffffff0000))", shadow->buffer); }
                    else if (i == 3)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "And64_(%s, 0xffffffffff000000))", shadow->buffer); }
                    else if (i == 4)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "And64_(%s, 0xffffffff00000000))", shadow->buffer); }
                    else if (i == 5)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "And64_(%s, 0xffffff0000000000))", shadow->buffer); }
                    else if (i == 6)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "And64_(%s, 0xffff000000000000))", shadow->buffer); }
                    else if (i == 7)  { VG_(snprintf)(dep, DEP_MAX_SIZE, "And64_(%s, 0xff00000000000000))", shadow->buffer); }
                    break;
            }
        }

        if (dep[0] != '\0') {
            break;
        }
    }

    return dep;
}

//
//  MEMORY TAINT ANALYSIS
//

void flip_memory(UInt addr, UInt size)
{
    Chunk* chunk;
    int i;

    for (i = 0; i < size/8; i++)
    {
        chunk = get_chunk_for_writing(addr+i);
        chunk->bytes[(addr+i) & 0xffff].tainted ^= 1;
        // VG_(printf)("flip_byte(0x%08x): %d -> %d\n", (addr+i), chunk->bytes[(addr+i) & 0xffff].tainted^1, chunk->bytes[(addr+i) & 0xffff].tainted);
    }
}

//
//  MEMORY SYMBOLIC EXECUTION
//

void update_memory_dep(UInt addr, char* dep, unsigned int dep_size)
{
    Chunk* chunk = get_chunk_for_writing(addr);

    update_dep(&chunk->bytes[addr & 0xffff], dep, dep_size);

    free_memory_dep(addr, dep_size-8);
}

void free_memory_dep(UInt addr, UInt size)
{
    Chunk* chunk;
    int i;

    for (i = 0; i < size/8; i++)
    {
        chunk = get_chunk_for_reading(addr+i);
        if (chunk == NULL)
            continue;

        free_dep(&chunk->bytes[(addr+i) & 0xffff]);
    }
}

//
//  REGISTERS
//

guest_register get_reg_from_offset(UInt offset)
{
    switch (offset)
    {
        case 8: return guest_EAX;
        case 12: return guest_ECX;
        case 16: return guest_EDX;
        case 20: return guest_EBX;
        case 24: return guest_ESP;
        case 28: return guest_EBP;
        case 32: return guest_ESI;
        case 36: return guest_EDI;
        case 40: return guest_CC_OP;
        case 44: return guest_CC_DEP1;
        case 48: return guest_CC_DEP2;
        case 52: return guest_CC_NDEP;
        case 56: return guest_DFLAG;
        case 60: return guest_IDFLAG;
        case 64: return guest_ACFLAG;
        case 68: return guest_EIP;
        default: return guest_INVALID;
    }
}

Shadow* get_register_shadow(UInt offset, UInt size)
{
    guest_register reg = get_reg_from_offset(offset);

    if (reg == guest_INVALID)
        return NULL;

    switch (size)
    {
        case 8:
            return &registers8[reg];
        case 16:
            return &registers16[reg];
        case 32:
            return &registers32[reg];
        default:
            VG_(tool_panic)("get_register_shadow");
    }
}

//
//  REGISTERS TAINT ANALYSIS
//

void flip_register8(guest_register reg)
{
    registers8[reg].tainted ^= 1;
}

void flip_register16(guest_register reg)
{
    registers16[reg].tainted ^= 1;

    registers8[reg].tainted = registers16[reg].tainted;
}

void flip_register32(guest_register reg)
{
    registers32[reg].tainted ^= 1;

    registers8[reg].tainted = registers16[reg].tainted = registers32[reg].tainted;
}

void flip_register(UInt offset, UInt size)
{
    guest_register reg = get_reg_from_offset(offset);

    if (reg == guest_INVALID)
        return;

    switch (size)
    {
        case 8:
            flip_register8(reg);
            break;
        case 16:
            flip_register16(reg);
            break;
        case 32:
            flip_register32(reg);
            break;
        default:
            VG_(tool_panic)("flip_register");
    }
}

//
//  REGISTERS SYMBOLIC EXECUTION
//

void update_register8_dep(guest_register reg, char* dep)
{
    update_dep(&registers8[reg], dep, 8);
}

void update_register16_dep(guest_register reg, char* dep)
{
    char dep8[DEP_MAX_SIZE] = {0};

    VG_(snprintf)(dep8, DEP_MAX_SIZE, "16to8_(And16_(%s, 0x00ff))", dep);

    update_dep(&registers16[reg], dep, 16);
    update_dep(&registers8[reg], dep8, 8);
}

void update_register32_dep(guest_register reg, char* dep)
{
    char dep16[DEP_MAX_SIZE] = {0};
    char dep8[DEP_MAX_SIZE] = {0};

    VG_(snprintf)(dep16, DEP_MAX_SIZE, "32to16_(And32_(%s,0x0000ffff))", dep);
    VG_(snprintf)(dep8, DEP_MAX_SIZE, "32to8_(And32_(%s,0x000000ff))", dep);

    update_dep(&registers32[reg], dep, 32);
    update_dep(&registers16[reg], dep16, 16);
    update_dep(&registers8[reg], dep8, 8);
}

void update_register_dep(UInt offset, UInt size, char* dep)
{
    guest_register reg = get_reg_from_offset(offset);

    if (reg == guest_INVALID)
        return;

    switch (size)
    {
        case 8:
            update_register8_dep(reg, dep);
            break;
        case 16:
            update_register16_dep(reg, dep);
            break;
        case 32:
            update_register32_dep(reg, dep);
            break;
        default:
            VG_(tool_panic)("update_register_dep");
    }
}

void free_register8_dep(guest_register reg)
{
    free_dep(&registers8[reg]);
}

void free_register16_dep(guest_register reg)
{
    free_dep(&registers16[reg]);
    free_register8_dep(reg);
}

void free_register32_dep(guest_register reg)
{
    free_dep(&registers32[reg]);
    free_register16_dep(reg);
}

void free_register_dep(UInt offset, UInt size)
{
    guest_register reg = get_reg_from_offset(offset);

    if (reg == guest_INVALID)
        return;

    switch (size)
    {
        case 8:
            free_register8_dep(reg);
            break;
        case 16:
            free_register16_dep(reg);
            break;
        case 32:
            free_register32_dep(reg);
            break;
        default:
            VG_(tool_panic)("free_register_dep");
    }
}

//
//  TEMPORARIES
//

Shadow* get_temporary_shadow(IRTemp tmp)
{
    tl_assert(tmp < MAX_TEMPORARIES);

    return &shadowTempArray[tmp];
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

void update_temporary_dep(IRTemp tmp, char* dep, unsigned int dep_size)
{
    tl_assert(tmp < MAX_TEMPORARIES);

    update_dep(&shadowTempArray[tmp], dep, dep_size);
}

void free_temporary_dep(IRTemp tmp)
{
    tl_assert(tmp < MAX_TEMPORARIES);

    free_dep(&shadowTempArray[tmp]);
}
