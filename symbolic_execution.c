#include "symbolic_execution.h"
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_libcbase.h"      // VG_(memset)
#include "pub_tool_mallocfree.h"    // VG_(malloc) VG_(free)
#include "pub_tool_libcassert.h"    // VG_(tool_panic)

void update_dep(Shadow* shadow, char* dep, unsigned int dep_size)
{
    tl_assert(DEP_MAX_SIZE >= dep_size);

    if (shadow->buffer == NULL) {
        shadow->buffer = VG_(malloc)("", DEP_MAX_LEN);
    }
    VG_(snprintf)(shadow->buffer, DEP_MAX_LEN, "%s", dep);

    shadow->size = dep_size;

    // VG_(printf)("update_dep(): %s (%u)\n", shadow->buffer, shadow->size);
}

void free_dep(Shadow* shadow)
{
    if (shadow->buffer != NULL)
    {
        VG_(free)(shadow->buffer);

        shadow->buffer = NULL;
    }

    shadow->size = 0;
}

//
//  MEMORY
//

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

    for (i = 0; i < DEP_MAX_SIZE/8; i++)
    {
        shadow = get_byte_shadow(addr-i);

        if (shadow == NULL || shadow->buffer == NULL)
            continue;

        if (size == 8)
        {
            switch (shadow->size)
            {
                case 8:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    break;
                case 16:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr16_(%s,8)", shadow->buffer); }
                    break;
                case 32:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,8)", shadow->buffer); }
                    else if (i == 2) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,16)", shadow->buffer); }
                    else if (i == 3) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,24)", shadow->buffer); }
                    break;
                case 64:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,8)", shadow->buffer); }
                    else if (i == 2) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,16)", shadow->buffer); }
                    else if (i == 3) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,24)", shadow->buffer); }
                    else if (i == 4) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,32)", shadow->buffer); }
                    else if (i == 5) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,40)", shadow->buffer); }
                    else if (i == 6) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,48)", shadow->buffer); }
                    else if (i == 7) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,56)", shadow->buffer); }
                    break;
            }
        }
        else if (size == 16)
        {
            switch (shadow->size)
            {
                case 8:
                     if     (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                     break;
                case 16:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr16_(%s,8)", shadow->buffer); }
                    break;
                case 32:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,8)", shadow->buffer); }
                    else if (i == 2) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,16)", shadow->buffer); }
                    else if (i == 3) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,24)", shadow->buffer); }
                    break;
                case 64:
                    if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,8)", shadow->buffer); }
                    else if (i == 2) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,16)", shadow->buffer); }
                    else if (i == 3) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,24)", shadow->buffer); }
                    else if (i == 4) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,32)", shadow->buffer); }
                    else if (i == 5) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,40)", shadow->buffer); }
                    else if (i == 6) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,48)", shadow->buffer); }
                    else if (i == 7) { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,56)", shadow->buffer); }
                    break;
            }
        }
        else if (size == 32)
        {
            switch (shadow->size)
            {
                case 8:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                case 16:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr16_(%s,8)", shadow->buffer); }
                    break;
                case 32:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,8)", shadow->buffer); }
                    else if (i == 2)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,16)", shadow->buffer); }
                    else if (i == 3)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,24)", shadow->buffer); }
                    break;
                case 64:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,8)", shadow->buffer); }
                    else if (i == 2)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,16)", shadow->buffer); }
                    else if (i == 3)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,24)", shadow->buffer); }
                    else if (i == 4)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,32)", shadow->buffer); }
                    else if (i == 5)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,40)", shadow->buffer); }
                    else if (i == 6)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,48)", shadow->buffer); }
                    else if (i == 7)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,56)", shadow->buffer); }
                    break;
            }
        }
        else if (size == 64)
        {
            switch (shadow->size)
            {
                case 8:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                case 16:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr16_(%s,8)", shadow->buffer); }
                    break;
                case 32:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,8)", shadow->buffer); }
                    else if (i == 2)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,16)", shadow->buffer); }
                    else if (i == 3)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr32_(%s,24)", shadow->buffer); }
                    break;
                case 64:
                    if      (i == 0)  { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                    else if (i == 1)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,8)", shadow->buffer); }
                    else if (i == 2)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,16)", shadow->buffer); }
                    else if (i == 3)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,24)", shadow->buffer); }
                    else if (i == 4)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,32)", shadow->buffer); }
                    else if (i == 5)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,40)", shadow->buffer); }
                    else if (i == 6)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,48)", shadow->buffer); }
                    else if (i == 7)  { VG_(snprintf)(dep, DEP_MAX_LEN, "Shr64_(%s,56)", shadow->buffer); }
                    break;
            }
        }

        if (dep[0] != '\0') {
            break;
        }
    }

    tl_assert(dep[0] != '\0');
    return dep;
}

void update_memory_dep(UInt addr, char* dep, unsigned int dep_size)
{
    Chunk* chunk = get_chunk_for_writing(addr);

    update_dep(&chunk->bytes[addr & 0xffff], dep, dep_size);

    free_memory_dep(addr+1, dep_size-8);
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

char* get_register_dep(UInt offset, UInt size)
{
    guest_register reg;
    Shadow shadow;

    reg = get_reg_from_offset(offset);
    tl_assert(reg != guest_INVALID);

    switch (size)
    {
        case 8:
            shadow = registers8[reg];
            break;
        case 16:
            shadow = registers16[reg];
            break;
        case 32:
            shadow = registers32[reg];
            break;
        default:
            VG_(tool_panic)("get_register_dep");
    }

    tl_assert(shadow.buffer != NULL);
    return shadow.buffer;
}

void update_register8_dep(guest_register reg, char* dep)
{
    char dep16[DEP_MAX_LEN] = {0};
    char dep32[DEP_MAX_LEN] = {0};

    VG_(snprintf)(dep16, DEP_MAX_LEN, "8to16_(%s)", dep);
    VG_(snprintf)(dep32, DEP_MAX_LEN, "8to32_(%s)", dep);

    update_dep(&registers8[reg], dep, 8);
    update_dep(&registers16[reg], dep16, 16);
    update_dep(&registers32[reg], dep32, 32);
}

void update_register16_dep(guest_register reg, char* dep)
{
    char dep8[DEP_MAX_LEN] = {0};
    char dep32[DEP_MAX_LEN] = {0};

    VG_(snprintf)(dep8, DEP_MAX_LEN, "16to8_(%s)", dep);
    VG_(snprintf)(dep32, DEP_MAX_LEN, "16to32_(%s)", dep);

    update_dep(&registers8[reg], dep8, 8);
    update_dep(&registers16[reg], dep, 16);
    update_dep(&registers32[reg], dep32, 32);
}

void update_register32_dep(guest_register reg, char* dep)
{
    char dep16[DEP_MAX_LEN] = {0};
    char dep8[DEP_MAX_LEN] = {0};

    VG_(snprintf)(dep16, DEP_MAX_LEN, "32to16_(%s)", dep);
    VG_(snprintf)(dep8, DEP_MAX_LEN, "32to8_(%s)", dep);

    update_dep(&registers8[reg], dep8, 8);
    update_dep(&registers16[reg], dep16, 16);
    update_dep(&registers32[reg], dep, 32);
}

void update_register_dep(UInt offset, UInt size, char* dep)
{
    guest_register reg = get_reg_from_offset(offset);

    tl_assert(reg != guest_INVALID);

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

    tl_assert(reg != guest_INVALID);

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

char* get_temporary_dep(IRTemp tmp)
{
    Shadow shadow;

    tl_assert(tmp < MAX_TEMPORARIES);
    shadow = shadowTempArray[tmp];

    tl_assert(shadow.buffer != NULL);
    return shadow.buffer;
}

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
