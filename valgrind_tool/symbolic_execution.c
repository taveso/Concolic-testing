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
    if (shadow->buffer != NULL) {
        VG_(free)(shadow->buffer);
        shadow->buffer = NULL;
    }

    shadow->size = 0;
}

//
//  MEMORY
//

char* get_memory_dep(UInt addr, UInt size, char* dep)
{
    int i;
    Chunk* chunk;
    Shadow* shadow;

    for (i = 0; i < DEP_MAX_SIZE/8; i++)
    {
        chunk = get_chunk_for_reading(addr-i);
        if (chunk == NULL)
            continue;

        shadow = chunk->bytes[(addr-i) & 0xffff];
        if (shadow == NULL || shadow->buffer == NULL)
            continue;

        switch (shadow->size)
        {
            case 8:
                if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                break;
            case 16:
                if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_LEN, "Sar16_(%s,8)", shadow->buffer); }
                break;
            case 32:
                if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_LEN, "Sar32_(%s,8)", shadow->buffer); }
                else if (i == 2) { VG_(snprintf)(dep, DEP_MAX_LEN, "Sar32_(%s,16)", shadow->buffer); }
                else if (i == 3) { VG_(snprintf)(dep, DEP_MAX_LEN, "Sar32_(%s,24)", shadow->buffer); }
                break;
            case 64:
                if      (i == 0) { VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer); }
                else if (i == 1) { VG_(snprintf)(dep, DEP_MAX_LEN, "Sar64_(%s,8)", shadow->buffer); }
                else if (i == 2) { VG_(snprintf)(dep, DEP_MAX_LEN, "Sar64_(%s,16)", shadow->buffer); }
                else if (i == 3) { VG_(snprintf)(dep, DEP_MAX_LEN, "Sar64_(%s,24)", shadow->buffer); }
                else if (i == 4) { VG_(snprintf)(dep, DEP_MAX_LEN, "Sar64_(%s,32)", shadow->buffer); }
                else if (i == 5) { VG_(snprintf)(dep, DEP_MAX_LEN, "Sar64_(%s,40)", shadow->buffer); }
                else if (i == 6) { VG_(snprintf)(dep, DEP_MAX_LEN, "Sar64_(%s,48)", shadow->buffer); }
                else if (i == 7) { VG_(snprintf)(dep, DEP_MAX_LEN, "Sar64_(%s,56)", shadow->buffer); }
                break;
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
    Chunk* chunk;
    Shadow* shadow;

    chunk = get_chunk_for_writing(addr);

    shadow = chunk->bytes[addr & 0xffff];
    tl_assert(shadow != NULL);

    update_dep(shadow, dep, dep_size);

    free_memory_dep(addr+1, dep_size-8);
}

void free_memory_dep(UInt addr, UInt size)
{
    Chunk* chunk;
    Shadow* shadow;
    int i;

    for (i = 0; i < size/8; i++)
    {
        chunk = get_chunk_for_reading(addr+i);
        if (chunk == NULL)
            continue;

        shadow = chunk->bytes[(addr+i) & 0xffff];
        if (shadow == NULL)
            continue;

        free_dep(shadow);
    }
}

//
//  REGISTERS
//

char* get_register_dep(UInt offset)
{
    guest_register reg;
    Shadow shadow;

    reg = get_reg_from_offset(offset);
    tl_assert(reg != guest_INVALID);

    shadow = registers[reg];
    tl_assert(shadow.buffer != NULL);

    return shadow.buffer;
}

void update_register_dep(UInt offset, UInt size, char* dep)
{
    guest_register reg = get_reg_from_offset(offset);
    tl_assert(reg != guest_INVALID);

    update_dep(&registers[reg], dep, size);
}

void free_register_dep(UInt offset)
{
    guest_register reg = get_reg_from_offset(offset);
    tl_assert(reg != guest_INVALID);

    free_dep(&registers[reg]);
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
