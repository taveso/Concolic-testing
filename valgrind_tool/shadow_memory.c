#include "shadow_memory.h"
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_libcbase.h"      // VG_(memset)
#include "pub_tool_mallocfree.h"    // VG_(malloc) VG_(free)
#include "pub_tool_libcassert.h"    // VG_(tool_panic)

void init_shadow_memory(void)
{
    VG_(memset)(MemoryMap, 0, sizeof(Chunk*)*MMAP_SIZE);

    VG_(memset)(registers, 0, sizeof(Shadow)*TOTAL_SHADOW_REGISTERS);

    VG_(memset)(shadowTempArray, 0, sizeof(Shadow)*MAX_TEMPORARIES);
}

void destroy_shadow_memory(void)
{
    unsigned int i, j;

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
//  REGISTERS
//

guest_register get_reg_from_offset(UInt offset)
{
    if (offset >= 8 && offset < 12)
        return guest_EAX;
    else if (offset >= 12 && offset < 16)
        return guest_ECX;
    else if (offset >= 16 && offset < 20)
        return guest_EDX;
    else if (offset >= 20 && offset < 24)
        return guest_EBX;
    else if (offset >= 24 && offset < 28)
        return guest_ESP;
    else if (offset >= 28 && offset < 32)
        return guest_EBP;
    else if (offset >= 32 && offset < 36)
        return guest_ESI;
    else if (offset >= 36 && offset < 40)
        return guest_EDI;
    else if (offset >= 40 && offset < 44)
        return guest_CC_OP;
    else if (offset >= 44 && offset < 48)
        return guest_CC_DEP1;
    else if (offset >= 48 && offset < 52)
        return guest_CC_DEP2;
    else if (offset >= 52 && offset < 56)
        return guest_CC_NDEP;
    else if (offset >= 56 && offset < 60)
        return guest_DFLAG;
    else if (offset >= 60 && offset < 64)
        return guest_IDFLAG;
    else if (offset >= 64 && offset < 68)
        return guest_ACFLAG;
    else if (offset >= 68 && offset < 72)
        return guest_EIP;
    else
        return guest_INVALID;
}
