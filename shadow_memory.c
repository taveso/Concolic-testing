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
