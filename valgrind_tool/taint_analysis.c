#include "taint_analysis.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_machine.h"
#include "pub_tool_tooliface.h"

//
//  MEMORY
//

char memory_is_tainted(UInt addr, UInt size)
{
    Chunk* chunk;
    int i;

    for (i = 0; i < size/8; i++)
    {
        chunk = get_chunk_for_reading(addr+i);
        if (chunk == NULL)
            continue;

        if (chunk->bytes[(addr+i) & 0xffff].tainted) {
            return 1;
        }
    }

    return 0;
}

void flip_memory(UInt addr, UInt size)
{
    Chunk* chunk;
    int i;

    for (i = 0; i < size/8; i++)
    {
        chunk = get_chunk_for_writing(addr+i);

        chunk->bytes[(addr+i) & 0xffff].tainted ^= 1;
    }
}


//
//  REGISTERS
//

char register8_is_tainted(guest_register reg)
{
    return registers8[reg].tainted;
}

char register16_is_tainted(guest_register reg)
{
    return registers16[reg].tainted;
}

char register32_is_tainted(guest_register reg)
{
    return registers32[reg].tainted;
}

char register_is_tainted(UInt offset, UInt size)
{
    guest_register reg = get_reg_from_offset(offset);

    if (reg == guest_INVALID)
        return 0;

    switch (size)
    {
        case 8:
            return register8_is_tainted(reg);
        case 16:
            return register16_is_tainted(reg);
        case 32:
            return register32_is_tainted(reg);
        default:
            VG_(tool_panic)("register_is_tainted");
    }
}

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

    tl_assert(reg != guest_INVALID);

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
//  TEMPORARIES
//

char temporary_is_tainted(IRTemp tmp)
{
    tl_assert(tmp < MAX_TEMPORARIES);

    return shadowTempArray[tmp].tainted;
}

char IRTemp_is_tainted(IRTemp tmp)
{
    if (tmp == IRTemp_INVALID) // Iex_Const
        return 0;
    else
        return temporary_is_tainted(tmp);
}

void flip_temporary(IRTemp tmp)
{
    tl_assert(tmp < MAX_TEMPORARIES);

    shadowTempArray[tmp].tainted ^= 1;
}
