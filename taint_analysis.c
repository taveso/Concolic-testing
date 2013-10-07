#include "taint_analysis.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_machine.h"
#include "pub_tool_tooliface.h"

//
//  MEMORY
//

char byte_is_tainted(UInt addr)
{
    Chunk* chunk = get_chunk_for_reading(addr);

    if (chunk == NULL)
        return 0;

    return chunk->bytes[addr & 0xffff];
}

char word_is_tainted(UInt addr)
{
    if (byte_is_tainted(addr) || byte_is_tainted(addr+1))
        return 1;

    return 0;
}

char dword_is_tainted(UInt addr)
{
    if (word_is_tainted(addr) || word_is_tainted(addr+2))
        return 1;

    return 0;
}

char qword_is_tainted(UInt addr)
{
    if (dword_is_tainted(addr) || dword_is_tainted(addr+4))
        return 1;

    return 0;
}

char dqword_is_tainted(UInt addr)
{
    if (qword_is_tainted(addr) || qword_is_tainted(addr+8))
        return 1;

    return 0;
}

char memory_is_tainted(UInt addr, UInt size)
{
    switch (size)
    {
        case 1:
            return byte_is_tainted(addr);
        case 2:
            return word_is_tainted(addr);
        case 4:
            return dword_is_tainted(addr);
        case 8:
            return qword_is_tainted(addr);
        case 16:
            return dqword_is_tainted(addr);
        default:
            VG_(tool_panic)("memory_is_tainted");
    }
}

//
//  REGISTERS
//

char register8_is_tainted(Register reg)
{
    return registers8[reg];
}

char register16_is_tainted(Register reg)
{
    return registers16[reg];
}

char register32_is_tainted(Register reg)
{
    return registers32[reg];
}

char register_is_tainted(UInt offset, UInt size)
{
    Register reg = get_reg_from_offset(offset);

    if (reg == REG_INVALID)
        return 0;

    switch (size)
    {
        case 1:
            return register8_is_tainted(reg);
        case 2:
            return register16_is_tainted(reg);
        case 4:
            return register32_is_tainted(reg);
        default:
            VG_(tool_panic)("register_is_tainted");
    }
}

//
//  TEMPORARIES
//

char temporary_is_tainted(IRTemp tmp)
{
    if (shadow_tmp_exists(tmp))
    {
        return g_ShadowTempArray[tmp];
    }
    else
        VG_(tool_panic)("temporary_is_tainted");
}

char IRTemp_is_tainted(IRTemp tmp)
{
    if (tmp == IRTemp_INVALID) // Iex_Const
        return 0;
    else
        return temporary_is_tainted(tmp);
}
