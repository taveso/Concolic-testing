#include "taint_analysis.h"
#include <stdlib.h>

//
//  VEX
//

char IRExpr_is_tainted(IRExpr* expr)
{
    switch (expr->tag)
    {
        case Iex_Binder:
        case Iex_Const:
        case Iex_CCall:
            return 0;

        case Iex_Get:
            return Get_is_tainted(expr);
        case Iex_GetI:
            // TODO
            return 0;
        case Iex_RdTmp:
            return temporary_is_tainted(expr->Iex.RdTmp.tmp);
        case Iex_Qop:
            return Qop_is_tainted(expr);
        case Iex_Triop:
            return Triop_is_tainted(expr);
        case Iex_Binop:
            return Binop_is_tainted(expr);
        case Iex_Unop:
            return Unop_is_tainted(expr);
        case Iex_Load:
            return Load_is_tainted(expr);
        case Iex_Mux0X:
            // TODO
            return 0;
    }
}

char Get_is_tainted(IRExpr* expr)
{
    return register_is_tainted(expr->Iex.Get.offset, sizeofIRType(expr->Iex.Get.ty));
}

char Unop_is_tainted(IRExpr* expr)
{
    switch (expr->Iex.Unop.op)
    {
        case Iop_Not8:
        case Iop_Not16:
        case Iop_Not32:
        case Iop_Clz32:
        case Iop_Ctz32:
        case Iop_8Uto16:
        case Iop_8Uto32:
        case Iop_16Uto32:
        case Iop_8Sto16:
        case Iop_8Sto32:
        case Iop_16Sto32:
        case Iop_32to8:
        case Iop_16to8:
        case Iop_16HIto8:
        case Iop_8HLto16:
        case Iop_32to16:
        case Iop_32HIto16:
        case Iop_16HLto32:
        case Iop_Not1:
        case Iop_32to1:
        case Iop_1Uto8:
        case Iop_1Uto32:
        case Iop_1Sto8:
        case Iop_1Sto16:
        case Iop_1Sto32:
        case Iop_NegF32:
        case Iop_AbsF32:
        case Iop_SqrtF32:
        case Iop_I16StoF32:
        case Iop_ReinterpF32asI32:
        case Iop_ReinterpI32asF32:
            return IRExpr_is_tainted(expr->Iex.Unop.arg);
        default:
            // TODO: throw exception
            return 0;
    }
}

char Binop_is_tainted(IRExpr* expr)
{
    switch (expr->Iex.Binop.op)
    {
        case Iop_Add8:
        case Iop_Add16:
        case Iop_Add32:
        case Iop_Sub8:
        case Iop_Sub16:
        case Iop_Sub32:
        case Iop_Mul8:
        case Iop_Mul16:
        case Iop_Mul32:
        case Iop_Shl8:
        case Iop_Shl16:
        case Iop_Shl32:
        case Iop_Shr8:
        case Iop_Shr16:
        case Iop_Shr32:
        case Iop_Sar8:
        case Iop_Sar16:
        case Iop_Sar32:
        case Iop_CmpEQ8:
        case Iop_CmpEQ16:
        case Iop_CmpEQ32:
        case Iop_CmpNE8:
        case Iop_CmpNE16:
        case Iop_CmpNE32:
        case Iop_CasCmpEQ8:
        case Iop_CasCmpEQ16:
        case Iop_CasCmpEQ32:
        case Iop_CasCmpNE8:
        case Iop_CasCmpNE16:
        case Iop_CasCmpNE32:
        case Iop_MullS8:
        case Iop_MullS16:
        case Iop_MullS32:
        case Iop_MullU8:
        case Iop_MullU16:
        case Iop_MullU32:
        case Iop_CmpLT32S:
        case Iop_CmpLE32S:
        case Iop_CmpLT32U:
        case Iop_CmpLE32U:
        case Iop_DivU32:
        case Iop_DivS32:
        case Iop_DivU32E:
        case Iop_DivS32E:
        case Iop_AddF32:
        case Iop_SubF32:
        case Iop_MulF32:
        case Iop_DivF32:
        case Iop_CmpF32:
        // TODO: Iop_Or Iop_And Iop_Xor
        case Iop_Or8:
        case Iop_Or16:
        case Iop_Or32:
        case Iop_And8:
        case Iop_And16:
        case Iop_And32:
        case Iop_Xor8:
        case Iop_Xor16:
        case Iop_Xor32:
            return IRExpr_is_tainted(expr->Iex.Binop.arg1) || IRExpr_is_tainted(expr->Iex.Binop.arg2);
        case Iop_F32toI16S:
        case Iop_F32toI32S:
        case Iop_I32StoF32:
            return IRExpr_is_tainted(expr->Iex.Binop.arg2);
        default:
            // TODO: throw exception
            return 0;
    }
}

char Triop_is_tainted(IRExpr* expr)
{
    // TODO: throw exception
    return 0;
}

char Qop_is_tainted(IRExpr* expr)
{
    // TODO: throw exception
    return 0;
}

char Load_is_tainted(IRExpr* expr)
{
    UInt load_address = get_address_from_IRExpr(expr->Iex.Load.addr);

    return memory_is_tainted(load_address, sizeofIRType(expr->Iex.Load.ty));
}

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
    if (!byte_is_tainted(addr) || !byte_is_tainted(addr+1))
        return 0;

    return 1;
}

char dword_is_tainted(UInt addr)
{
    if (!byte_is_tainted(addr) || !byte_is_tainted(addr+1) || !byte_is_tainted(addr+2) || !byte_is_tainted(addr+3))
        return 0;

    return 1;
}

char memory_is_tainted(UInt addr, Int size)
{
    switch (size)
    {
        case 1:
            return byte_is_tainted(addr);
        case 2:
            return word_is_tainted(addr);
        case 4:
            return dword_is_tainted(addr);
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

char register_is_tainted(Int offset, Int size)
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
    }
}

//
//  TEMPORARIES
//

char temporary_is_tainted(IRTemp tmp)
{
    return g_tmp_map[tmp]->tainted;
}

//
//  UTILS
//

UInt get_address_from_IRExpr(IRExpr* addr)
{
    // tl_assert(isIRAtom(addr)); //

    if (addr->tag == Iex_RdTmp) {
        return addr->Iex.RdTmp.tmp;
    }
    else // addr->tag == Iex_Const
    {
        // tl_assert(addr->Iex.Const.con->tag == Ico_U32); //

        return addr->Iex.Const.con->Ico.U32;
    }
}
