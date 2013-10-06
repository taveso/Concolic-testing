#include "taint_analysis.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_machine.h"
#include "pub_tool_tooliface.h"

//
//  VEX
//

char IRExpr_is_tainted(IRExpr* expr)
{
    switch (expr->tag)
    {
        case Iex_Binder:
        // we don't care about floating point and SIMD operations
        case Iex_GetI:
        case Iex_Qop:
        case Iex_Triop:
            return 0;

        case Iex_Get:
            return Get_is_tainted(expr);
        case Iex_RdTmp:
            return temporary_is_tainted(expr->Iex.RdTmp.tmp);
        case Iex_Binop:
            return Binop_is_tainted(expr);
        case Iex_Unop:
            return Unop_is_tainted(expr);
        case Iex_Load:
            return Load_is_tainted(expr);
        case Iex_Const:
            return 0;
        case Iex_CCall:
            // TODO
            return 0;
        case Iex_Mux0X:
            // return Mux0X_is_tainted(expr, sb_out);
            return 0;
    }
}

char Get_is_tainted(IRExpr* expr)
{
    return register_is_tainted(expr->Iex.Get.offset, sizeofIRType(expr->Iex.Get.ty));
}

char Unop_is_tainted(IRExpr* expr)
{
    tl_assert(isIRAtom(expr->Iex.Unop.arg));

    return IRAtom_is_tainted(expr->Iex.Unop.arg);
}

char Binop_is_tainted(IRExpr* expr)
{
    // we don't care about floating point and SIMD operations
    if (expr->Iex.Binop.op > Iop_AddF64)
        return 0;

    tl_assert(isIRAtom(expr->Iex.Binop.arg1));
    tl_assert(isIRAtom(expr->Iex.Binop.arg2));

    return IRAtom_is_tainted(expr->Iex.Binop.arg1) || IRAtom_is_tainted(expr->Iex.Binop.arg2);
}

char Load_is_tainted(IRExpr* expr)
{
    return IRAtom_addr_is_tainted(expr->Iex.Load.addr, sizeofIRType(expr->Iex.Load.ty));
}

char IRAtom_is_tainted(IRExpr* expr)
{
    tl_assert(isIRAtom(expr));

    if (expr->tag == Iex_RdTmp)
        return temporary_is_tainted(expr->Iex.RdTmp.tmp);
    else // expr->tag == Iex_Const
        return 0;
}

char IRAtom_addr_is_tainted(IRExpr* expr, Int size)
{
    UInt addr = get_IRAtom_addr(expr);

    return memory_is_tainted(addr, size);
}

char IRTemp_is_tainted(IRTemp tmp)
{
    if (tmp == IRTemp_INVALID) // Iex_Const
        return 0;
    else
        return temporary_is_tainted(tmp);
}

static VG_REGPARM(0) void helper_Mux0X_is_tainted(UInt cond, UInt expr0, UInt exprX)
{
    VG_(printf)("helper_Mux0X: cond: %u - expr0: %u - exprX: %u\n", cond, expr0, exprX);
}

char Mux0X_is_tainted(IRExpr* expr, IRSB* irsb)
{
    // ppIRType(typeOfIRExpr(bb->tyenv, expr->Iex.Mux0X.cond)); // Ity_I8

    IRExpr* cond = expr->Iex.Mux0X.cond;
    IRExpr* expr0 = expr->Iex.Mux0X.expr0;
    IRExpr* exprX = expr->Iex.Mux0X.exprX;

    tl_assert(cond->tag == Iex_RdTmp);
    tl_assert(isIRAtom(expr0));
    tl_assert(isIRAtom(exprX));

    IRTemp tmp = newIRTemp(irsb->tyenv, Ity_I32);
    addStmtToIRSB(irsb, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_8Uto32, cond)));

    TempMapEnt ent;
    ent.tainted = 0;
    VG_(addToXA)(g_TempMap, &ent);

    cond = IRExpr_RdTmp(tmp);

    VG_(printf)("Mux0X_is_tainted: cond: %u - expr0: %u - exprX: %u\n",
                (UInt) cond,
                mkIRExpr_HWord((expr0->tag == Iex_RdTmp) ? expr0->Iex.RdTmp.tmp : IRTemp_INVALID),
                mkIRExpr_HWord((exprX->tag == Iex_RdTmp) ? exprX->Iex.RdTmp.tmp : IRTemp_INVALID));

    IRDirty* di = unsafeIRDirty_0_N(0,
                                    "helper_Mux0X_is_tainted",
                                    VG_(fnptr_to_fnentry)(helper_Mux0X_is_tainted),
                                    mkIRExprVec_3(cond,
                                                  mkIRExpr_HWord((expr0->tag == Iex_RdTmp) ? expr0->Iex.RdTmp.tmp : IRTemp_INVALID),
                                                  mkIRExpr_HWord((exprX->tag == Iex_RdTmp) ? exprX->Iex.RdTmp.tmp : IRTemp_INVALID)
                                                  )
                                    );
    addStmtToIRSB(irsb, IRStmt_Dirty(di));
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
    if (shadow_tmp_exists(tmp))
    {
        return g_ShadowTempArray[tmp];
    }

    return 0;
}

//
//  UTILS
//

UInt get_IRAtom_addr(IRExpr* expr)
{
    tl_assert(isIRAtom(expr));

    if (expr->tag == Iex_RdTmp)
    {
        // TODO: expr->Iex.RdTmp.tmp value ?
        return 0xdeadbeef;
    }
    else // expr->tag == Iex_Const
    {
        tl_assert(expr->Iex.Const.con->tag == Ico_U32);

        return expr->Iex.Const.con->Ico.U32;
    }
}
