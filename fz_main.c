#include "shadow_memory.h"
#include "taint_analysis.h"
#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"    // tl_assert()
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_machine.h"       // VG_(fnptr_to_fnentry)

/*
    Bind the given expression to a new temporary, and return the temporary.
    This effectively converts an arbitrary expression into an IRAtom.
*/
static IRExpr* assignNew(IRSB* sb_out, IRExpr* expr)
{
    IRTemp tmp = newIRTemp(sb_out->tyenv, typeOfIRExpr(sb_out->tyenv, expr));

    addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, expr));

    return IRExpr_RdTmp(tmp);
}
static IRExpr* assignNew_HWord(IRSB* sb_out, IRExpr* expr)
{
    IRTemp tmp = newIRTemp(sb_out->tyenv, Ity_I32);

    switch (typeOfIRExpr(sb_out->tyenv, expr))
    {
        case Ity_I1:
            addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_1Uto32, expr)));
            break;
        case Ity_I8:
            addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_8Uto32, expr)));
            break;
        case Ity_I16:
            addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_16Uto32, expr)));
            break;
        case Ity_I32:
            addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, expr));
            break;
        default:
            VG_(tool_panic)("assignNew_HWord");
   }

    return IRExpr_RdTmp(tmp);
}

//
//  TAINT ANALYSIS DIRTY HELPERS
//

static VG_REGPARM(0) void helper_instrument_Put(UInt offset, IRTemp data, UInt size) //
{
    if (register_is_tainted(offset, size) != IRTemp_is_tainted(data))
    {
        flip_register(offset, size);
    }
}
static VG_REGPARM(0) void helper_instrument_PutI(UInt base, UInt ix, UInt bias, UInt nElems) //
{
    UInt index = base+((ix+bias)%nElems);
    switch (index)
    {
        case 8:     // EAX
        case 12:    // ECX
        case 16:    // EDX
        case 20:    // EBX
        case 24:    // ESP
        case 28:    // EBP
        case 32:    // ESI
        case 38:    // EDI
        case 68:    // EIP
            VG_(tool_panic)("helper_instrument_PutI");
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Get(IRTemp tmp, UInt offset, UInt size) //
{
    if (temporary_is_tainted(tmp) != register_is_tainted(offset, size))
    {
        flip_temporary(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_GetI(UInt base, UInt ix, UInt bias, UInt nElems) //
{
    UInt index = base+((ix+bias)%nElems);
    switch (index)
    {
        case 8:     // EAX
        case 12:    // ECX
        case 16:    // EDX
        case 20:    // EBX
        case 24:    // ESP
        case 28:    // EBP
        case 32:    // ESI
        case 38:    // EDI
        case 68:    // EIP
            VG_(tool_panic)("helper_instrument_WrTmp_GetI");
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_RdTmp(IRTemp tmp_lhs, IRTemp tmp_rhs) //
{
    if (temporary_is_tainted(tmp_lhs) != temporary_is_tainted(tmp_rhs))
    {
        flip_temporary(tmp_lhs);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Binop(IRTemp tmp, IRTemp arg1, IRTemp arg2) //
{
    if (temporary_is_tainted(tmp) != (IRTemp_is_tainted(arg1) || IRTemp_is_tainted(arg2)))
    {
        flip_temporary(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Unop(IRTemp tmp, IRTemp arg) //
{
    if (temporary_is_tainted(tmp) != IRTemp_is_tainted(arg))
    {
        flip_temporary(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Load(IRTemp tmp, UInt addr, UInt size) //
{
    if (temporary_is_tainted(tmp) != memory_is_tainted(addr, size))
    {
        flip_temporary(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Const(IRTemp tmp) //
{
    if (temporary_is_tainted(tmp))
    {
        flip_temporary(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Mux0X(IRTemp tmp, UInt cond, IRTemp expr0, IRTemp exprX) //
{
    if (cond == 0)
    {
        if (temporary_is_tainted(tmp) != IRTemp_is_tainted(expr0))
        {
            flip_temporary(tmp);
        }
    }
    else
    {
        if (temporary_is_tainted(tmp) != IRTemp_is_tainted(exprX))
        {
            flip_temporary(tmp);
        }
    }
}
static VG_REGPARM(0) void helper_instrument_Store(UInt addr, IRTemp data, UInt size) //
{
    if (memory_is_tainted(addr, size) != IRTemp_is_tainted(data))
    {
        flip_memory(addr, size);
    }
}
static VG_REGPARM(0) void helper_instrument_CAS_single_element(UInt addr, IRTemp dataLo, UInt size, UInt cas_succeeded) //
{
    if (cas_succeeded)
    {
        if (memory_is_tainted(addr, size) != IRTemp_is_tainted(dataLo))
        {
            flip_memory(addr, size);
        }
    }
}
static VG_REGPARM(0) void helper_instrument_CAS_double_element(UInt addr, IRTemp dataLo, IRTemp dataHi, UInt size, UInt oldLo_succeeded, UInt oldHi_succeeded) //
{
    char cas_succeeded = oldLo_succeeded && oldHi_succeeded;

    if (cas_succeeded)
    {
        if (memory_is_tainted(addr, size) != IRTemp_is_tainted(dataLo))
        {
            flip_memory(addr, size);
        }

        if (memory_is_tainted(addr+size, size) != IRTemp_is_tainted(dataHi))
        {
            flip_memory(addr+size, size);
        }
    }
}
static VG_REGPARM(0) void helper_instrument_LLSC_Load_Linked(IRTemp result, UInt addr, UInt size) //
{
    if (temporary_is_tainted(result) != memory_is_tainted(addr, size))
    {
        flip_temporary(result);
    }
}
static VG_REGPARM(0) void helper_instrument_LLSC_Store_Conditional(UInt addr, IRTemp storedata, UInt size, UInt store_succeeded) //
{
    if (store_succeeded)
    {
        if (memory_is_tainted(addr, size) != IRTemp_is_tainted(storedata))
        {
            flip_memory(addr, size);
        }
    }
}
static VG_REGPARM(0) void helper_instrument_Exit(UInt guard, UInt offsIP, UInt size) //
{
    if (guard)
    {
        if (register_is_tainted(offsIP, size))
        {
            flip_register(offsIP, size);
        }
    }
}

//
//  VEX INSTRUMENTATION FUNCTIONS
//

void instrument_Put(IRStmt* st, IRSB* sb_out) //
{
    Int offset = st->Ist.Put.offset;
    IRExpr* data = st->Ist.Put.data;
    Int size = sizeofIRType(typeOfIRExpr(sb_out->tyenv, data));
    IRDirty* di;

    tl_assert(isIRAtom(data));

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_Put",
                           VG_(fnptr_to_fnentry)(helper_instrument_Put),
                           mkIRExprVec_3(mkIRExpr_HWord(offset),
                                         mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord(size))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
/*
    The PutI statement is used to write guest registers which identity is not known until run time,
    i.e. not general-purpose registers and instruction pointer (in principle),
    no harm in verifying though.
*/
void instrument_PutI(IRStmt* st, IRSB* sb_out) //
{
    IRPutI* details = st->Ist.PutI.details;
    IRRegArray* descr = details->descr;
    Int base = descr->base;
    Int nElems = descr->nElems;
    IRExpr* ix = details->ix;
    Int bias = details->bias;
    IRDirty* di;

    tl_assert(ix->tag == Iex_RdTmp);

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_PutI",
                           VG_(fnptr_to_fnentry)(helper_instrument_PutI),
                           mkIRExprVec_4(mkIRExpr_HWord(base),
                                         assignNew_HWord(sb_out, ix),
                                         mkIRExpr_HWord(bias),
                                         mkIRExpr_HWord(nElems))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Get(IRStmt* st, IRSB* sb_out) //
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    Int offset = data->Iex.Get.offset;
    Int size = sizeofIRType(data->Iex.Get.ty);
    IRDirty* di;

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_Get",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Get),
                           mkIRExprVec_3(mkIRExpr_HWord(tmp),
                                         mkIRExpr_HWord(offset),
                                         mkIRExpr_HWord(size))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
/*
    The GetI expression is used to read guest registers which identity is not known until run time,
    i.e. not general-purpose registers and instruction pointer (in principle),
    no harm in verifying though.
*/
void instrument_WrTmp_GetI(IRStmt* st, IRSB* sb_out) //
{
    IRExpr* data = st->Ist.WrTmp.data;
    IRRegArray* descr = data->Iex.GetI.descr;
    Int base = descr->base;
    Int nElems = descr->nElems;
    IRExpr* ix = data->Iex.GetI.ix;
    Int bias = data->Iex.GetI.bias;
    IRDirty* di;

    tl_assert(ix->tag == Iex_RdTmp);

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_GetI",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_GetI),
                           mkIRExprVec_4(mkIRExpr_HWord(base),
                                         assignNew_HWord(sb_out, ix),
                                         mkIRExpr_HWord(bias),
                                         mkIRExpr_HWord(nElems))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_RdTmp(IRStmt* st, IRSB* sb_out) //
{
    IRTemp tmp_lhs = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    IRTemp tmp_rhs = data->Iex.RdTmp.tmp;
    IRDirty* di;

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_RdTmp",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_RdTmp),
                           mkIRExprVec_2(mkIRExpr_HWord(tmp_lhs),
                                         mkIRExpr_HWord(tmp_rhs))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Binop(IRStmt* st, IRSB* sb_out) //
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    IROp op = data->Iex.Binop.op;
    IRExpr* arg1 = data->Iex.Binop.arg1;
    IRExpr* arg2 = data->Iex.Binop.arg2;
    IRDirty* di;

    // we don't care about floating point and SIMD operations
    if (op > Iop_AddF64)
        return;

    tl_assert(isIRAtom(arg1));
    tl_assert(isIRAtom(arg2));

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_Binop",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Binop),
                           mkIRExprVec_3(mkIRExpr_HWord(tmp),
                                         mkIRExpr_HWord((arg1->tag == Iex_RdTmp) ? arg1->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord((arg2->tag == Iex_RdTmp) ? arg2->Iex.RdTmp.tmp : IRTemp_INVALID))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Unop(IRStmt* st, IRSB* sb_out) //
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    IRExpr* arg = data->Iex.Unop.arg;
    IRDirty* di;

    tl_assert(isIRAtom(arg));

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_Unop",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Unop),
                           mkIRExprVec_2(mkIRExpr_HWord(tmp),
                                         mkIRExpr_HWord((arg->tag == Iex_RdTmp) ? arg->Iex.RdTmp.tmp : IRTemp_INVALID))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Load(IRStmt* st, IRSB* sb_out) //
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    Int size = sizeofIRType(data->Iex.Load.ty);
    IRExpr* addr = data->Iex.Load.addr;
    IRDirty* di;

    tl_assert(isIRAtom(addr));

    if (addr->tag == Iex_RdTmp)
    {
        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_WrTmp_Load",
                               VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Load),
                               mkIRExprVec_3(mkIRExpr_HWord(tmp),
                                             assignNew_HWord(sb_out, addr),
                                             mkIRExpr_HWord(size))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
    else // addr->tag == Iex_Const
    {
        tl_assert(addr->Iex.Const.con->tag == Ico_U32);

        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_WrTmp_Load",
                               VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Load),
                               mkIRExprVec_3(mkIRExpr_HWord(tmp),
                                             mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                             mkIRExpr_HWord(size))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
}
void instrument_WrTmp_Const(IRStmt* st, IRSB* sb_out) //
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRDirty* di;

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_Const",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Const),
                           mkIRExprVec_1(mkIRExpr_HWord(tmp))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Mux0X(IRStmt* st, IRSB* sb_out) //
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    IRExpr* cond = data->Iex.Mux0X.cond;
    IRExpr* expr0 = data->Iex.Mux0X.expr0;
    IRExpr* exprX = data->Iex.Mux0X.exprX;
    IRDirty* di;

    tl_assert(cond->tag == Iex_RdTmp);
    tl_assert(isIRAtom(expr0));
    tl_assert(isIRAtom(exprX));

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_Mux0X",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Mux0X),
                           mkIRExprVec_4(mkIRExpr_HWord(tmp),
                                         assignNew_HWord(sb_out, cond),
                                         mkIRExpr_HWord((expr0->tag == Iex_RdTmp) ? expr0->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord((exprX->tag == Iex_RdTmp) ? exprX->Iex.RdTmp.tmp : IRTemp_INVALID))
                                         );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp(IRStmt* st, IRSB* sb_out) //
{
    switch (st->Ist.WrTmp.data->tag)
    {
        case Iex_Binder:
        // we don't care about floating point and SIMD operations
        case Iex_Qop:
        case Iex_Triop:
            break;

        case Iex_Get:
            instrument_WrTmp_Get(st, sb_out);
            break;
        case Iex_GetI:
            instrument_WrTmp_GetI(st, sb_out);
            break;
        case Iex_RdTmp:
            instrument_WrTmp_RdTmp(st, sb_out);
            break;
        case Iex_Binop:
            instrument_WrTmp_Binop(st, sb_out);
            break;
        case Iex_Unop:
            instrument_WrTmp_Unop(st, sb_out);
            break;
        case Iex_Load:
            instrument_WrTmp_Load(st, sb_out);
            break;
        case Iex_Const:
            instrument_WrTmp_Const(st, sb_out);
            break;
        case Iex_CCall:
            // ppIRStmt(st);
            // VG_(printf)("\n");
            // TODO Iex_CCall
            break;
        case Iex_Mux0X:
            instrument_WrTmp_Mux0X(st, sb_out);
            break;
    }
}
void instrument_Store(IRStmt* st, IRSB* sb_out) //
{
    IRExpr* addr = st->Ist.Store.addr;
    IRExpr* data = st->Ist.Store.data;
    Int size = sizeofIRType(typeOfIRExpr(sb_out->tyenv, st->Ist.Store.data));
    IRDirty* di;

    tl_assert(isIRAtom(addr));
    tl_assert(isIRAtom(data));

    if (addr->tag == Iex_RdTmp)
    {
        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_Store",
                               VG_(fnptr_to_fnentry)(helper_instrument_Store),
                               mkIRExprVec_3(assignNew_HWord(sb_out, addr),
                                             mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord(size))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
    else // addr->tag == Iex_Const
    {
        tl_assert(addr->Iex.Const.con->tag == Ico_U32);

        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_Store",
                               VG_(fnptr_to_fnentry)(helper_instrument_Store),
                               mkIRExprVec_3(mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                             mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord(size))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
}
void instrument_CAS_single_element(IRStmt* st, IRSB* sb_out) //
{
    IRCAS* cas = st->Ist.CAS.details;
    IRTemp oldLo = cas->oldLo;
    IRExpr* addr = cas->addr;
    IRExpr* expdLo = cas->expdLo;
    IRExpr* dataLo = cas->dataLo;
    Int size;
    IROp op;
    IRExpr* expr;
    IRDirty* di;

    tl_assert(isIRAtom(addr));
    tl_assert(isIRAtom(dataLo));

    size = sizeofIRType(typeOfIRExpr(sb_out->tyenv, dataLo));

    switch (size)
    {
        case 1: op = Iop_CasCmpEQ8; break;
        case 2: op = Iop_CasCmpEQ16; break;
        case 4: op = Iop_CasCmpEQ32; break;
        default: VG_(tool_panic)("instrument_CAS_single_element");
    }

    expr = assignNew(sb_out, IRExpr_Binop(op, IRExpr_RdTmp(oldLo), expdLo)); // statement has to be flat

    if (addr->tag == Iex_RdTmp)
    {
        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_CAS_single_element",
                               VG_(fnptr_to_fnentry)(helper_instrument_CAS_single_element),
                               mkIRExprVec_4(assignNew_HWord(sb_out, addr),
                                             mkIRExpr_HWord((dataLo->tag == Iex_RdTmp) ? dataLo->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord(size),
                                             assignNew_HWord(sb_out, expr))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
    else // addr->tag == Iex_Const
    {
        tl_assert(addr->Iex.Const.con->tag == Ico_U32);

        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_CAS_single_element",
                               VG_(fnptr_to_fnentry)(helper_instrument_CAS_single_element),
                               mkIRExprVec_4(mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                             mkIRExpr_HWord((dataLo->tag == Iex_RdTmp) ? dataLo->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord(size),
                                             assignNew_HWord(sb_out, expr))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
}
void instrument_CAS_double_element(IRStmt* st, IRSB* sb_out) //
{
    IRCAS* cas = st->Ist.CAS.details;
    IRTemp oldHi = cas->oldHi, oldLo = cas->oldLo;
    IREndness end = cas->end;
    IRExpr* addr = cas->addr;
    IRExpr *expdHi = cas->expdHi, *expdLo = cas->expdLo;
    IRExpr *dataHi = cas->dataHi, *dataLo = cas->dataLo;
    Int size;
    IROp op;
    IRExpr *expr, *expr2;
    IRDirty* di;

    tl_assert(isIRAtom(addr));
    tl_assert(end == Iend_LE); // we assume endianness is little endian
    tl_assert(isIRAtom(dataLo));
    tl_assert(isIRAtom(dataHi));

    size = sizeofIRType(typeOfIRExpr(sb_out->tyenv, dataLo));

    switch (size)
    {
        case 1: op = Iop_CasCmpEQ8; break;
        case 2: op = Iop_CasCmpEQ16; break;
        case 4: op = Iop_CasCmpEQ32; break;
        default: VG_(tool_panic)("instrument_CAS_double_element");
    }

    expr = assignNew(sb_out, IRExpr_Binop(op, IRExpr_RdTmp(oldLo), expdLo)); // statement has to be flat
    expr2 = assignNew(sb_out, IRExpr_Binop(op, IRExpr_RdTmp(oldHi), expdHi)); // statement has to be flat

    if (addr->tag == Iex_RdTmp)
    {
        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_CAS_double_element",
                               VG_(fnptr_to_fnentry)(helper_instrument_CAS_double_element),
                               mkIRExprVec_6(assignNew_HWord(sb_out, addr),
                                             mkIRExpr_HWord((dataLo->tag == Iex_RdTmp) ? dataLo->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord((dataHi->tag == Iex_RdTmp) ? dataHi->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord(size),
                                             assignNew_HWord(sb_out, expr),
                                             assignNew_HWord(sb_out, expr2))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
    else // addr->tag == Iex_Const
    {
        tl_assert(addr->Iex.Const.con->tag == Ico_U32);

        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_CAS_double_element",
                               VG_(fnptr_to_fnentry)(helper_instrument_CAS_double_element),
                               mkIRExprVec_6(mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                             mkIRExpr_HWord((dataLo->tag == Iex_RdTmp) ? dataLo->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord((dataHi->tag == Iex_RdTmp) ? dataHi->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord(size),
                                             assignNew_HWord(sb_out, expr),
                                             assignNew_HWord(sb_out, expr2))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
}
void instrument_CAS(IRStmt* st, IRSB* sb_out) //
{
    if (st->Ist.CAS.details->oldHi == IRTemp_INVALID)
    {
        instrument_CAS_single_element(st, sb_out);
    }
    else
    {
        instrument_CAS_double_element(st, sb_out);
    }
}
void instrument_LLSC_Load_Linked(IRStmt* st, IRSB* sb_out) //
{
    IRTemp result = st->Ist.LLSC.result;
    IRExpr* addr = st->Ist.LLSC.addr;
    Int size = sizeofIRType(typeOfIRTemp(sb_out->tyenv, result));
    IRDirty* di;

    tl_assert(isIRAtom(addr));

    if (addr->tag == Iex_RdTmp)
    {
        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_LLSC_Load_Linked",
                               VG_(fnptr_to_fnentry)(helper_instrument_LLSC_Load_Linked),
                               mkIRExprVec_3(mkIRExpr_HWord(result),
                                             assignNew_HWord(sb_out, addr),
                                             mkIRExpr_HWord(size))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
    else // addr->tag == Iex_Const
    {
        tl_assert(addr->Iex.Const.con->tag == Ico_U32);

        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_LLSC_Load_Linked",
                               VG_(fnptr_to_fnentry)(helper_instrument_LLSC_Load_Linked),
                               mkIRExprVec_3(mkIRExpr_HWord(result),
                                             mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                             mkIRExpr_HWord(size))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
}
void instrument_LLSC_Store_Conditional(IRStmt* st, IRSB* sb_out) //
{
    IRTemp result = st->Ist.LLSC.result;
    IRExpr* addr = st->Ist.LLSC.addr;
    IRExpr* storedata = st->Ist.LLSC.storedata;
    Int size = sizeofIRType(typeOfIRExpr(sb_out->tyenv, storedata));
    IRExpr* result_expr = IRExpr_RdTmp(result);
    IRDirty* di;

    tl_assert(isIRAtom(addr));
    tl_assert(isIRAtom(storedata));

    if (addr->tag == Iex_RdTmp)
    {
        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_LLSC_Store_Conditional",
                               VG_(fnptr_to_fnentry)(helper_instrument_LLSC_Store_Conditional),
                               mkIRExprVec_4(assignNew_HWord(sb_out, addr),
                                             mkIRExpr_HWord((storedata->tag == Iex_RdTmp) ? storedata->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord(size),
                                             assignNew_HWord(sb_out, result_expr))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
    else // addr->tag == Iex_Const
    {
        tl_assert(addr->Iex.Const.con->tag == Ico_U32);

        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_LLSC_Store_Conditional",
                               VG_(fnptr_to_fnentry)(helper_instrument_LLSC_Store_Conditional),
                               mkIRExprVec_4(mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                             mkIRExpr_HWord((storedata->tag == Iex_RdTmp) ? storedata->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord(size),
                                             assignNew_HWord(sb_out, result_expr))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
}
void instrument_LLSC(IRStmt* st, IRSB* sb_out) //
{
    if (st->Ist.LLSC.storedata == NULL)
    {
        instrument_LLSC_Load_Linked(st, sb_out);
    }
    else
    {
        instrument_LLSC_Store_Conditional(st, sb_out);
    }
}
void instrument_Exit(IRStmt* st, IRSB* sb_out) //
{
    IRExpr* guard = st->Ist.Exit.guard;
    Int offsIP = st->Ist.Exit.offsIP;
    Int size = sizeofIRType(typeOfIRConst(st->Ist.Exit.dst));
    IRDirty* di;

    tl_assert(guard->tag == Iex_RdTmp);

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_Exit",
                           VG_(fnptr_to_fnentry)(helper_instrument_Exit),
                           mkIRExprVec_3(assignNew_HWord(sb_out, guard),
                                         mkIRExpr_HWord(offsIP),
                                         mkIRExpr_HWord(size))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}

//
//  BASIC TOOL FUNCTIONS
//

static void fz_post_clo_init(void)
{
    init_shadow_memory();
}

static
IRSB* fz_instrument ( VgCallbackClosure* closure,
                      IRSB* sb_in,
                      VexGuestLayout* layout,
                      VexGuestExtents* vge,
                      IRType gWordTy, IRType hWordTy )
{
    Int i;
    IRSB* sb_out;

    if (gWordTy != hWordTy) {
        /* We don't currently support this case. */
        VG_(tool_panic)("host/guest word size mismatch");
    }

    /* Set up SB */
    sb_out = deepCopyIRSBExceptStmts(sb_in);

    // Copy verbatim any IR preamble preceding the first IMark
    i = 0;
    while (i < sb_in->stmts_used && sb_in->stmts[i]->tag != Ist_IMark) {
        addStmtToIRSB(sb_out, sb_in->stmts[i]);
        i++;
    }

    for (/*use current i*/; i < sb_in->stmts_used; i++)
    {
        IRStmt* st = sb_in->stmts[i];
        if (!st)
            continue;

        switch (st->tag)
        {
            case Ist_NoOp:
            case Ist_IMark:
            case Ist_AbiHint:
            case Ist_Dirty:
            case Ist_MBE:
                break;

            case Ist_Put:
                instrument_Put(st, sb_out);
                break;
            case Ist_PutI:
                instrument_PutI(st, sb_out);
                break;
            case Ist_WrTmp:
                instrument_WrTmp(st, sb_out);
                break;
            case Ist_Store:
                instrument_Store(st, sb_out);
                break;
            case Ist_CAS:
                addStmtToIRSB(sb_out, st); // dirty helpers use temporaries (oldHi, oldLo) defined in the instruction
                instrument_CAS(st, sb_out);
                break;
            case Ist_LLSC:
                instrument_LLSC(st, sb_out);
                break;
            case Ist_Exit:
                instrument_Exit(st, sb_out);
                break;
        }

        if (st->tag != Ist_CAS) {
            addStmtToIRSB(sb_out, st);
        }
    }

    // ppIRSB(sb_in);

    return sb_out;
}

static void fz_fini(Int exitcode)
{
    destroy_shadow_memory();
}

static void fz_pre_clo_init(void)
{
   VG_(details_name)            ("DaFuzz");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("a concolic fuzzer");
   VG_(details_copyright_author)("Copyright (C) 2013, and GNU GPL'd, by Sonny Tavernier.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(details_avg_translation_sizeB) ( 275 );

   VG_(basic_tool_funcs)        (fz_post_clo_init,
                                 fz_instrument,
                                 fz_fini);

   /* No needs, no core events to track */
}

VG_DETERMINE_INTERFACE_VERSION(fz_pre_clo_init)
