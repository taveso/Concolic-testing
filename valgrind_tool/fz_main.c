#include "shadow_memory.h"
#include "taint_analysis.h"
#include "symbolic_execution.h"
#include "util.h"
#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"    // tl_assert()
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_machine.h"       // VG_(fnptr_to_fnentry)
#include "pub_tool_libcbase.h"      // VG_(strcmp)
#include "pub_tool_options.h"

// export VALGRIND_LIB=/home/fanatic/valgrind-3.8.1/inst/lib/valgrind/

Int sizeofIRType_bits(IRType ty)
{
    switch (ty)
    {
        case Ity_I1: return 1;
        case Ity_I8: return 8;
        case Ity_I16: return 16;
        case Ity_I32: return 32;
        case Ity_I64: return 64;
        case Ity_I128: return 128;
        case Ity_F32: return 32;
        case Ity_F64: return 64;
        case Ity_D32: return 32;
        case Ity_D64: return 64;
        case Ity_D128: return 128;
        case Ity_F128: return 128;
        case Ity_V128: return 128;
        case Ity_V256: return 256;
        default: VG_(tool_panic)("sizeofIRType_bits");
    }
}

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
        case Ity_I64:
            addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_64to32, expr)));
            break;
        default:
            VG_(tool_panic)("assignNew_HWord");
   }

    return IRExpr_RdTmp(tmp);
}

//
//  CONCOLIC EXECUTION HELPERS
//

static VG_REGPARM(0) void helper_instrument_Put(UInt offset, IRTemp data, UInt size)
{
    if (get_reg_from_offset(offset) == guest_INVALID)
    {
        tl_assert(!IRTemp_is_tainted(data));
        return;
    }

    if (register_is_tainted(offset) != IRTemp_is_tainted(data))
    {
        flip_register(offset, IRTemp_is_tainted(data));
    }

    if (IRTemp_is_tainted(data))
    {
        char dep[DEP_MAX_LEN] = {0};

        VG_(snprintf)(dep, DEP_MAX_LEN, "PUT(%s)", get_temporary_dep(data));

        update_register_dep(offset, size, dep);
    }
    else
    {
        free_register_dep(offset);
    }
}
static VG_REGPARM(0) void helper_instrument_PutI(UInt base, UInt ix, UInt bias, UInt nElems)
{
    UInt index = base+((ix+bias)%nElems);

    tl_assert(get_reg_from_offset(index) == guest_INVALID);
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Get(IRTemp tmp, UInt offset, UInt size)
{
    if (temporary_is_tainted(tmp) != register_is_tainted(offset))
    {
        flip_temporary(tmp);
    }

    if (register_is_tainted(offset))
    {
        char dep[DEP_MAX_LEN] = {0};

        VG_(snprintf)(dep, DEP_MAX_LEN, "GET(%s)", get_register_dep(offset));

        update_temporary_dep(tmp, dep, size);
    }
    else
    {
        free_temporary_dep(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_GetI(UInt base, UInt ix, UInt bias, UInt nElems)
{
    UInt index = base+((ix+bias)%nElems);

    tl_assert(get_reg_from_offset(index) == guest_INVALID);
}
static VG_REGPARM(0) void helper_instrument_WrTmp_RdTmp(IRTemp tmp_lhs, IRTemp tmp_rhs, UInt size)
{
    if (temporary_is_tainted(tmp_lhs) != temporary_is_tainted(tmp_rhs))
    {
        flip_temporary(tmp_lhs);
    }

    if (temporary_is_tainted(tmp_rhs))
    {
        char dep[DEP_MAX_LEN] = {0};

        VG_(snprintf)(dep, DEP_MAX_LEN, "RdTmp(%s)", get_temporary_dep(tmp_rhs));

        update_temporary_dep(tmp_lhs, dep, size);
    }
    else
    {
        free_temporary_dep(tmp_lhs);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Binop(IRTemp tmp, IRTemp arg1, IRTemp arg2, UInt op, UInt size, UInt arg1_value, UInt arg2_value)
{
    if (temporary_is_tainted(tmp) != (IRTemp_is_tainted(arg1) || IRTemp_is_tainted(arg2)))
    {
        flip_temporary(tmp);
    }

    if (IRTemp_is_tainted(arg1) || IRTemp_is_tainted(arg2))
    {
        char str[32] = {0};
        char dep[DEP_MAX_LEN] = {0};

        IROp_to_str(op, str);

        if (!IRTemp_is_tainted(arg1))
        {
            VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%u,%s)", str, arg1_value, get_temporary_dep(arg2));
        }
        else if (!IRTemp_is_tainted(arg2))
        {
            VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s,%u)", str, get_temporary_dep(arg1), arg2_value);
        }
        else
        {
            VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s,%s)", str, get_temporary_dep(arg1), get_temporary_dep(arg2));
        }

        update_temporary_dep(tmp, dep, size);
    }
    else
    {
        free_temporary_dep(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Unop(IRTemp tmp, IRTemp arg, UInt op, UInt size)
{
    if (temporary_is_tainted(tmp) != IRTemp_is_tainted(arg))
    {
        flip_temporary(tmp);
    }

    if (IRTemp_is_tainted(arg))
    {
        char str[32] = {0};
        char dep[DEP_MAX_LEN] = {0};

        IROp_to_str(op, str);

        VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s)", str, get_temporary_dep(arg));

        update_temporary_dep(tmp, dep, size);
    }
    else
    {
        free_temporary_dep(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Load(IRTemp tmp, UInt addr, UInt size)
{
    if (temporary_is_tainted(tmp) != memory_is_tainted(addr, size))
    {
        flip_temporary(tmp);
    }

    if (memory_is_tainted(addr, size))
    {
        char dep[DEP_MAX_LEN] = {0};
        char dep_rhs[DEP_MAX_LEN] = {0};

        VG_(snprintf)(dep, DEP_MAX_LEN, "LDle:%d(%s)", size, get_memory_dep(addr, size, dep_rhs));

        update_temporary_dep(tmp, dep, size);
    }
    else
    {
        free_temporary_dep(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Const(IRTemp tmp)
{
    if (temporary_is_tainted(tmp))
    {
        flip_temporary(tmp);

        free_temporary_dep(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_CCall_x86g_calculate_condition(IRTemp tmp, IRTemp cc_dep1, IRTemp cc_dep2, UInt cond, UInt cc_op_value, UInt cc_dep1_value, UInt cc_dep2_value)
{
    if (temporary_is_tainted(tmp) != (IRTemp_is_tainted(cc_dep1) || IRTemp_is_tainted(cc_dep2)))
    {
        flip_temporary(tmp);
    }

    if (IRTemp_is_tainted(cc_dep1) || IRTemp_is_tainted(cc_dep2))
    {
        char dep[DEP_MAX_LEN] = {0};

        if (!IRTemp_is_tainted(cc_dep1))
        {
            VG_(snprintf)(dep, DEP_MAX_LEN, "x86g_calculate_condition(%u, %u, %u, %s)", cond, cc_op_value, cc_dep1_value, get_temporary_dep(cc_dep2));
        }
        else if (!IRTemp_is_tainted(cc_dep2))
        {
            VG_(snprintf)(dep, DEP_MAX_LEN, "x86g_calculate_condition(%u, %u, %s, %u)", cond, cc_op_value, get_temporary_dep(cc_dep1), cc_dep2_value);
        }
        else
        {
            VG_(snprintf)(dep, DEP_MAX_LEN, "x86g_calculate_condition(%u, %u, %s, %s)", cond, cc_op_value, get_temporary_dep(cc_dep1), get_temporary_dep(cc_dep2));
        }

        update_temporary_dep(tmp, dep, 32); // 1 because x86g_calculate_condition returns UInt
    }
    else
    {
        free_temporary_dep(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_WrTmp_CCall_else()
{
    // VG_(printf)("helper_instrument_WrTmp_CCall_else\n");
}
static VG_REGPARM(0) void helper_instrument_WrTmp_Mux0X(IRTemp tmp, UInt cond, IRTemp expr0, IRTemp exprX, UInt size)
{
    char expr_is_tainted = (cond == 0) ? IRTemp_is_tainted(expr0) : IRTemp_is_tainted(exprX);

    if (temporary_is_tainted(tmp) != expr_is_tainted)
    {
        flip_temporary(tmp);
    }

    if (expr_is_tainted)
    {
        char dep[DEP_MAX_LEN] = {0};

        VG_(snprintf)(dep, DEP_MAX_LEN, "Mux0X(%s)", (cond == 0 ? get_temporary_dep(expr0) : get_temporary_dep(exprX)));

        update_temporary_dep(tmp, dep, size);
    }
    else
    {
        free_temporary_dep(tmp);
    }
}
static VG_REGPARM(0) void helper_instrument_Store(UInt addr, IRTemp data, UInt size)
{
    if (memory_is_tainted(addr, size) != IRTemp_is_tainted(data))
    {
        flip_memory(addr, size, IRTemp_is_tainted(data));
    }

    if (IRTemp_is_tainted(data))
    {
        char dep[DEP_MAX_LEN] = {0};

        VG_(snprintf)(dep, DEP_MAX_LEN, "STle(%s)", get_temporary_dep(data));

        update_memory_dep(addr, dep, size);
    }
    else
    {
        free_memory_dep(addr, size);
    }
}
static VG_REGPARM(0) void helper_instrument_CAS_single_element(UInt addr, IRTemp dataLo, UInt size, UInt cas_succeeded)
{
    if (cas_succeeded)
    {
        if (memory_is_tainted(addr, size) != IRTemp_is_tainted(dataLo))
        {
            flip_memory(addr, size, IRTemp_is_tainted(dataLo));
        }

        if (IRTemp_is_tainted(dataLo))
        {
            char dep[DEP_MAX_LEN] = {0};

            VG_(snprintf)(dep, DEP_MAX_LEN, "CASle(%s)", get_temporary_dep(dataLo));

            update_memory_dep(addr, dep, size);
        }
        else
        {
            free_memory_dep(addr, size);
        }
    }
}
static VG_REGPARM(0) void helper_instrument_CAS_double_element(UInt addr, IRTemp dataLo, IRTemp dataHi, UInt size, UInt oldLo_succeeded, UInt oldHi_succeeded)
{
    char cas_succeeded = oldLo_succeeded && oldHi_succeeded;

    if (cas_succeeded)
    {
        if (memory_is_tainted(addr, size) != IRTemp_is_tainted(dataLo))
        {
            flip_memory(addr, size, IRTemp_is_tainted(dataLo));
        }

        if (memory_is_tainted(addr+size, size) != IRTemp_is_tainted(dataHi))
        {
            flip_memory(addr+size, size, IRTemp_is_tainted(dataHi));
        }

        if (IRTemp_is_tainted(dataLo))
        {
            char dep[DEP_MAX_LEN] = {0};

            VG_(snprintf)(dep, DEP_MAX_LEN, "CASle(%s)", get_temporary_dep(dataLo));

            update_memory_dep(addr, dep, size);
        }
        else
        {
            free_memory_dep(addr, size);
        }

        if (IRTemp_is_tainted(dataHi))
        {
            char dep[DEP_MAX_LEN] = {0};

            VG_(snprintf)(dep, DEP_MAX_LEN, "CASle(%s)", get_temporary_dep(dataHi));

            update_memory_dep(addr+size, dep, size);
        }
        else
        {
            free_memory_dep(addr+size, size);
        }
    }
}
static VG_REGPARM(0) void helper_instrument_LLSC_Load_Linked(IRTemp result, UInt addr, UInt size)
{
    if (temporary_is_tainted(result) != memory_is_tainted(addr, size))
    {
        flip_temporary(result);
    }

    if (memory_is_tainted(addr, size))
    {
        char dep[DEP_MAX_LEN] = {0};
        char dep_rhs[DEP_MAX_LEN] = {0};

        VG_(snprintf)(dep, DEP_MAX_LEN, "LDle-Linked(%s)", get_memory_dep(addr, size, dep_rhs));

        update_temporary_dep(result, dep, size);
    }
    else
    {
        free_temporary_dep(result);
    }
}
static VG_REGPARM(0) void helper_instrument_LLSC_Store_Conditional(UInt addr, IRTemp storedata, UInt size, UInt store_succeeded)
{
    if (store_succeeded)
    {
        if (memory_is_tainted(addr, size) != IRTemp_is_tainted(storedata))
        {
            flip_memory(addr, size, IRTemp_is_tainted(storedata));
        }

        if (IRTemp_is_tainted(storedata))
        {
            char dep[DEP_MAX_LEN] = {0};

            VG_(snprintf)(dep, DEP_MAX_LEN, "STle-Cond(%s)", get_temporary_dep(storedata));

            update_memory_dep(addr, dep, size);
        }
        else
        {
            free_memory_dep(addr, size);
        }
    }
}
static VG_REGPARM(0) void helper_instrument_Exit(UInt branch_is_taken, UInt offsIP, UInt size, UInt guard)
{
    if (branch_is_taken)
    {
        if (register_is_tainted(offsIP))
        {
            flip_register(offsIP, 0);

            free_register_dep(offsIP);
        }
    }

    if (temporary_is_tainted(guard))
    {
        char* dep = get_temporary_dep(guard);

        if (branch_is_taken)
            VG_(printf)("branch: TAKEN(%s)\n\n", dep);
        else
            VG_(printf)("branch: NOT_TAKEN(%s)\n\n", dep);
    }
}
static VG_REGPARM(0) void helper_instrument_superblock()
{
    unsigned int i;

    for (i = 0; i < MAX_TEMPORARIES; i++)
    {
        if (temporary_is_tainted(i))
        {
            flip_temporary(i);
            free_temporary_dep(i);
        }
    }
}

//
//  VEX INSTRUMENTATION FUNCTIONS
//

void instrument_Put(IRStmt* st, IRSB* sb_out)
{
    Int offset = st->Ist.Put.offset;
    IRExpr* data = st->Ist.Put.data;
    Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, data));
    IRDirty* di;

    tl_assert(isIRAtom(data));
    // the data transfer type is the type of data

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
    i.e. not the registers we are shadowing (in principle), no harm in verifying though.
*/
void instrument_PutI(IRStmt* st, IRSB* sb_out)
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
void instrument_WrTmp_Get(IRStmt* st, IRSB* sb_out)
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    Int offset = data->Iex.Get.offset;
    Int size = sizeofIRType_bits(data->Iex.Get.ty);
    IRDirty* di;

    tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == data->Iex.Get.ty);

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
    i.e. not the registers we are shadowing (in principle), no harm in verifying though.
*/
void instrument_WrTmp_GetI(IRStmt* st, IRSB* sb_out)
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
void instrument_WrTmp_RdTmp(IRStmt* st, IRSB* sb_out)
{
    IRTemp tmp_lhs = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    IRTemp tmp_rhs = data->Iex.RdTmp.tmp;
    Int size = sizeofIRType_bits(typeOfIRTemp(sb_out->tyenv, tmp_rhs));
    IRDirty* di;

    tl_assert(typeOfIRTemp(sb_out->tyenv, tmp_lhs) == typeOfIRTemp(sb_out->tyenv, tmp_rhs));

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_RdTmp",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_RdTmp),
                           mkIRExprVec_3(mkIRExpr_HWord(tmp_lhs),
                                         mkIRExpr_HWord(tmp_rhs),
                                         mkIRExpr_HWord(size))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Binop(IRStmt* st, IRSB* sb_out)
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    IROp op = data->Iex.Binop.op;
    IRExpr* arg1 = data->Iex.Binop.arg1;
    IRExpr* arg2 = data->Iex.Binop.arg2;
    UInt arg1_value = 0, arg2_value = 0;
    IRExpr* expr = IRExpr_Binop(op, arg1, arg2);
    Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, expr));
    IRDirty* di;

    // we don't care about floating point and SIMD operations
    if (op > Iop_AddF64)
        return;

    tl_assert(isIRAtom(arg1));
    tl_assert(isIRAtom(arg2));
    tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == typeOfIRExpr(sb_out->tyenv, expr));

    if (arg1->tag == Iex_Const)
    {
        switch (arg1->Iex.Const.con->tag)
        {
            case Ico_U1: arg1_value = arg1->Iex.Const.con->Ico.U1; break;
            case Ico_U8: arg1_value = arg1->Iex.Const.con->Ico.U8; break;
            case Ico_U16: arg1_value = arg1->Iex.Const.con->Ico.U16; break;
            case Ico_U32: arg1_value = arg1->Iex.Const.con->Ico.U32; break;
            case Ico_U64: arg1_value = arg1->Iex.Const.con->Ico.U64; break;
            default: VG_(tool_panic)("instrument_WrTmp_Binop");
        }
    }
    if (arg2->tag == Iex_Const)
    {
        switch (arg2->Iex.Const.con->tag)
        {
            case Ico_U1: arg2_value = arg2->Iex.Const.con->Ico.U1; break;
            case Ico_U8: arg2_value = arg2->Iex.Const.con->Ico.U8; break;
            case Ico_U16: arg2_value = arg2->Iex.Const.con->Ico.U16; break;
            case Ico_U32: arg2_value = arg2->Iex.Const.con->Ico.U32; break;
            case Ico_U64: arg2_value = arg2->Iex.Const.con->Ico.U64; break;
            default: VG_(tool_panic)("instrument_WrTmp_Binop");
        }
    }

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_Binop",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Binop),
                           mkIRExprVec_7(mkIRExpr_HWord(tmp),
                                         mkIRExpr_HWord((arg1->tag == Iex_RdTmp) ? arg1->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord((arg2->tag == Iex_RdTmp) ? arg2->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord(op),
                                         mkIRExpr_HWord(size),
                                         (arg1->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, arg1) : mkIRExpr_HWord(arg1_value),
                                         (arg2->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, arg2) : mkIRExpr_HWord(arg2_value))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Unop(IRStmt* st, IRSB* sb_out)
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    IROp op = data->Iex.Unop.op;
    IRExpr* arg = data->Iex.Unop.arg;
    IRExpr* expr = IRExpr_Unop(op, arg);
    Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, expr));
    IRDirty* di;

    tl_assert(isIRAtom(arg));
    tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == typeOfIRExpr(sb_out->tyenv, expr));

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_Unop",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Unop),
                           mkIRExprVec_4(mkIRExpr_HWord(tmp),
                                         mkIRExpr_HWord((arg->tag == Iex_RdTmp) ? arg->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord(op),
                                         mkIRExpr_HWord(size))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Load(IRStmt* st, IRSB* sb_out)
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    IRExpr* addr = data->Iex.Load.addr;
    Int size = sizeofIRType_bits(data->Iex.Load.ty);
    IRDirty* di;

    tl_assert(isIRAtom(addr));
    if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
    tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == data->Iex.Load.ty);

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_Load",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Load),
                           mkIRExprVec_3(mkIRExpr_HWord(tmp),
                                         (addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                         mkIRExpr_HWord(size))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Const(IRStmt* st, IRSB* sb_out)
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
/*
    cc_op
        add/sub/mul
        adc/sbb
        shl/Shl/sar
            tmp = cond(cc_op(cc_dep1, cc_dep2))
        and/or/xor
        inc/dec
        rol/ror
            tmp = cond(cc_op(cc_dep1, 0))

    The taintness of tmp depends on taintness of both args. (we can't handle and(cc_dep1, 0) which gives an untainted result)
    cf. valgrind guest_x86_defs.h
*/
void instrument_WrTmp_CCall(IRStmt* st, IRSB* sb_out)
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    IRCallee* cee = data->Iex.CCall.cee;
    IRExpr** args = data->Iex.CCall.args;
    IRDirty* di;

    if (VG_(strcmp)(cee->name, "x86g_calculate_condition") == 0)
    {
        IRExpr* cond = args[0];
        IRExpr* cc_op = args[1];
        IRExpr* cc_dep1 = args[2];
        IRExpr* cc_dep2 = args[3];

        tl_assert(cond->tag == Iex_Const && cond->Iex.Const.con->tag == Ico_U32);
        tl_assert(isIRAtom(cc_op));
        tl_assert(isIRAtom(cc_dep1));
        tl_assert(isIRAtom(cc_dep2));
        if (cc_op->tag == Iex_Const) tl_assert(cc_op->Iex.Const.con->tag == Ico_U32);
        if (cc_dep1->tag == Iex_Const) tl_assert(cc_dep1->Iex.Const.con->tag == Ico_U32);
        if (cc_dep2->tag == Iex_Const) tl_assert(cc_dep2->Iex.Const.con->tag == Ico_U32);
        // typeOf(x86g_calculate_condition) == typeOf(tmp) == I32

        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_WrTmp_CCall_x86g_calculate_condition",
                               VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_CCall_x86g_calculate_condition),
                               mkIRExprVec_7(mkIRExpr_HWord(tmp),
                                             mkIRExpr_HWord((cc_dep1->tag == Iex_RdTmp) ? cc_dep1->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord((cc_dep2->tag == Iex_RdTmp) ? cc_dep2->Iex.RdTmp.tmp : IRTemp_INVALID),
                                             mkIRExpr_HWord(cond->Iex.Const.con->Ico.U32),
                                             (cc_op->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, cc_op) : mkIRExpr_HWord(cc_op->Iex.Const.con->Ico.U32),
                                             (cc_dep1->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, cc_dep1) : mkIRExpr_HWord(cc_dep1->Iex.Const.con->Ico.U32),
                                             (cc_dep2->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, cc_dep2) : mkIRExpr_HWord(cc_dep2->Iex.Const.con->Ico.U32))
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
    else {
        di = unsafeIRDirty_0_N(0,
                               "helper_instrument_WrTmp_CCall_else",
                               VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_CCall_else),
                               mkIRExprVec_0()
                               );
        addStmtToIRSB(sb_out, IRStmt_Dirty(di));
    }
}
void instrument_WrTmp_Mux0X(IRStmt* st, IRSB* sb_out)
{
    IRTemp tmp = st->Ist.WrTmp.tmp;
    IRExpr* data = st->Ist.WrTmp.data;
    IRExpr* cond = data->Iex.Mux0X.cond;
    IRExpr* expr0 = data->Iex.Mux0X.expr0;
    IRExpr* exprX = data->Iex.Mux0X.exprX;
    Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, expr0));
    IRDirty* di;

    tl_assert(cond->tag == Iex_RdTmp);
    tl_assert(isIRAtom(expr0));
    tl_assert(isIRAtom(exprX));
    tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == typeOfIRExpr(sb_out->tyenv, expr0));
    tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == typeOfIRExpr(sb_out->tyenv, exprX));

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_WrTmp_Mux0X",
                           VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Mux0X),
                           mkIRExprVec_5(mkIRExpr_HWord(tmp),
                                         assignNew_HWord(sb_out, cond),
                                         mkIRExpr_HWord((expr0->tag == Iex_RdTmp) ? expr0->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord((exprX->tag == Iex_RdTmp) ? exprX->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord(size))
                            );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp(IRStmt* st, IRSB* sb_out)
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
            instrument_WrTmp_CCall(st, sb_out);
            break;
        case Iex_Mux0X:
            instrument_WrTmp_Mux0X(st, sb_out);
            break;
    }
}
void instrument_Store(IRStmt* st, IRSB* sb_out)
{
    IRExpr* addr = st->Ist.Store.addr;
    IRExpr* data = st->Ist.Store.data;
    Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, st->Ist.Store.data));
    IRDirty* di;

    tl_assert(isIRAtom(addr));
    tl_assert(isIRAtom(data));
    if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
    // the data transfer type is the type of data

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_Store",
                           VG_(fnptr_to_fnentry)(helper_instrument_Store),
                           mkIRExprVec_3((addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                         mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord(size))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_CAS_single_element(IRStmt* st, IRSB* sb_out)
{
    IRCAS* cas = st->Ist.CAS.details;
    IRTemp oldLo = cas->oldLo;
    IRExpr* addr = cas->addr;
    IRExpr* expdLo = cas->expdLo;
    IRExpr* dataLo = cas->dataLo;
    Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, dataLo));
    IROp op;
    IRExpr* expr;
    IRDirty* di;

    tl_assert(isIRAtom(addr));
    tl_assert(isIRAtom(dataLo));
    if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
    tl_assert(typeOfIRExpr(sb_out->tyenv, addr) == typeOfIRExpr(sb_out->tyenv, dataLo));

    switch (size)
    {
        case 8: op = Iop_CasCmpEQ8; break;
        case 16: op = Iop_CasCmpEQ16; break;
        case 32: op = Iop_CasCmpEQ32; break;
        default: VG_(tool_panic)("instrument_CAS_single_element");
    }

    expr = assignNew(sb_out, IRExpr_Binop(op, IRExpr_RdTmp(oldLo), expdLo)); // statement has to be flat

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_CAS_single_element",
                           VG_(fnptr_to_fnentry)(helper_instrument_CAS_single_element),
                           mkIRExprVec_4((addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                         mkIRExpr_HWord((dataLo->tag == Iex_RdTmp) ? dataLo->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord(size),
                                         assignNew_HWord(sb_out, expr))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_CAS_double_element(IRStmt* st, IRSB* sb_out)
{
    IRCAS* cas = st->Ist.CAS.details;
    IRTemp oldHi = cas->oldHi, oldLo = cas->oldLo;
    IREndness end = cas->end;
    IRExpr* addr = cas->addr;
    IRExpr *expdHi = cas->expdHi, *expdLo = cas->expdLo;
    IRExpr *dataHi = cas->dataHi, *dataLo = cas->dataLo;
    Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, dataLo));
    IROp op;
    IRExpr *expr, *expr2;
    IRDirty* di;

    tl_assert(isIRAtom(addr));
    tl_assert(end == Iend_LE); // we assume endianness is little endian
    tl_assert(isIRAtom(dataLo));
    tl_assert(isIRAtom(dataHi));
    if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
    tl_assert(typeOfIRExpr(sb_out->tyenv, addr) == typeOfIRExpr(sb_out->tyenv, dataLo));

    switch (size)
    {
        case 8: op = Iop_CasCmpEQ8; break;
        case 16: op = Iop_CasCmpEQ16; break;
        case 32: op = Iop_CasCmpEQ32; break;
        default: VG_(tool_panic)("instrument_CAS_double_element");
    }

    expr = assignNew(sb_out, IRExpr_Binop(op, IRExpr_RdTmp(oldLo), expdLo)); // statement has to be flat
    expr2 = assignNew(sb_out, IRExpr_Binop(op, IRExpr_RdTmp(oldHi), expdHi)); // statement has to be flat

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_CAS_double_element",
                           VG_(fnptr_to_fnentry)(helper_instrument_CAS_double_element),
                           mkIRExprVec_6((addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                         mkIRExpr_HWord((dataLo->tag == Iex_RdTmp) ? dataLo->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord((dataHi->tag == Iex_RdTmp) ? dataHi->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord(size),
                                         assignNew_HWord(sb_out, expr),
                                         assignNew_HWord(sb_out, expr2))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_CAS(IRStmt* st, IRSB* sb_out)
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
void instrument_LLSC_Load_Linked(IRStmt* st, IRSB* sb_out)
{
    IRTemp result = st->Ist.LLSC.result;
    IRExpr* addr = st->Ist.LLSC.addr;
    Int size = sizeofIRType_bits(typeOfIRTemp(sb_out->tyenv, result));
    IRDirty* di;

    tl_assert(isIRAtom(addr));
    if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
    // the data transfer type is the type of result

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_LLSC_Load_Linked",
                           VG_(fnptr_to_fnentry)(helper_instrument_LLSC_Load_Linked),
                           mkIRExprVec_3(mkIRExpr_HWord(result),
                                         (addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                         mkIRExpr_HWord(size))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_LLSC_Store_Conditional(IRStmt* st, IRSB* sb_out)
{
    IRTemp result = st->Ist.LLSC.result;
    IRExpr* addr = st->Ist.LLSC.addr;
    IRExpr* storedata = st->Ist.LLSC.storedata;
    Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, storedata));
    IRExpr* result_expr = IRExpr_RdTmp(result);
    IRDirty* di;

    tl_assert(isIRAtom(addr));
    tl_assert(isIRAtom(storedata));
    if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
    // the data transfer type is the type of storedata

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_LLSC_Store_Conditional",
                           VG_(fnptr_to_fnentry)(helper_instrument_LLSC_Store_Conditional),
                           mkIRExprVec_4((addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                                         mkIRExpr_HWord((storedata->tag == Iex_RdTmp) ? storedata->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord(size),
                                         assignNew_HWord(sb_out, result_expr))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_LLSC(IRStmt* st, IRSB* sb_out)
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
void instrument_Exit(IRStmt* st, IRSB* sb_out)
{
    IRExpr* guard = st->Ist.Exit.guard;
    Int offsIP = st->Ist.Exit.offsIP;
    Int size = sizeofIRType_bits(typeOfIRConst(st->Ist.Exit.dst));
    IRDirty* di;

    tl_assert(guard->tag == Iex_RdTmp);

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_Exit",
                           VG_(fnptr_to_fnentry)(helper_instrument_Exit),
                           mkIRExprVec_4(assignNew_HWord(sb_out, guard),
                                         mkIRExpr_HWord(offsIP),
                                         mkIRExpr_HWord(size),
                                         mkIRExpr_HWord(guard->Iex.RdTmp.tmp))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}

//
//  SYSCALL WRAPPERS
//

#define SYS_READ    3
#define SYS_OPEN    5
// #define TEST_FILE   "test.txt"
static Char* clo_fnname = NULL;

int fd_to_taint = 0;

void handle_sys_read(UWord* args, SysRes res)
{
    int fd;
    void* buf;
    unsigned long i;

    if (res._isError == 0)
    {
        fd = (int)args[0];
        buf = (void*)args[1];

        if (fd == fd_to_taint)
        {
            VG_(printf)("read(%p) = %lu\n", buf, res._val);

            for (i = 0; i < res._val; i++)
            {
                if (!memory_is_tainted(((UInt)buf)+i, 8))
                {
                    flip_memory(((UInt)buf)+i, 8, 1);
                }

                char dep[DEP_MAX_LEN] = {0};
                VG_(snprintf)(dep, DEP_MAX_LEN, "INPUT(%lu)", i);

                update_memory_dep(((UInt)buf)+i, dep, 8);
            }
        }
    }
}

void handle_sys_open(UWord* args, SysRes res)
{
    const char* pathname;

    if (res._isError == 0)
    {
        pathname = (const char *)args[0];

        if (VG_(strcmp)(pathname, clo_fnname) == 0)
        {
            VG_(printf)("open(\"%s\", ..) = %lu\n", pathname, res._val);
            fd_to_taint = res._val;
        }
    }
}

static void pre_syscall(ThreadId tId, UInt syscall_number, UWord* args, UInt nArgs)
{
}

static void post_syscall(ThreadId tId, UInt syscall_number, UWord* args, UInt nArgs, SysRes res)
{
    switch (syscall_number)
    {
        case SYS_READ:
            handle_sys_read(args, res);
            break;
        case SYS_OPEN:
            handle_sys_open(args, res);
            break;
    }
}

//
//  BASIC TOOL FUNCTIONS
//

static Bool fz_process_cmd_line_option(Char* arg)
{
    if VG_STR_CLO(arg, "--fname", clo_fnname) {}

    tl_assert(clo_fnname);
    tl_assert(clo_fnname[0]);
    return True;
}

static void fz_print_usage(void)
{
   VG_(printf)(
"    --fnname=<filename>           file to taint\n"
   );
}

static void fz_print_debug_usage(void)
{
   VG_(printf)(
"    (none)\n"
   );
}

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
    IRDirty* di;

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

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_superblock",
                           VG_(fnptr_to_fnentry)(helper_instrument_superblock),
                           mkIRExprVec_0()
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));

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

    // ppIRSB(sb_out);

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

   VG_(needs_command_line_options)(fz_process_cmd_line_option,
                                   fz_print_usage,
                                   fz_print_debug_usage);

   VG_(needs_syscall_wrapper)   (pre_syscall, post_syscall);

   /* No needs, no core events to track */
}

VG_DETERMINE_INTERFACE_VERSION(fz_pre_clo_init)
