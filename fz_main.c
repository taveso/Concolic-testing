#include "shadow_memory.h"
#include "taint_analysis.h"
#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"    // tl_assert()
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_mallocfree.h"    // VG_(malloc) VG_(free)
#include "pub_tool_machine.h"       // VG_(fnptr_to_fnentry)

static VG_REGPARM(0) void helper_instrument_Put(UInt offset, IRTemp data, UInt data_size)
{
    // VG_(printf)("helper_instrument_Put: offset: %u - data: %u - data_size: %u\n", offset, data, data_size);

    if (register_is_tainted(offset, data_size) != IRTemp_is_tainted(data))
    {
        flip_register(offset, data_size);
    }
}

void instrument_Put(IRStmt* st, IRSB* sb_out)
{
    Int offset = st->Ist.Put.offset;
    IRExpr* data = st->Ist.Put.data;
    Int data_size = sizeofIRType(typeOfIRExpr(sb_out->tyenv, data));
    IRDirty* di;

    tl_assert(isIRAtom(data));

    di = unsafeIRDirty_0_N(0,
                           "helper_instrument_Put",
                           VG_(fnptr_to_fnentry)(helper_instrument_Put),
                           mkIRExprVec_3(mkIRExpr_HWord(offset),
                                         mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : IRTemp_INVALID),
                                         mkIRExpr_HWord(data_size))
                           );
    addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}

void instrument_PutI()
{
}

void instrument_WrTmp(IRStmt* st, IRSB* sb_out)
{
    if (temporary_is_tainted(st->Ist.WrTmp.tmp) != IRExpr_is_tainted(st->Ist.WrTmp.data))
    {
        flip_temporary(st->Ist.WrTmp.tmp);
    }
}

void instrument_Store(IRStmt* st, IRSB* sb_out)
{
    Int data_size = sizeofIRType(typeOfIRExpr(sb_out->tyenv, st->Ist.Store.data));

    if (IRAtom_addr_is_tainted(st->Ist.Store.addr, data_size) != IRAtom_is_tainted(st->Ist.Store.data))
    {
        flip_memory(get_IRAtom_addr(st->Ist.Store.addr), data_size);
    }
}

void instrument_CAS(IRStmt* st, IRSB* sb_out)
{
    IRCAS* cas = st->Ist.CAS.details;

    tl_assert(cas->addr != NULL);
    tl_assert(cas->dataLo != NULL);

    char is_double_element_cas = cas->dataHi != NULL;

    UInt store_address = get_IRAtom_addr(cas->addr);

    Int data_size = sizeofIRType(typeOfIRExpr(sb_out->tyenv, cas->dataLo));
    if (is_double_element_cas)
        data_size *= 2;

    if (is_double_element_cas)
    {
        if (memory_is_tainted(store_address, data_size) != (IRExpr_is_tainted(cas->dataLo) || IRExpr_is_tainted(cas->dataHi))) {
            flip_memory(store_address, data_size);
        }
    }
    else
    {
        if (memory_is_tainted(store_address, data_size) != IRExpr_is_tainted(cas->dataLo)) {
            flip_memory(store_address, data_size);
        }
    }
}

void instrument_LLSC(IRStmt* st, IRSB* sb_out)
{
    // Load-Linked
    if (st->Ist.LLSC.storedata == NULL)
    {
        UInt load_address = get_IRAtom_addr(st->Ist.LLSC.addr);
        Int data_size = sizeofIRType(typeOfIRTemp(sb_out->tyenv, st->Ist.LLSC.result));

        if (temporary_is_tainted(st->Ist.LLSC.result) != memory_is_tainted(load_address, data_size)) {
            flip_temporary(st->Ist.LLSC.result);
        }
    }
    // Store-Conditional
    else
    {
//        char store_succeeded = st->Ist.LLSC.result == 1;
//        if (store_succeeded)
//        {
            UInt store_address = get_IRAtom_addr(st->Ist.LLSC.addr);
            Int data_size = sizeofIRType(typeOfIRExpr(sb_out->tyenv, st->Ist.LLSC.storedata));

            if (memory_is_tainted(store_address, data_size) != IRExpr_is_tainted(st->Ist.LLSC.storedata)) {
                flip_memory(store_address, data_size);
            }
//        }
    }
}

void instrument_Exit(IRStmt* st)
{
    tl_assert(st->Ist.Exit.guard->tag == Iex_RdTmp);

    if (st->Ist.Exit.guard) // if <guard> is true // TODO: st->Ist.Exit.guard value ?
    {
        Int data_size = sizeofIRType(typeOfIRConst(st->Ist.Exit.dst));

        if (register_is_tainted(st->Ist.Exit.offsIP, data_size)) {
            flip_register(st->Ist.Exit.offsIP, data_size);
        }
    }
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

    if (gWordTy != hWordTy) {
        /* We don't currently support this case. */
        VG_(tool_panic)("host/guest word size mismatch");
    }

    sb_out = deepCopyIRSBExceptStmts(sb_in);

    // ignore any IR preamble preceding the first IMark
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
                // TODO
                break;
            case Ist_WrTmp:
                instrument_WrTmp(st, sb_out);
                break;
            case Ist_Store:
                instrument_Store(st, sb_out);
                break;
            case Ist_CAS:
                instrument_CAS(st, sb_out);
                break;
            case Ist_LLSC:
                instrument_LLSC(st, sb_out);
                break;
            case Ist_Exit:
                // TODO
                break;
        }

        addStmtToIRSB(sb_out, st);
    }

    /* */

    // ppIRSB(sb_in);

    return sb_out;
}

static void fz_fini(Int exitcode)
{
    destroy_shadow_memory();
}

static void fz_pre_clo_init(void)
{
   VG_(details_name)            ("Nulgrind");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("the minimal Valgrind tool");
   VG_(details_copyright_author)(
      "Copyright (C) 2002-2012, and GNU GPL'd, by Nicholas Nethercote.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(details_avg_translation_sizeB) ( 275 );

   VG_(basic_tool_funcs)        (fz_post_clo_init,
                                 fz_instrument,
                                 fz_fini);

   /* No needs, no core events to track */
}

VG_DETERMINE_INTERFACE_VERSION(fz_pre_clo_init)
