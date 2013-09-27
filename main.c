#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "VEX/libvex.h"
#include "shadow_memory.h"
#include "taint_analysis.h"

void instrument_Put(IRStmt* st, IRTypeEnv* tyenv)
{
    Int data_size = sizeofIRType(typeOfIRExpr(tyenv, st->Ist.Put.data));

    if (register_is_tainted(st->Ist.Put.offset, data_size) != IRExpr_is_tainted(st->Ist.Put.data))
    {
        flip_register(st->Ist.Put.offset, data_size);
    }
}

void instrument_PutI()
{
}

void instrument_WrTmp(IRStmt* st, IRTypeEnv* tyenv)
{
    add_tmp_to_g_map(st->Ist.WrTmp.tmp, typeOfIRTemp(tyenv, st->Ist.WrTmp.tmp));

    if (temporary_is_tainted(st->Ist.WrTmp.tmp) != IRExpr_is_tainted(st->Ist.WrTmp.data))
    {
        flip_temporary(st->Ist.WrTmp.tmp);
    }
}

void instrument_Store(IRStmt* st, IRTypeEnv* tyenv)
{
    UInt store_address = get_address_from_IRExpr(st->Ist.Store.addr);
    Int data_size = sizeofIRType(typeOfIRExpr(tyenv, st->Ist.Store.data));

    if (memory_is_tainted(store_address, data_size) != IRExpr_is_tainted(st->Ist.Store.data)) {
        flip_memory(store_address, data_size);
    }
}

void instrument_CAS(IRStmt* st, IRTypeEnv* tyenv)
{
    IRCAS* cas = st->Ist.CAS.details;

    // tl_assert(cas->addr != NULL); //
    // tl_assert(cas->dataLo != NULL); //

    char is_double_element_cas = cas->dataHi != NULL;

    UInt store_address = get_address_from_IRExpr(cas->addr);

    Int data_size = sizeofIRType(typeOfIRExpr(tyenv, cas->dataLo));
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

void instrument_LLSC(IRStmt* st, IRTypeEnv* tyenv)
{
    // Load-Linked
    if (st->Ist.LLSC.storedata == NULL)
    {
        UInt load_address = get_address_from_IRExpr(st->Ist.LLSC.addr);
        Int data_size = sizeofIRType(typeOfIRTemp(tyenv, st->Ist.LLSC.result));

        if (temporary_is_tainted(st->Ist.LLSC.result) != memory_is_tainted(load_address, data_size)) {
            flip_temporary(st->Ist.LLSC.result);
        }
    }
    // Store-Conditional
    else
    {
        char store_succeeded = st->Ist.LLSC.result == 1;
        if (store_succeeded)
        {
            UInt store_address = get_address_from_IRExpr(st->Ist.LLSC.addr);
            Int data_size = sizeofIRType(typeOfIRExpr(tyenv, st->Ist.LLSC.storedata));

            if (memory_is_tainted(store_address, data_size) != IRExpr_is_tainted(st->Ist.LLSC.storedata)) {
                flip_memory(store_address, data_size);
            }
        }
    }
}

void instrument_Exit(IRStmt* st)
{
    if (st->Ist.Exit.guard) // IRType only RdTmp ?
    {
        Int data_size = sizeofIRType(typeOfIRConst(st->Ist.Exit.dst));

        if (register_is_tainted(st->Ist.Exit.offsIP, data_size)) {
            flip_register(st->Ist.Exit.offsIP, data_size);
        }
    }
}

IRSB* instrument(void* closure,
                IRSB* irsb,
                VexGuestLayout* layout,
                VexGuestExtents* vge,
                IRType gWordTy, IRType hWordTy)
{
    Int i;

    if (gWordTy != hWordTy) {
        /* We don't currently support this case. */
        // VG_(tool_panic)("host/guest word size mismatch");
    }

    // ignore any IR preamble preceding the first IMark
    i = 0;
    while (i < irsb->stmts_used && irsb->stmts[i]->tag != Ist_IMark) {
        i++;
    }

    for (/*use current i*/; i < irsb->stmts_used; i++)
    {
        IRStmt* st = irsb->stmts[i];
        if (!st || st->tag == Ist_NoOp) continue;

        switch (st->tag)
        {
            case Ist_NoOp:
            case Ist_IMark:
            case Ist_AbiHint:
            case Ist_Dirty:
            case Ist_MBE:
                break;

            case Ist_Put:
                instrument_Put(st, irsb->tyenv);
                break;
            case Ist_PutI:
                // TODO
                break;
            case Ist_WrTmp:
                instrument_WrTmp(st, irsb->tyenv);
                break;
            case Ist_Store:
                instrument_Store(st, irsb->tyenv);
                break;
            case Ist_CAS:
                instrument_CAS(st, irsb->tyenv);
                break;
            case Ist_LLSC:
                instrument_LLSC(st, irsb->tyenv);
                break;
            case Ist_Exit:
                // TODO
                break;
        }
    }

    /* */

    ppIRSB(irsb);

    return irsb;
}

void test()
{
    int x = 13;
    int y = 37;

    x = y;
}

void test2()
{
    int x = 13;
    int y = 37;
    int z = 1337;
    int t = x > 0 ? y : z;
}

__attribute__ ((noreturn)) void failure_exit(void) { fprintf(stderr, "failure_exit()\n"); }
void log_bytes(HChar* log, Int nbytes) { fprintf(stdout, "%s", log); }

Bool chase_into_ok(void* callback_opaque, Addr64 guest_address) { return True; }
UInt needs_self_check(void* callback_opaque, VexGuestExtents* guest_extents) { return 0; }
void disp_cp_chain_me_to_slowEP() {}
void disp_cp_chain_me_to_fastEP() {}
void disp_cp_xindir() {}
void disp_cp_xassisted() {}

int main(void)
{
    // init shadow memory
    init();

    /* LibVEX_Init */

    VexControl vcon;
    vcon.iropt_verbosity = 0;
    vcon.iropt_level = 0;
    vcon.iropt_register_updates = VexRegUpdUnwindregsAtMemAccess;
    vcon.iropt_unroll_thresh = 0;
    vcon.guest_max_insns = 50;
    vcon.guest_chase_thresh = 0;
    vcon.guest_chase_cond = False;

    LibVEX_Init(failure_exit, log_bytes, 0, False, &vcon);

    /* LibVEX_Translate */

    VexTranslateArgs vta;

    VexArchInfo vexArchInfo;
    memset(&vexArchInfo, 0, sizeof(VexArchInfo));
    VexAbiInfo vexAbiInfo;
    memset(&vexAbiInfo, 0, sizeof(VexAbiInfo));
    vta.arch_guest = VexArchX86;
    vta.archinfo_guest = vexArchInfo;
    vta.arch_host = VexArchX86;
    vta.archinfo_host = vexArchInfo;
    vta.abiinfo_both = vexAbiInfo;

    vta.callback_opaque = NULL;

    unsigned int block_addr = (unsigned int) test2;
    vta.guest_bytes = (UChar*) block_addr;
    vta.guest_bytes_addr = (Addr64) block_addr;

    vta.chase_into_ok = chase_into_ok;

    VexGuestExtents guest_extents;
    vta.guest_extents = &guest_extents;

    UChar host_bytes[1337];
    Int host_bytes_used;
    vta.host_bytes = host_bytes;
    vta.host_bytes_size = 1337;
    vta.host_bytes_used = &host_bytes_used;

    vta.instrument1 = instrument;
    vta.instrument2 = NULL;

    vta.finaltidy = NULL;

    vta.needs_self_check = needs_self_check;

    vta.preamble_function = NULL;

    vta.traceflags = 0;

    vta.addProfInc = False;

    vta.disp_cp_chain_me_to_slowEP = disp_cp_chain_me_to_slowEP;
    vta.disp_cp_chain_me_to_fastEP = disp_cp_chain_me_to_fastEP;
    vta.disp_cp_xindir = disp_cp_xindir;
    vta.disp_cp_xassisted = disp_cp_xassisted;

    LibVEX_Translate(&vta);

    // destroy shadow memory
    destroy();
}
