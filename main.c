
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "VEX/libvex.h"
#include "shadow_memory.h"
#include "taint_analysis.h"

void instrument_Put(IRStmt* st, IRTypeEnv* env)
{
	Int register_offset = st->Ist.Put.offset;
	IRExpr* data = st->Ist.Put.data;
	IRType type = typeOfIRExpr(env, data);
	
	// BAD
	if (!is_guest_reg_offset(register_offset))
		return;
		  		
	if (register_is_tainted(register_offset, type) != IRExpr_is_tainted(data))
	{
		flip_register(register_offset, type);
	}
}

void instrument_PutI()
{
}

void instrument_WrTmp(IRStmt* st, IRTypeEnv* env)
{
	IRTemp tmp = st->Ist.WrTmp.tmp;
	IRType type = typeOfIRTemp(env, tmp);
	IRExpr* data = st->Ist.WrTmp.data;
		  		
	add_tmp_to_g_map(tmp, type);
	
	// BAD
	if (data->tag == Iex_Get && !is_guest_reg_offset(data->Iex.Get.offset))
		return;
		  	
	if (temporary_is_tainted(tmp) != IRExpr_is_tainted(data))
	{
		flip_temporary(tmp);
	}
}

void instrument_Store(IRStmt* st)
{
	IRExpr* addr = st->Ist.Store.addr;
	IRExpr* data = st->Ist.Store.data;
		  		
	// assert(isIRAtom(data));
		  	
	if (addr->tag == Iex_RdTmp)
	{		  	
		IRTemp tmp_dst = addr->Iex.RdTmp.tmp;
			  		
		if (data->tag == Iex_RdTmp) // STle(t1) = t0
	  	{
	  		IRTemp tmp_src = data->Iex.RdTmp.tmp;
				  		
	  		if (temporary_is_tainted(tmp_dst) != temporary_is_tainted(tmp_src)) {
				flip_temporary(tmp_dst);
			}
	  	}
	  	else if (data->tag == Iex_Const) // STle(t5) = 0xD:I32
	  	{
	  		if (temporary_is_tainted(tmp_dst)) {
				flip_temporary(tmp_dst);
			}
	  	}
	}
	// TODO: else throw exception
}

void instrument_CAS()
{
}

void instrument_LLSC()
{
}

void instrument_Exit()
{
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
		  		instrument_Store(st);
		  		break;
		  	case Ist_CAS:
		  		// TODO
		  		break;
		  	case Ist_LLSC:
		  		// TODO
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
