#ifndef _TAINT_ANALYSIS_H
#define _TAINT_ANALYSIS_H

#include "shadow_memory.h"
#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

/* VEX */

char IRExpr_is_tainted(IRExpr* expr);
char Get_is_tainted(IRExpr* expr);
char Unop_is_tainted(IRExpr* expr);
char Binop_is_tainted(IRExpr* expr);
char Load_is_tainted(IRExpr* expr);
char Mux0X_is_tainted(IRExpr* expr, IRSB* irsb);

char IRAtom_is_tainted(IRExpr* expr);
char IRAtom_addr_is_tainted(IRExpr* expr, Int size);

char IRTemp_is_tainted(IRTemp tmp);

/* MEMORY */

char byte_is_tainted(UInt addr);
char word_is_tainted(UInt addr);
char dword_is_tainted(UInt addr);
char memory_is_tainted(UInt addr, Int size);

/* REGISTERS */

char register8_is_tainted(Register reg);
char register16_is_tainted(Register reg);
char register32_is_tainted(Register reg);
char register_is_tainted(Int offset, Int size);

/* TEMPORARIES */

char temporary_is_tainted(IRTemp tmp);

/* UTILS */

UInt get_IRAtom_addr(IRExpr* expr);

#endif // TAINT_ANALYSIS_H
