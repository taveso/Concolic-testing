#ifndef _TAINT_ANALYSIS_H
#define _TAINT_ANALYSIS_H

#include "shadow_memory.h"
#include "VEX/libvex.h"

char IRExpr_is_tainted(IRExpr* expr);
char Get_is_tainted(IRExpr* expr);
char Unop_is_tainted(IRExpr* expr);
char Binop_is_tainted(IRExpr* expr);
char Triop_is_tainted(IRExpr* expr);
char Qop_is_tainted(IRExpr* expr);
char Load_is_tainted(IRExpr* expr);

char byte_is_tainted(unsigned int addr);
char word_is_tainted(unsigned int addr);
char dword_is_tainted(unsigned int addr);
char memory_is_tainted(unsigned int addr, IRType ty);

char register8_is_tainted(Register reg);
char register16_is_tainted(Register reg);
char register32_is_tainted(Register reg);
char register_is_tainted(Int offset, IRType ty);

char temporary_is_tainted(IRTemp tmp);

#endif
