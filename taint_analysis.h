#ifndef _TAINT_ANALYSIS_H
#define _TAINT_ANALYSIS_H

#include "shadow_memory.h"
#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

/* MEMORY */

char byte_is_tainted(UInt addr);
char word_is_tainted(UInt addr);
char dword_is_tainted(UInt addr);
char qword_is_tainted(UInt addr);
char dqword_is_tainted(UInt addr);
char memory_is_tainted(UInt addr, UInt size);

/* REGISTERS */

char register8_is_tainted(Register reg);
char register16_is_tainted(Register reg);
char register32_is_tainted(Register reg);
char register_is_tainted(UInt offset, UInt size);

/* TEMPORARIES */

char temporary_is_tainted(IRTemp tmp);
char IRTemp_is_tainted(IRTemp tmp);

#endif // TAINT_ANALYSIS_H
