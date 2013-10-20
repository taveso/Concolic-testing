#ifndef _SHADOW_MEMORY_H
#define _SHADOW_MEMORY_H

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

void init_shadow_memory(void);
void destroy_shadow_memory(void);

/* SHADOW DATA STRUCTURE */

#define DEP_MAX_SIZE 1024

typedef struct {
    char tainted;
    /* dependency */
    char* buffer;
    unsigned int size;
} Shadow;

/* SYMBOLIC EXECUTION */

void update_dep(Shadow* shadow, char* dep, unsigned int dep_size);
void free_dep(Shadow* shadow);

/* MEMORY */

#define MMAP_SIZE	65536
#define CHUNK_SIZE	65536

typedef struct {
    Shadow bytes[CHUNK_SIZE];
} Chunk;

Chunk* MemoryMap[MMAP_SIZE]; // designed for a 32-bit (4GB) address space (4Go = 4194304Ko = 64Ko*65536 = 65536o*65536)

Chunk* get_chunk_for_reading(UInt addr);
Chunk* get_chunk_for_writing(UInt addr);

Shadow* get_byte_shadow(UInt addr);
char* get_memory_dep(UInt addr, UInt size, char* dep);

/* MEMORY TAINT ANALYSIS */

void flip_memory(UInt addr, UInt size);

/* MEMORY SYMBOLIC EXECUTION */

void update_memory_dep(UInt addr, char* dep, unsigned int dep_size);

void free_memory_dep(UInt addr, UInt size);

/* REGISTERS */

#define TOTAL_SHADOW_REGISTERS  16

typedef enum {guest_EAX,
              guest_ECX,
              guest_EDX,
              guest_EBX,
              guest_ESP,
              guest_EBP,
              guest_ESI,
              guest_EDI,
              guest_CC_OP,
              guest_CC_DEP1,
              guest_CC_DEP2,
              guest_CC_NDEP,
              guest_DFLAG,
              guest_IDFLAG,
              guest_ACFLAG,
              guest_EIP,
              guest_INVALID} guest_register;

Shadow registers8[TOTAL_SHADOW_REGISTERS];
Shadow registers16[TOTAL_SHADOW_REGISTERS];
Shadow registers32[TOTAL_SHADOW_REGISTERS];

guest_register get_reg_from_offset(UInt offset);

Shadow* get_register_shadow(UInt offset, UInt size);

/* REGISTERS TAINT ANALYSIS */

void flip_register8(guest_register reg);
void flip_register16(guest_register reg);
void flip_register32(guest_register reg);
void flip_register(UInt offset, UInt size);

/* REGISTERS SYMBOLIC EXECUTION */

void update_register8_dep(guest_register reg, char* dep);
void update_register16_dep(guest_register reg, char* dep);
void update_register32_dep(guest_register reg, char* dep);
void update_register_dep(UInt offset, UInt size, char* dep);

void free_register8_dep(guest_register reg);
void free_register16_dep(guest_register reg);
void free_register32_dep(guest_register reg);
void free_register_dep(UInt offset, UInt size);

/* TEMPORARIES */

#define MAX_TEMPORARIES 512

Shadow shadowTempArray[MAX_TEMPORARIES]; // a temporary is assigned before being used

Shadow* get_temporary_shadow(IRTemp tmp);

/* TEMPORARIES TAINT ANALYSIS */

void flip_temporary(IRTemp tmp);

/* TEMPORARIES SYMBOLIC EXECUTION */

void update_temporary_dep(IRTemp tmp, char* dep, unsigned int dep_size);

void free_temporary_dep(IRTemp tmp);

#endif // SHADOW_MEMORY_H
