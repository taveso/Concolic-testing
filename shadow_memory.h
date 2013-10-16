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

#define CHUNK_SIZE	65536
#define MMAP_SIZE	65536

typedef struct {
    Shadow bytes[CHUNK_SIZE];
} Chunk;

Chunk* MemoryMap[MMAP_SIZE]; // designed for a 32-bit (4GB) address space (4Go = 4194304Ko = 64Ko*65536 = 65536o*65536)

Chunk* get_chunk_for_reading(UInt addr);
Chunk* get_chunk_for_writing(UInt addr);

Shadow* get_memory_shadow(UInt addr);

/* MEMORY TAINT ANALYSIS */

void flip_byte(UInt addr);
void flip_word(UInt addr);
void flip_dword(UInt addr);
void flip_qword(UInt addr);
void flip_dqword(UInt addr);
void flip_memory(UInt addr, UInt size);

/* MEMORY SYMBOLIC EXECUTION */

void update_byte_dep(UInt addr, char* dep, unsigned int dep_size);
void update_word_dep(UInt addr, char* dep, unsigned int dep_size);
void update_dword_dep(UInt addr, char* dep, unsigned int dep_size);
void update_qword_dep(UInt addr, char* dep, unsigned int dep_size);
void update_dqword_dep(UInt addr, char* dep, unsigned int dep_size);
void update_memory_dep(UInt addr, UInt size, char* dep, unsigned int dep_size);

void free_byte_dep(UInt addr);
void free_word_dep(UInt addr);
void free_dword_dep(UInt addr);
void free_qword_dep(UInt addr);
void free_dqword_dep(UInt addr);
void free_memory_dep(UInt addr, UInt size);

/* REGISTERS */

typedef enum {EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, EIP, REG_INVALID} Register;

Shadow registers8[9];
Shadow registers16[9];
Shadow registers32[9];

Register get_reg_from_offset(UInt offset);

Shadow* get_register_shadow(UInt offset, UInt size);

/* REGISTERS TAINT ANALYSIS */

void flip_register8(Register reg);
void flip_register16(Register reg);
void flip_register32(Register reg);
void flip_register(UInt offset, UInt size);

/* REGISTERS SYMBOLIC EXECUTION */

void update_register8_dep(Register reg, char* dep, unsigned int dep_size);
void update_register16_dep(Register reg, char* dep, unsigned int dep_size);
void update_register32_dep(Register reg, char* dep, unsigned int dep_size);
void update_register_dep(UInt offset, UInt size, char* dep, unsigned int dep_size);

void free_register8_dep(Register reg);
void free_register16_dep(Register reg);
void free_register32_dep(Register reg);
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
