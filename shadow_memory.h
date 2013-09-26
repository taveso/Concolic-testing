#ifndef _SHADOW_MEMORY_H
#define _SHADOW_MEMORY_H

#include "VEX/libvex.h"
#include <stdint.h>

void init();
void destroy();

/* Memory */

#define CHUNK_SIZE	65536
#define MMAP_SIZE	65536

typedef struct {
	char bytes[CHUNK_SIZE];
} Chunk;

Chunk* MemoryMap[MMAP_SIZE];

Chunk* get_chunk_for_reading(intptr_t addr);
Chunk* get_chunk_for_writing(intptr_t addr);

void flip_byte(intptr_t addr);
void flip_word(intptr_t addr);
void flip_dword(intptr_t addr);

/* Registers */

char registers8[9];
char registers16[9];
char registers32[9];

typedef enum {Accumulator, Counter, Data, Base, StackPointer, StackBasePointer, SourceIndex, DestinationIndex, InstructionPointer} Register;

void flip_register8(Register reg);
void flip_register16(Register reg);
void flip_register32(Register reg);
char is_guest_reg_offset(Int offset);
Register get_reg_from_offset(Int offset);
void flip_register(Int offset, IRType ty);

/* Temporaries */

typedef struct {
	IRTemp tmp;
	IRType type;
	char tainted;
} Temp_info;

#define	MAX_TEMP	0xffff

Temp_info** g_tmp_map;
unsigned int g_tmp_map_len;

char tmp_exists(IRTemp tmp);
void add_tmp_to_g_map(IRTemp tmp, IRType type);

void flip_temporary(IRTemp tmp);

#endif
