#ifndef _SHADOW_MEMORY_H
#define _SHADOW_MEMORY_H

#include "VEX/libvex.h"

void init();
void destroy();

/* MEMORY */

#define CHUNK_SIZE	65536
#define MMAP_SIZE	65536

typedef struct {
    char bytes[CHUNK_SIZE];
} Chunk;

Chunk* MemoryMap[MMAP_SIZE]; // designed for a 32-bit (4GB) address space (4Go = 4194304Ko = 64Ko*65536 = 65536o*65536)

Chunk* get_chunk_for_reading(UInt addr);
Chunk* get_chunk_for_writing(UInt addr);

void flip_byte(UInt addr);
void flip_word(UInt addr);
void flip_dword(UInt addr);
void flip_memory(UInt addr, Int size);

/* REGISTERS */

typedef enum {EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, EIP, REG_INVALID} Register;

char registers8[9];
char registers16[9];
char registers32[9];

Register get_reg_from_offset(Int offset);

void flip_register8(Register reg);
void flip_register16(Register reg);
void flip_register32(Register reg);
void flip_register(Int offset, Int size);

/* TEMPORARIES */

#define	MAX_TEMP	0xffff

typedef struct {
    IRTemp tmp;
    IRType type;
    char tainted;
} Temp_info;

Temp_info** g_tmp_map;
unsigned int g_tmp_map_len;

char tmp_exists(IRTemp tmp);
void add_tmp_to_g_map(IRTemp tmp, IRType type);

void flip_temporary(IRTemp tmp);

#endif // SHADOW_MEMORY_H
