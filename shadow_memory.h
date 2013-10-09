#ifndef _SHADOW_MEMORY_H
#define _SHADOW_MEMORY_H

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

void init_shadow_memory(void);
void destroy_shadow_memory(void);

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
void flip_qword(UInt addr);
void flip_dqword(UInt addr);
void flip_memory(UInt addr, UInt size);

/* REGISTERS */

typedef enum {EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, EIP, REG_INVALID} Register;

char registers8[9];
char registers16[9];
char registers32[9];

Register get_reg_from_offset(UInt offset);

void flip_register8(Register reg);
void flip_register16(Register reg);
void flip_register32(Register reg);
void flip_register(UInt offset, UInt size);

/* TEMPORARIES */

#define MAX_TEMPORARIES 512

char shadowTempArray[MAX_TEMPORARIES]; // a temporary is assigned before being used

char shadow_tmp_exists(IRTemp tmp);
void flip_temporary(IRTemp tmp);

#endif // SHADOW_MEMORY_H
