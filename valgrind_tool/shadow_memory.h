#ifndef _SHADOW_MEMORY_H
#define _SHADOW_MEMORY_H

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

void init_shadow_memory(void);
void destroy_shadow_memory(void);

/* SHADOW DATA STRUCTURE */

#define DEP_MAX_LEN     2048
#define DEP_MAX_SIZE    64

typedef struct {
    char tainted;
    // dependency
    char* buffer;
    unsigned int size;
} Shadow;

/* MEMORY */

#define MMAP_SIZE	65536
#define CHUNK_SIZE	65536

typedef struct {
    Shadow bytes[CHUNK_SIZE];
} Chunk;

Chunk* MemoryMap[MMAP_SIZE]; // designed for a 32-bit (4GB) address space (4Go = 4194304Ko = 64Ko*65536 = 65536o*65536)

Chunk* get_chunk_for_reading(UInt addr);
Chunk* get_chunk_for_writing(UInt addr);

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

Shadow registers[TOTAL_SHADOW_REGISTERS];

guest_register get_reg_from_offset(UInt offset);

/* TEMPORARIES */

#define MAX_TEMPORARIES 512

Shadow shadowTempArray[MAX_TEMPORARIES]; // a temporary is assigned before being used

#endif // SHADOW_MEMORY_H
