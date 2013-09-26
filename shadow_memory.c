#include "shadow_memory.h"
#include <string.h>
#include <stdlib.h>

void init()
{
	int i;
	
	memset(MemoryMap, 0, sizeof(Chunk*)*MMAP_SIZE);
	
	g_tmp_map = malloc(sizeof(Temp_info*)*MAX_TEMP);
	memset(g_tmp_map, 0, sizeof(Temp_info*)*MAX_TEMP);
	g_tmp_map_len = 0;
}

void destroy()
{
	int i;
	
	for (i = 0; i < MMAP_SIZE; i++) {
		if (MemoryMap[i] != NULL) {
			free(MemoryMap[i]);
		}
	}
	
	for (i = 0; i < MAX_TEMP; i++) {
		if (g_tmp_map[i] != NULL) {
			free(g_tmp_map[i]);
		}
	}
	free(g_tmp_map);
}

Chunk* get_chunk_for_reading(intptr_t addr) 
{
	return MemoryMap[(addr >> 16) & 0xffff];
}

Chunk* get_chunk_for_writing(intptr_t addr) 
{
	intptr_t x = (addr >> 16) & 0xffff;
        
 	if (MemoryMap[x] == NULL)
	{
		MemoryMap[x] = malloc(sizeof(Chunk));
	}

	return MemoryMap[x];
}

void flip_byte(intptr_t addr)
{
	Chunk* chunk = get_chunk_for_writing(addr);
	
	chunk->bytes[addr & 0xffff] ^= 1;
}

void flip_word(intptr_t addr) 
{
	flip_byte(addr);
	flip_byte(addr+1);
}

void flip_dword(intptr_t addr)
{
	flip_byte(addr);
	flip_byte(addr+1);
	flip_byte(addr+2);
	flip_byte(addr+3);
}

void flip_register8(Register reg) 
{
	registers8[reg] ^= 1;
}

void flip_register16(Register reg)
{
	registers16[reg] ^= 1;
 
	// EAX ECX EDX EBX
	if (reg < 4)
	{
		registers8[reg] = registers16[reg];		// low-order byte
		registers8[reg+4] = registers16[reg];	// high-order byte
	}
}

void flip_register32(Register reg)
{
	registers32[reg] ^= 1;
 
	registers16[reg] = registers32[reg];

	// EAX ECX EDX EBX
	if (reg < 4)
	{
		registers8[reg] = registers32[reg];		// low-order byte
		registers8[reg+4] = registers32[reg];	// high-order byte
	}
}

char is_guest_reg_offset(Int offset)
{
	switch (offset)
	{
		case 8:
		case 12:
		case 16:
		case 20:
		case 24:
		case 28:
		case 32:
		case 36:
		case 68:
			return 1;
		default:
			return 0;
	}
}

Register get_reg_from_offset(Int offset)
{
	switch (offset)
	{
		case 8: return Accumulator;
		case 12: return Counter;
		case 16: return Data;
		case 20: return Base;
		case 24: return StackPointer;
		case 28: return StackBasePointer;
		case 32: return SourceIndex;
		case 36: return DestinationIndex;
		case 68: return InstructionPointer;
	}
}

void flip_register(Int offset, IRType ty)
{
	Register reg = get_reg_from_offset(offset);

	switch (ty)
	{
		case Ity_I8:
			flip_register8(reg);
			break;
		case Ity_I16:
			flip_register16(reg);
			break;
		case Ity_I32:
			flip_register32(reg);
			break;
	}
}

char tmp_exists(IRTemp tmp)
{
	return g_tmp_map[tmp] != NULL;
}

void add_tmp_to_g_map(IRTemp tmp, IRType type)
{
	if (!tmp_exists(tmp))
	{
		g_tmp_map[tmp] = malloc(sizeof(Temp_info));
		g_tmp_map[tmp]->tmp = tmp;
		g_tmp_map[tmp]->type = type;
		g_tmp_map[tmp]->tainted = 0;
		
		g_tmp_map_len++;
	}
}

void flip_temporary(IRTemp tmp)
{
	if (tmp_exists(tmp)) {
		g_tmp_map[tmp]->tainted ^= 1;
	}
}
