#pragma once

#include <stdint.h>
#include <stdio.h>

enum SYSCALL : unsigned char {
    PUTC,
    GETC,
    EXIT,
};

enum OPCODE : unsigned char {
    ADD,
    SUB,
    MUL,
    DIV,
    MOD,
    MOV,
    MOC,
    CMP,
    JEQ,
    JL,
    JLE,
    JG,
    JGE,
    STM,
    LDM,
    SYS,
    CALL,
    RET,
    AND,
    XOR,
    NOT,
    JMP,
    PRINT,
    ROR,
    ROL,
    SHR,
    SHL
};


#pragma pack(push, 1)
struct instr_t {
    enum OPCODE opcode;
    int op1;
    int op2;
};
#pragma pack(pop)

#define REG_SZ 10
#define REG_SP (REG_SZ-1)

struct vm_ctx {
    struct instr_t* prog;
    int prog_sz;
    unsigned char* mem;
    int mem_sz;
    int rip;
    int64_t reg[REG_SZ];
    int running;
    int cmp1;
    int cmp2;
    int depth;
};

void run_vm(struct instr_t* prog, int prog_sz, unsigned char* mem, int mem_sz, char* chunk_ptr);