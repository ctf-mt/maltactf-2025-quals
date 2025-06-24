#include "vm.hpp"
#include <cstddef>

void run_syscall(struct vm_ctx* ctx) {
    switch ((enum SYSCALL)ctx->reg[0]) {
        case GETC:
            ctx->reg[0] = getc(stdin);
            break;
        case PUTC:
            putc(ctx->reg[0], stdout);
            break;
        case EXIT:
            ctx->running = 0;
            break;
    }
}

void run_instr(struct vm_ctx* ctx) {
    struct instr_t* instr = &ctx->prog[ctx->rip];
    uint8_t aa, bb;

    bool increment_ip = true;
    switch (instr->opcode) {
        case ADD:
            ctx->reg[instr->op1] += ctx->reg[instr->op2];
            break;
        case SUB:
            ctx->reg[instr->op1] -= ctx->reg[instr->op2];
            break;
        case MUL:
            ctx->reg[instr->op1] *= ctx->reg[instr->op2];
            break;
        case DIV:
            ctx->reg[instr->op1] /= ctx->reg[instr->op2];
            break;
        case MOD:
            ctx->reg[instr->op1] %= ctx->reg[instr->op2];
            break;
        case MOV:
            ctx->reg[instr->op1] = ctx->reg[instr->op2];
            break;
        case MOC:
            ctx->reg[instr->op1] = instr->op2;
            break;
        case CMP:
            ctx->cmp1 = ctx->reg[instr->op1];
            ctx->cmp2 = ctx->reg[instr->op2];
            break;
        case JEQ:
            if (ctx->cmp1 == ctx->cmp2) {
                ctx->rip = instr->op1 / sizeof(*instr);
                increment_ip = false;
            }
            break;
        case JL:
            if (ctx->cmp1 < ctx->cmp2) {
                ctx->rip = instr->op1 / sizeof(*instr);
                increment_ip = false;
            }
            break;
        case JLE:
            if (ctx->cmp1 <= ctx->cmp2) {
                ctx->rip = instr->op1 / sizeof(*instr);
                increment_ip = false;
            }
            break;
        case JG:
            if (ctx->cmp1 > ctx->cmp2) {
                ctx->rip = instr->op1 / sizeof(*instr);
                increment_ip = false;
            }
            break;
        case JGE:
            if (ctx->cmp1 >= ctx->cmp2) {
                ctx->rip = instr->op1 / sizeof(*instr);
                increment_ip = false;
            }
            break;
        case STM:
            ctx->mem[ctx->reg[instr->op1]] = ctx->reg[instr->op2];
            break;
        case LDM:
            ctx->reg[instr->op1] = ctx->mem[ctx->reg[instr->op2]];
            break;
        case SYS:
            run_syscall(ctx);
            break;
        case CALL:
            ctx->mem[++ctx->reg[REG_SP]] = ctx->rip + 1;
            ctx->rip = instr->op1 / sizeof(instr_t);
            ctx->depth += 1;
            increment_ip = false;
            break;
        case RET:
            if (ctx->depth == 0) {
                ctx->running = 0;
            } else {
                ctx->rip = ctx->mem[ctx->reg[REG_SP]--];
                ctx->depth -= 1;
                increment_ip = false;
            }
            break;
        case AND:
            ctx->reg[instr->op1] &= ctx->reg[instr->op2];
            break;
        case XOR:
            ctx->reg[instr->op1] ^= ctx->reg[instr->op2];
            break;
        case NOT:
            ctx->reg[instr->op1] = ~ctx->reg[instr->op1];
            break;
        case JMP:
            ctx->rip = instr->op1 / sizeof(*instr);
            increment_ip = false;
            break;
        case PRINT:
            printf("[PR] %x\n", ctx->reg[instr->op1]);
            break;
        case ROR:
            aa = ctx->reg[instr->op1], bb = ctx->reg[instr->op2];
            ctx->reg[instr->op1] = (aa >> bb) | (aa << (8 - bb));
            ctx->reg[instr->op1] &= 255;
            break;
        case ROL:
            aa = ctx->reg[instr->op1], bb = ctx->reg[instr->op2];
            ctx->reg[instr->op1] = (aa << bb) | (aa >> (8 - bb));
            ctx->reg[instr->op1] &= 255;
            break;
        case SHR:
            ctx->reg[instr->op1] >>= ctx->reg[instr->op2];
            break;
        case SHL:
            ctx->reg[instr->op1] <<= ctx->reg[instr->op2];
            ctx->reg[instr->op1] &= 255;
            break;
    }

    if (increment_ip) {
        ctx->rip++;
    }
}

void run_vm(struct instr_t* prog, int prog_sz, unsigned char* mem, int mem_sz, char* chunk_ptr) {
    struct vm_ctx ctx = {
        .prog = prog,
        .prog_sz = prog_sz,
        .mem = mem,
        .mem_sz = mem_sz,
        .rip = 90 / sizeof(instr_t),
        .reg = {0},
        .running = 1,
        .depth = 0,
    };
    ctx.reg[REG_SP] = 256;
    for (std::size_t i = 0; i < 16; ++i) {
        ctx.mem[i] = chunk_ptr[i];
    }
    while (ctx.running) {
        run_instr(&ctx);
    }
    for (std::size_t i = 0; i < 16; ++i) {
        chunk_ptr[i] = ctx.mem[i];
    }
}
