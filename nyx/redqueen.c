/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "qemu/osdep.h"

#include <assert.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <inttypes.h>

#include "debug.h"
#include "file_helper.h"
#include "nyx/interface.h"
#include "nyx/memory_access.h"
#include "nyx/redqueen.h"
#include "nyx/state/state.h"
#include "patcher.h"
#include "redqueen_trace.h"

redqueen_workdir_t redqueen_workdir = { 0 };

void setup_redqueen_workdir(char *workdir)
{
    assert(asprintf(&redqueen_workdir.redqueen_results, "%s/redqueen_results.txt",
                    workdir) > 0);
    assert(asprintf(&redqueen_workdir.symbolic_results, "%s/symbolic_results.txt",
                    workdir) > 0);
    assert(asprintf(&redqueen_workdir.pt_trace_results, "%s/pt_trace_results.txt",
                    workdir) > 0);
    assert(asprintf(&redqueen_workdir.redqueen_patches, "%s/redqueen_patches.txt",
                    workdir) > 0);
    assert(asprintf(&redqueen_workdir.breakpoint_white, "%s/breakpoint_white.txt",
                    workdir) > 0);
    assert(asprintf(&redqueen_workdir.breakpoint_black, "%s/breakpoint_black.txt",
                    workdir) > 0);
    assert(asprintf(&redqueen_workdir.target_code_dump, "%s/target_code_dump.img",
                    workdir) > 0);
}

redqueen_t *new_rq_state(CPUState *cpu, page_cache_t *page_cache)
{
    redqueen_t *res = malloc(sizeof(redqueen_t));

    res->cpu                = cpu;
    res->intercept_mode     = false;
    res->singlestep_enabled = false;
    res->hooks_applied      = 0;
    res->page_cache         = page_cache;

    res->lookup                   = kh_init(RQ);
    res->last_rip                 = 0x0;
    res->next_rip                 = 0x0;
    res->num_breakpoint_whitelist = 0;
    res->breakpoint_whitelist     = NULL;

    res->trace_state = redqueen_trace_new();

    return res;
}


static bool is_interessting_lea_at(redqueen_t *self, cs_insn *ins)
{
    bool res = false;

    assert(ins);
    cs_x86 *x86 = &(ins->detail->x86);

    assert(x86->op_count == 2);
    cs_x86_op *op2 = &(x86->operands[1]);

    assert(op2->type == X86_OP_MEM);

    x86_reg reg  = op2->mem.index;
    int64_t disp = (int64_t)op2->mem.disp;
    res          = disp < 0 && (-disp) > 0xff && op2->mem.scale == 1 &&
          op2->mem.base == X86_REG_INVALID && reg != X86_REG_INVALID;

    if (res) {
        x86_reg reg = op2->mem.index;
        if (reg == X86_REG_EIP || reg == X86_REG_RIP || reg == X86_REG_EBP ||
            reg == X86_REG_RBP)
        {
            // nyx_debug_p(REDQUEEN_PREFIX, "got boring index\n");
            res = false;
        } // don't instrument local stack offset computations
    }
    return res;
}

static bool uses_register(cs_x86_op *op, x86_reg reg)
{
    if (op->type == X86_OP_REG && op->reg == reg) {
        return true;
    }

    if (op->type == X86_OP_MEM && op->mem.base == reg) {
        return true;
    }

    return false;
}

static bool uses_stack_access(cs_x86_op *op)
{
    if (uses_register(op, X86_REG_RBP) || uses_register(op, X86_REG_EBP)) {
        return true;
    }

    if (uses_register(op, X86_REG_RSP) || uses_register(op, X86_REG_ESP)) {
        return true;
    }

    return false;
}

static bool is_interessting_add_at(redqueen_t *self, cs_insn *ins)
{
    assert(ins);
    cs_x86 *x86 = &(ins->detail->x86);

    assert(x86->op_count == 2);
    cs_x86_op *op1 = &(x86->operands[0]);
    cs_x86_op *op2 = &(x86->operands[1]);

    if (op2->type == X86_OP_IMM && (op1->type == X86_OP_REG || op1->type == X86_OP_MEM))
    {
        // offsets needs to be negative, < -0xff to ensure we only look at multi byte substractions
        if ((op2->imm > 0x7fff && (((op2->imm >> 8) & 0xff) != 0xff))) {
            if (!uses_stack_access(op1)) {
                return true;
            }
        }
    }
    return false;
}

static bool is_interessting_sub_at(redqueen_t *self, cs_insn *ins)
{
    assert(ins);
    cs_x86 *x86 = &(ins->detail->x86);

    assert(x86->op_count == 2);
    cs_x86_op *op1 = &(x86->operands[0]);
    cs_x86_op *op2 = &(x86->operands[1]);

    if (op2->type == X86_OP_IMM && (op1->type == X86_OP_REG || op1->type == X86_OP_MEM))
    {
        if (op2->imm > 0xFF) {
            if (!uses_stack_access(op1)) {
                return true;
            }
        }
    }
    return false;
}

static bool is_interessting_xor_at(redqueen_t *self, cs_insn *ins)
{
    assert(ins);
    cs_x86 *x86 = &(ins->detail->x86);

    assert(x86->op_count == 2);
    cs_x86_op *op1 = &(x86->operands[0]);
    cs_x86_op *op2 = &(x86->operands[1]);

    if (op1->type == X86_OP_REG && op2->type == X86_OP_REG) {
        if (op1->reg != op2->reg) {
            return true;
        }
    }
    return false;
}

static void opcode_analyzer(redqueen_t *self, cs_insn *ins)
{
    // uint8_t i, j;
    // cs_x86 details = ins->detail->x86;
    // printf("SELF %p\n", self->redqueen_state);
    // printf("INS %lx\n", ins->address);
    if (ins->id == X86_INS_CMP) {
        set_rq_instruction(self, ins->address);
        // nyx_debug_p(REDQUEEN_PREFIX, "hooking cmp %lx %s %s\n", ins->address, ins->mnemonic, ins->op_str);
    }
    if (ins->id == X86_INS_LEA && is_interessting_lea_at(self, ins)) {
        // nyx_debug_p(REDQUEEN_PREFIX, "hooking lea %lx\n", ins->address);
        set_rq_instruction(self, ins->address);
    }
    if (ins->id == X86_INS_SUB && is_interessting_sub_at(self, ins)) {
        // nyx_debug_p(REDQUEEN_PREFIX, "hooking sub %lx\n", ins->address);
        set_rq_instruction(self, ins->address);
    }
    if (ins->id == X86_INS_ADD && is_interessting_add_at(self, ins)) {
        // nyx_debug_p(REDQUEEN_PREFIX, "hooking add %lx\n", ins->address);
        set_rq_instruction(self, ins->address);
    }
    if (ins->id == X86_INS_XOR && is_interessting_xor_at(self, ins)) {
        // nyx_debug_p(REDQUEEN_PREFIX, "hooking xor %lx %s %s\n", ins->address, ins->mnemonic, ins->op_str);
        set_rq_instruction(self, ins->address);
    }
    if (ins->id == X86_INS_CALL || ins->id == X86_INS_LCALL) {
        // nyx_debug_p(REDQUEEN_PREFIX, "hooking call %lx %s %s\n", ins->address, ins->mnemonic, ins->op_str);
        set_rq_instruction(self, ins->address);
    }
}

void redqueen_callback(void               *opaque,
                       disassembler_mode_t mode,
                       uint64_t            start_addr,
                       uint64_t            end_addr)
{
    GET_GLOBAL_STATE()->bb_coverage++;
    redqueen_t *self = (redqueen_t *)opaque;

    if (start_addr != end_addr) {
        uint64_t failed_page = 0;
        uint64_t code        = start_addr;

        cs_insn *insn = page_cache_cs_malloc(self->page_cache, mode);

        while (page_cache_disassemble_iter(self->page_cache, &code, insn,
                                           &failed_page, mode))
        {
            if (insn->address > end_addr) {
                break;
            }
            opcode_analyzer(self, insn);
        }
        cs_free(insn, 1);
    }
}

void destroy_rq_state(redqueen_t *self)
{
    redqueen_trace_free(self->trace_state);
    kh_destroy(RQ, self->lookup);
    free(self);
}

static void redqueen_set_addr_flags(redqueen_t *self, uint64_t addr, uint32_t flags)
{
    int unused = 0;

    khiter_t k = kh_get(RQ, self->lookup, addr);
    if (k == kh_end(self->lookup)) {
        k                         = kh_put(RQ, self->lookup, addr, &unused);
        kh_value(self->lookup, k) = 0;
    }
    kh_value(self->lookup, k) |= flags;
}

static bool redqueen_check_addr_flags(redqueen_t *self, uint64_t addr, uint32_t flags)
{
    khiter_t k = kh_get(RQ, self->lookup, addr);
    if (k != kh_end(self->lookup)) {
        return !!(kh_value(self->lookup, k) & flags);
    } else {
        return false;
    }
}

static bool redqueen_check_addr(redqueen_t *self, uint64_t addr)
{
    khiter_t k = kh_get(RQ, self->lookup, addr);
    if (k != kh_end(self->lookup)) {
        return true;
    } else {
        return false;
    }
}

static uint32_t redqueen_update_addr_count(redqueen_t *self, uint64_t addr)
{
    int      unused __attribute__((unused));
    uint32_t value = 0;
    khiter_t k     = kh_get(RQ, self->lookup, addr);
    if (k != kh_end(self->lookup)) {
        value = kh_value(self->lookup, k);
    } else {
        k = kh_put(RQ, self->lookup, addr, &unused);
    }
    value++;
    kh_value(self->lookup, k) = value;
    return value & 0xFF000000UL;
}

void set_rq_instruction(redqueen_t *self, uint64_t addr)
{
    if (!redqueen_check_addr_flags(self, addr, CMP_BITMAP_BLACKLISTED)) {
        redqueen_set_addr_flags(self, addr, CMP_BITMAP_RQ_INSTRUCTION);
    }
}

void set_rq_blacklist(redqueen_t *self, uint64_t addr)
{
    redqueen_set_addr_flags(self, addr, CMP_BITMAP_BLACKLISTED);
}

static void insert_hooks_whitelist(redqueen_t *self)
{
    for (size_t i = 0; i < self->num_breakpoint_whitelist; i++) {
        insert_breakpoint(self->cpu, self->breakpoint_whitelist[i], 1);
    }
}

static void insert_hooks_bitmap(redqueen_t *self)
{
    uint64_t c = 0;
    uint64_t addr;
    uint32_t value __attribute__((unused));
    uint32_t mode = GET_GLOBAL_STATE()->redqueen_instrumentation_mode;

    kh_foreach(self->lookup, addr, value, {
        if (redqueen_check_addr_flags(self, addr, CMP_BITMAP_BLACKLISTED)) {
            continue;
        }

        bool should_hook_rq =
            (mode == REDQUEEN_LIGHT_INSTRUMENTATION) &&
            redqueen_check_addr_flags(self, addr, CMP_BITMAP_SHOULD_HOOK_RQ);

        if (should_hook_rq) {
            insert_breakpoint(self->cpu, addr, 1);
            c++;
        }
    });
}

void redqueen_insert_hooks(redqueen_t *self)
{
    nyx_debug_p(REDQUEEN_PREFIX, "insert hooks\n");
    assert(!self->hooks_applied);
    switch (GET_GLOBAL_STATE()->redqueen_instrumentation_mode) {
    case (REDQUEEN_LIGHT_INSTRUMENTATION):
        insert_hooks_bitmap(self);
        break;
    case (REDQUEEN_WHITELIST_INSTRUMENTATION):
        insert_hooks_whitelist(self);
        break;
    case (REDQUEEN_NO_INSTRUMENTATION):
        break;
    default:
        assert(false);
    }
    self->hooks_applied = 1;
}

void redqueen_remove_hooks(redqueen_t *self)
{
    nyx_debug_p(REDQUEEN_PREFIX, "remove hooks\n");
    assert(self->hooks_applied);
    remove_all_breakpoints(self->cpu);

    for (khiter_t i = kh_begin(self->lookup); i != kh_end(self->lookup); ++i) {
        if (!kh_exist(self->lookup, i))
            continue;
        kh_val(self->lookup, i) &= 0xFF000000UL;
    }
    self->hooks_applied = 0;
    return;
}
static uint64_t get_segment_register(x86_reg reg)
{
    X86CPU      *cpu = X86_CPU(qemu_get_cpu(0));
    CPUX86State *env = &cpu->env;

    switch (reg) {
    case X86_REG_GS:
        return env->segs[R_GS].base;
    case X86_REG_FS:
        return env->segs[R_FS].base;
    case X86_REG_CS:
        return env->segs[R_CS].base;
    case X86_REG_DS:
        return env->segs[R_DS].base;
    case X86_REG_SS:
        return env->segs[R_SS].base;
    default:
        break;
    }
    assert(false);
}

static inline uint64_t sign_extend_from_size(uint64_t value, uint8_t size)
{
    switch (size) {
    case 64:
        return value;
    case 32:
        return ((int32_t)(value) < 0) ? 0xffffffff00000000 | value : value;
    case 16:
        return ((int16_t)(value) < 0) ? 0xffffffffffff0000 | value : value;
    case 8:
        return ((int8_t)(value) < 0) ? 0xffffffffffffff00 | value : value;
    }
    assert(false);
}

static uint64_t eval_reg(x86_reg reg, uint8_t *size)
{
    uint64_t     value = 0;
    CPUX86State *env   = &(X86_CPU(qemu_get_cpu(0)))->env;

    switch (reg) {
    case X86_REG_RAX:
        value = env->regs[RAX];
        *size = 64;
        break;
    case X86_REG_RCX:
        value = env->regs[RCX];
        *size = 64;
        break;
    case X86_REG_RDX:
        value = env->regs[RDX];
        *size = 64;
        break;
    case X86_REG_RBX:
        value = env->regs[RBX];
        *size = 64;
        break;
    case X86_REG_RSP:
        value = env->regs[RSP];
        *size = 64;
        break;
    case X86_REG_RBP:
        value = env->regs[RBP];
        *size = 64;
        break;
    case X86_REG_RSI:
        value = env->regs[RSI];
        *size = 64;
        break;
    case X86_REG_RDI:
        value = env->regs[RDI];
        *size = 64;
        break;
    case X86_REG_R8:
        value = env->regs[R8];
        *size = 64;
        break;
    case X86_REG_R9:
        value = env->regs[R9];
        *size = 64;
        break;
    case X86_REG_R10:
        value = env->regs[R10];
        *size = 64;
        break;
    case X86_REG_R11:
        value = env->regs[R11];
        *size = 64;
        break;
    case X86_REG_R12:
        value = env->regs[R12];
        *size = 64;
        break;
    case X86_REG_R13:
        value = env->regs[R13];
        *size = 64;
        break;
    case X86_REG_R14:
        value = env->regs[R14];
        *size = 64;
        break;
    case X86_REG_R15:
        value = env->regs[R15];
        *size = 64;
        break;
    case X86_REG_EAX:
        value = env->regs[RAX] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_ECX:
        value = env->regs[RCX] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_EDX:
        value = env->regs[RDX] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_EBX:
        value = env->regs[RBX] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_ESP:
        value = env->regs[RSP] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_EBP:
        value = env->regs[RBP] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_ESI:
        value = env->regs[RSI] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_EDI:
        value = env->regs[RDI] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_R8D:
        value = env->regs[R8] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_R9D:
        value = env->regs[R9] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_R10D:
        value = env->regs[R10] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_R11D:
        value = env->regs[R11] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_R12D:
        value = env->regs[R12] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_R13D:
        value = env->regs[R13] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_R14D:
        value = env->regs[R14] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_R15D:
        value = env->regs[R15] & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_AX:
        value = env->regs[RAX] & 0xffff;
        *size = 16;
        break;
    case X86_REG_CX:
        value = env->regs[RCX] & 0xffff;
        *size = 16;
        break;
    case X86_REG_DX:
        value = env->regs[RDX] & 0xffff;
        *size = 16;
        break;
    case X86_REG_BX:
        value = env->regs[RBX] & 0xffff;
        *size = 16;
        break;
    case X86_REG_SP:
        value = env->regs[RSP] & 0xffff;
        *size = 16;
        break;
    case X86_REG_BP:
        value = env->regs[RBP] & 0xffff;
        *size = 16;
        break;
    case X86_REG_SI:
        value = env->regs[RSI] & 0xffff;
        *size = 16;
        break;
    case X86_REG_DI:
        value = env->regs[RDI] & 0xffff;
        *size = 16;
        break;
    case X86_REG_R8W:
        value = env->regs[R8] & 0xffff;
        *size = 16;
        break;
    case X86_REG_R9W:
        value = env->regs[R9] & 0xffff;
        *size = 16;
        break;
    case X86_REG_R10W:
        value = env->regs[R10] & 0xffff;
        *size = 16;
        break;
    case X86_REG_R11W:
        value = env->regs[R11] & 0xffff;
        *size = 16;
        break;
    case X86_REG_R12W:
        value = env->regs[R12] & 0xffff;
        *size = 16;
        break;
    case X86_REG_R13W:
        value = env->regs[R13] & 0xffff;
        *size = 16;
        break;
    case X86_REG_R14W:
        value = env->regs[R14] & 0xffff;
        *size = 16;
        break;
    case X86_REG_R15W:
        value = env->regs[R15] & 0xffff;
        *size = 16;
        break;
    case X86_REG_AL:
        value = env->regs[RAX] & 0xff;
        *size = 8;
        break;
    case X86_REG_CL:
        value = env->regs[RCX] & 0xff;
        *size = 8;
        break;
    case X86_REG_DL:
        value = env->regs[RDX] & 0xff;
        *size = 8;
        break;
    case X86_REG_BL:
        value = env->regs[RBX] & 0xff;
        *size = 8;
        break;
    case X86_REG_SPL:
        value = env->regs[RSP] & 0xff;
        *size = 8;
        break;
    case X86_REG_BPL:
        value = env->regs[RBP] & 0xff;
        *size = 8;
        break;
    case X86_REG_SIL:
        value = env->regs[RSI] & 0xff;
        *size = 8;
        break;
    case X86_REG_DIL:
        value = env->regs[RDI] & 0xff;
        *size = 8;
        break;
    case X86_REG_R8B:
        value = env->regs[R8] & 0xff;
        *size = 8;
        break;
    case X86_REG_R9B:
        value = env->regs[R9] & 0xff;
        *size = 8;
        break;
    case X86_REG_R10B:
        value = env->regs[R10] & 0xff;
        *size = 8;
        break;
    case X86_REG_R11B:
        value = env->regs[R11] & 0xff;
        *size = 8;
        break;
    case X86_REG_R12B:
        value = env->regs[R12] & 0xff;
        *size = 8;
        break;
    case X86_REG_R13B:
        value = env->regs[R13] & 0xff;
        *size = 8;
        break;
    case X86_REG_R14B:
        value = env->regs[R14] & 0xff;
        *size = 8;
        break;
    case X86_REG_R15B:
        value = env->regs[R15] & 0xff;
        *size = 8;
        break;
    case X86_REG_AH:
        value = (env->regs[RAX] >> 8) & 0xff;
        *size = 8;
        break;
    case X86_REG_CH:
        value = (env->regs[RCX] >> 8) & 0xff;
        *size = 8;
        break;
    case X86_REG_DH:
        value = (env->regs[RDX] >> 8) & 0xff;
        *size = 8;
        break;
    case X86_REG_BH:
        value = (env->regs[RBX] >> 8) & 0xff;
        *size = 8;
        break;
    case X86_REG_RIP:
        value = env->eip;
        *size = 64;
        break;
    case X86_REG_EIP:
        value = env->eip & 0xffffffff;
        *size = 32;
        break;
    case X86_REG_IP:
        value = env->eip & 0xfffff;
        *size = 16;
        break;
    default:
        assert(false);
    }
    return value;
}

static uint64_t eval_addr(cs_x86_op *op)
{
    uint8_t  size    = 0;
    uint64_t base    = 0;
    uint64_t index   = 0;
    uint64_t segment = 0;

    assert(op->type == X86_OP_MEM);

    if (op->mem.base != X86_REG_INVALID) {
        base = eval_reg(op->mem.base, &size);
    }
    if (op->mem.index != X86_REG_INVALID) {
        index = eval_reg(op->mem.index, &size);
    }

    if (op->mem.segment != X86_REG_INVALID) {
        segment = get_segment_register(op->mem.segment);
    }

    uint64_t addr = segment + base + index * op->mem.scale + op->mem.disp;
    return addr;
}

static uint64_t eval_mem(cs_x86_op *op)
{
    uint64_t val = 0;
    assert(op->size == 1 || op->size == 2 || op->size == 4 || op->size == 8);
    // nyx_debug_p(REDQUEEN_PREFIX, "EVAL MEM FOR OP:\n");

    /* TODO @ sergej: replace me later */
    read_virtual_memory(eval_addr(op), (uint8_t *)&val, op->size, qemu_get_cpu(0));
    return val;
}

static uint64_t eval(cs_x86_op *op, uint8_t *size)
{
    switch ((int)op->type) {
    case X86_OP_REG:
        return eval_reg(op->reg, size);
    case X86_OP_IMM:
        *size = 0;
        return op->imm;
    case X86_OP_MEM:
        switch (op->size) {
        case 1:
            *size = 8;
            return eval_mem(op) & 0xff;
        case 2:
            *size = 16;
            return eval_mem(op) & 0xffff;
        case 4:
            *size = 32;
            return eval_mem(op) & 0xffffffff;
        case 8:
            *size = 64;
            return eval_mem(op);
        }
    }

    /* unreachable, dude! */
    assert(false);
    return 0;
}

static void print_comp_result(uint64_t    addr,
                              const char *type,
                              uint64_t    val1,
                              uint64_t    val2,
                              uint8_t     size,
                              bool        is_imm)
{
    char        result_buf[256];
    const char *format = NULL;

    uint8_t pos = 0;
    pos += snprintf(result_buf + pos, 256 - pos, "%lx\t\t %s", addr, type);
    // nyx_debug_p(REDQUEEN_PREFIX, "got size: %ld\n", size);
    uint64_t mask = 0;
    switch (size) {
    case 64:
        format = " 64\t%016lX-%016lX";
        mask   = 0xffffffffffffffff;
        break;
    case 32:
        format = " 32\t%08X-%08X";
        mask   = 0xffffffff;
        break;
    case 16:
        format = " 16\t%04X-%04X";
        mask   = 0xffff;
        break;
    case 8:
        format = " 8\t%02X-%02X";
        mask   = 0xff;
        break;
    default:
        assert(false);
    }
    pos += snprintf(result_buf + pos, 256 - pos, format, val1 & mask, val2 & mask);
    if (is_imm) {
        pos += snprintf(result_buf + pos, 256 - pos, " IMM");
    }
    pos += snprintf(result_buf + pos, 256 - pos, "\n");
    write_re_result(result_buf);
}

static void get_cmp_value(cs_insn *ins, const char *type)
{
    uint8_t size_1 = 0;
    uint8_t size_2 = 0;

    assert(ins);
    cs_x86 *x86 = &(ins->detail->x86);

    assert(x86->op_count == 2);
    cs_x86_op *op1 = &(x86->operands[0]);
    cs_x86_op *op2 = &(x86->operands[1]);

    uint64_t v1 = eval(op1, &size_1);
    uint64_t v2 = eval(op2, &size_2);

    if (GET_GLOBAL_STATE()->redqueen_instrumentation_mode ==
            REDQUEEN_WHITELIST_INSTRUMENTATION ||
        v1 != v2)
    {
        print_comp_result(ins->address, type, v1, v2, (size_1 ? size_1 : size_2),
                          op2->type == X86_OP_IMM);
    }
}

static void get_cmp_value_add(cs_insn *ins)
{
    uint8_t size_1 = 0;
    uint8_t size_2 = 0;

    assert(ins);
    cs_x86 *x86 = &(ins->detail->x86);

    assert(x86->op_count == 2);
    cs_x86_op *op1 = &(x86->operands[0]);
    cs_x86_op *op2 = &(x86->operands[1]);

    uint64_t v1 = eval(op1, &size_1);
    uint64_t v2 = -sign_extend_from_size(eval(op2, &size_2), size_1);

    if (op2->type != X86_OP_IMM) {
        return;
    }

    if (GET_GLOBAL_STATE()->redqueen_instrumentation_mode ==
            REDQUEEN_WHITELIST_INSTRUMENTATION ||
        v1 != v2)
    {
        bool is_imm = true;
        print_comp_result(ins->address, "SUB", v1, v2, size_1, is_imm);
    }
}

static void get_cmp_value_lea(cs_insn *ins)
{
    uint64_t index_val = 0;

    assert(ins);
    cs_x86 *x86 = &(ins->detail->x86);

    assert(x86->op_count == 2);
    cs_x86_op *op2 = &(x86->operands[1]);

    assert(op2->type == X86_OP_MEM);

    uint8_t size = 0;
    if (op2->mem.base != X86_REG_INVALID && op2->mem.index != X86_REG_INVALID) {
        return;
    }

    if (op2->mem.base == X86_REG_INVALID && op2->mem.index == X86_REG_INVALID) {
        return;
    }

    if (op2->mem.base != X86_REG_INVALID) {
        index_val = eval_reg(op2->mem.base, &size);
    }

    if (op2->mem.index != X86_REG_INVALID) {
        index_val = eval_reg(op2->mem.index, &size);
    }

    if (GET_GLOBAL_STATE()->redqueen_instrumentation_mode ==
            REDQUEEN_WHITELIST_INSTRUMENTATION ||
        index_val != -op2->mem.disp)
    {
        bool is_imm = false;
        print_comp_result(ins->address, "LEA", index_val, -op2->mem.disp,
                          op2->size * 8, is_imm);
    }
}


static uint64_t limit_to_word_width(uint64_t val)
{
    switch (GET_GLOBAL_STATE()->disassembler_word_width) {
    case 64:
        return val;
    case 32:
        return val & 0xffffffff;
    default:
        assert(false);
    }
}

static uint64_t word_width_to_bytes(void)
{
    switch (GET_GLOBAL_STATE()->disassembler_word_width) {
    case 64:
        return 8;
    case 32:
        return 4;
    default:
        assert(false);
    }
}

static uint64_t read_stack(uint64_t word_index)
{
    CPUX86State *env   = &(X86_CPU(qemu_get_cpu(0)))->env;
    uint64_t     rsp   = env->regs[RSP];
    rsp                = limit_to_word_width(rsp);
    uint64_t res       = 0;
    uint64_t stack_ptr = rsp + word_index * word_width_to_bytes();
    /* TODO @ sergej */
    assert(read_virtual_memory(stack_ptr, (uint8_t *)(&res), 8, qemu_get_cpu(0)));
    return limit_to_word_width(res);
}

static void format_strcmp(uint8_t *buf1, uint8_t *buf2)
{
    char  out_buf[REDQUEEN_MAX_STRCMP_LEN * 4 + 2];
    char *tmp_hex_buf = &out_buf[0];
    for (int i = 0; i < REDQUEEN_MAX_STRCMP_LEN; i++) {
        tmp_hex_buf += sprintf(tmp_hex_buf, "%02X", (uint8_t)buf1[i]);
    }
    *tmp_hex_buf++ = '-';
    for (int i = 0; i < REDQUEEN_MAX_STRCMP_LEN; i++) {
        tmp_hex_buf += sprintf(tmp_hex_buf, "%02X", (uint8_t)buf2[i]);
    }
    char        *res = 0;
    CPUX86State *env = &(X86_CPU(qemu_get_cpu(0)))->env;
    uint64_t     rip = env->eip;
    assert(asprintf(&res, "%lx\t\tSTR %d\t%s\n", rip, REDQUEEN_MAX_STRCMP_LEN * 8,
                    out_buf) != -1);
    write_re_result(res);
    free(res);
}

static bool test_strchr(uint64_t arg1, uint64_t arg2)
{
    CPUState *cpu = qemu_get_cpu(0);

    /* TODO @ sergej */
    if (!is_addr_mapped(arg1, cpu) || arg2 & (~0xff)) {
        return false;
    }
    uint8_t buf1[REDQUEEN_MAX_STRCMP_LEN];
    uint8_t buf2[REDQUEEN_MAX_STRCMP_LEN];

    /* TODO @ sergej */
    assert(read_virtual_memory(arg1, &buf1[0], REDQUEEN_MAX_STRCMP_LEN, cpu));
    if (!memchr(buf1, '\0', REDQUEEN_MAX_STRCMP_LEN)) {
        return false;
    }
    memset(buf2, '\0', REDQUEEN_MAX_STRCMP_LEN);
    buf2[0] = (uint8_t)(arg2);
    format_strcmp(buf1, buf2);
    return true;
}

static bool test_strcmp(uint64_t arg1, uint64_t arg2)
{
    CPUState *cpu = qemu_get_cpu(0);
    if (!is_addr_mapped(arg1, cpu) || !is_addr_mapped(arg2, cpu)) {
        return false;
    }
    // nyx_debug_p(REDQUEEN_PREFIX,"valid ptrs\n");
    uint8_t buf1[REDQUEEN_MAX_STRCMP_LEN];
    uint8_t buf2[REDQUEEN_MAX_STRCMP_LEN];
    /* TODO @ sergej */
    assert(read_virtual_memory(arg1, &buf1[0], REDQUEEN_MAX_STRCMP_LEN, cpu));
    assert(read_virtual_memory(arg2, &buf2[0], REDQUEEN_MAX_STRCMP_LEN, cpu));
    format_strcmp(buf1, buf2);
    return true;
}

static bool test_strcmp_cdecl(void)
{
    uint64_t arg1 = read_stack(0);
    uint64_t arg2 = read_stack(1);
    // nyx_debug_p(REDQUEEN_PREFIX, "extract call params cdecl %lx %lx\n", arg1, arg2);
    test_strchr(arg1, arg2);
    return test_strcmp(arg1, arg2);
}

static bool test_strcmp_fastcall(void)
{
    CPUX86State *env  = &(X86_CPU(qemu_get_cpu(0)))->env;
    uint64_t     arg1 = env->regs[RCX]; // rcx
    uint64_t     arg2 = env->regs[RDX]; // rdx
    // nyx_debug_p(REDQUEEN_PREFIX, "extract call params fastcall %lx %lx\n", arg1, arg2);
    test_strchr(arg1, arg2);
    return test_strcmp(arg1, arg2);
}

static bool test_strcmp_sys_v(void)
{
    if (GET_GLOBAL_STATE()->disassembler_word_width != 64) {
        return false;
    }
    CPUX86State *env  = &(X86_CPU(qemu_get_cpu(0)))->env;
    uint64_t     arg1 = env->regs[RDI]; // rdx
    uint64_t     arg2 = env->regs[RSI]; // rsi
    // nyx_debug_p(REDQUEEN_PREFIX, "extract call params sysv %lx %lx\n", arg1, arg2);
    test_strchr(arg1, arg2);
    return test_strcmp(arg1, arg2);
}

static void extract_call_params(void)
{
    // nyx_debug_p(REDQUEEN_PREFIX, "extract call at %lx\n", ip);
    test_strcmp_cdecl();
    test_strcmp_fastcall();
    test_strcmp_sys_v();
}

static void handle_hook_redqueen_light(redqueen_t *self, uint64_t ip, cs_insn *insn)
{
    if (insn->id == X86_INS_CMP || insn->id == X86_INS_XOR)
    { // handle original redqueen case
        get_cmp_value(insn, "CMP");
    } else if (insn->id == X86_INS_SUB) { // handle original redqueen case
        get_cmp_value(insn, "SUB");
    } else if (insn->id == X86_INS_LEA) { // handle original redqueen case
        get_cmp_value_lea(insn);
    } else if (insn->id == X86_INS_ADD) { // handle original redqueen case
        get_cmp_value_add(insn);
    } else if (insn->id == X86_INS_CALL || insn->id == X86_INS_LCALL) {
        extract_call_params();
    }
}

static uint8_t handle_hook_breakpoint(redqueen_t *self, bool write_data)
{
    X86CPU      *cpu = X86_CPU(self->cpu);
    CPUX86State *env = &cpu->env;

    cs_insn *insn = NULL;
    switch (GET_GLOBAL_STATE()->disassembler_word_width) {
    case 64:
        insn = page_cache_cs_malloc(self->page_cache, mode_64);
        break;
    case 32:
        insn = page_cache_cs_malloc(self->page_cache, mode_32);
        break;
    default:
        abort();
    }
    uint8_t  ins_size    = 0;
    uint64_t ip          = env->eip;
    uint64_t code        = ip;
    uint64_t failed_page = 0;

    switch (GET_GLOBAL_STATE()->disassembler_word_width) {
    case 64:
        assert(page_cache_disassemble_iter(self->page_cache, &code, insn,
                                           &failed_page, mode_64));
        break;
    case 32:
        assert(page_cache_disassemble_iter(self->page_cache, &code, insn,
                                           &failed_page, mode_32));
        break;
    default:
        abort();
    }

    ins_size = insn->size;

    if (write_data) {
        // int mode = self->cpu->redqueen_instrumentation_mode;
        int mode = GET_GLOBAL_STATE()->redqueen_instrumentation_mode;
        if (mode == REDQUEEN_LIGHT_INSTRUMENTATION ||
            mode == REDQUEEN_WHITELIST_INSTRUMENTATION ||
            mode == REDQUEEN_SE_INSTRUMENTATION)
        {
            handle_hook_redqueen_light(self, ip, insn);
        }
        if (mode == REDQUEEN_SE_INSTRUMENTATION) {
            assert(false);
        }
    }
    cs_free(insn, 1);

    assert(ins_size != 0);
    return ins_size;
}

void handle_hook(redqueen_t *self)
{
    X86CPU      *cpu = X86_CPU(self->cpu);
    CPUX86State *env = &cpu->env;

    if (self->next_rip) {
        remove_breakpoint(self->cpu, self->next_rip, 1);

        if (self->last_rip &&
            redqueen_update_addr_count(self, self->last_rip) < REDQUEEN_TRAP_LIMIT)
        {
            insert_breakpoint(self->cpu, self->last_rip, 1);
        }

        kvm_update_guest_debug(self->cpu, 0);

        self->last_rip = 0;
        self->next_rip = 0;
    }

    if (redqueen_check_addr(self, env->eip)) {
        self->last_rip = env->eip;
        remove_breakpoint(self->cpu, env->eip, 1);

        if (self->cpu->pt_enabled && GET_GLOBAL_STATE()->pt_c3_filter == env->cr[3]) {
            self->next_rip = handle_hook_breakpoint(self, true);
        } else {
            self->next_rip = handle_hook_breakpoint(self, true);
        }
    }
}


static void _redqueen_update_whitelist(redqueen_t *self)
{
    if (GET_GLOBAL_STATE()->redqueen_instrumentation_mode ==
        REDQUEEN_WHITELIST_INSTRUMENTATION)
    {
        free(self->breakpoint_whitelist);
        parse_address_file(redqueen_workdir.breakpoint_white,
                           &self->num_breakpoint_whitelist,
                           &self->breakpoint_whitelist);
    }
}

static void _redqueen_update_blacklist(redqueen_t *self)
{
    if (GET_GLOBAL_STATE()->redqueen_update_blacklist) {
        size_t    num_addrs = 0;
        uint64_t *addrs;
        parse_address_file(redqueen_workdir.breakpoint_black, &num_addrs, &addrs);
        for (size_t i = 0; i < num_addrs; i++) {
            set_rq_blacklist(self, addrs[i]);
        }
        free(addrs);
    }
}

void enable_rq_intercept_mode(redqueen_t *self)
{
    if (!self->intercept_mode) {
        delete_redqueen_files();
        _redqueen_update_whitelist(self);
        _redqueen_update_blacklist(self);
        redqueen_insert_hooks(self);
        self->intercept_mode = true;
    }
}

void disable_rq_intercept_mode(redqueen_t *self)
{
    if (self->intercept_mode) {
        redqueen_remove_hooks(self);
        self->intercept_mode = false;
    }
}
