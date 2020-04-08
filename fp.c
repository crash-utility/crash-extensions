/* fp.c - Parser for obtaining functions' parameters from stack frames.
 *
 * Copyright (C) 2013 Alexandr Terekhov
 * Copyright (C) 2013 EPAM Systems. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "defs.h"

#define DECLARE_REG_UNION_X(R) \
    union { \
        uint64_t r ## R ## x; \
        struct { \
            union { \
                uint32_t e ## R ## x; \
                struct { \
                    union { \
                        uint16_t R ## x; \
                        struct { \
                            uint8_t R ## l; \
                            uint8_t R ## h; \
                        }; \
                    }; \
                    unsigned char R ## x ## _res[2]; \
                }; \
            }; \
            unsigned char e ## R ## _res[4]; \
        }; \
    }

#define DECLARE_REG_UNION_IP(R) \
    union { \
        uint64_t r ## R; \
        struct { \
            union { \
                uint32_t e ## R; \
                struct { \
                    union { \
                        uint16_t R; \
                        struct { \
                            uint8_t R ## l; \
                            uint8_t R ## l ## _res; \
                        }; \
                    }; \
                    uint8_t R ## _res[2]; \
                }; \
            }; \
            uint8_t e ## R ## _res[4]; \
        }; \
    }

#define DECLARE_REG_UNION_R(R) \
    union { \
        uint64_t r ## R; \
        struct { \
            union { \
                uint32_t r ## R ## d; \
                struct { \
                    union { \
                        uint16_t r ## R ## w; \
                        struct { \
                            uint8_t r ## R ## b; \
                            uint8_t r ## R ## b ## _res; \
                        }; \
                    }; \
                    uint8_t r ## R ## w ## _res[2]; \
                }; \
            }; \
            uint8_t r ## R ## d ## _res[4]; \
        }; \
    }

#define DECLARE_REG_UNION_RIP \
    union { \
        uint64_t rip; \
        struct { \
            uint32_t eip; \
            uint32_t rip_res; \
        }; \
    }

#define OFF_X(R)    offsetof(__pr, r ## R ## x), offsetof(__pr, e ## R ## x), \
                    offsetof(__pr, R ## x), offsetof(__pr, R ## h), offsetof(__pr, R ## l)

#define OFF_IP(R)   offsetof(__pr, r ## R), offsetof(__pr, e ## R), \
                    offsetof(__pr, R), 0, offsetof(__pr, R ## l)

#define OFF_R(R)    offsetof(__pr, r ## R), offsetof(__pr, r ## R ## d), \
                    offsetof(__pr, r ## R ## w), 0, offsetof(__pr, r ## R ## b)

#define OFF_RIP     offsetof(__pr, rip), offsetof(__pr, eip), 0, 0, 0

#define E_X(RR)     R ## RR ## X, E ## RR ## X, RR ## X, RR ## H, RR ## L
#define E_IP(RR)    R ## RR, E ## RR, RR, FOO ## RR, RR ## L
#define E_R(RR)     R ## RR, R ## RR ## D, R ## RR ## W, FOO ## RR, R ## RR ## L
#define E_RIP       RIP, EIP, IP_FOO, IP_BAR, IP_BAZ

#define S_X(RR)     "%r" RR "x", "%e" RR "x", "%" RR "x", "%" RR "h", "%" RR "l"
#define S_IP(RR)    "%" "r" RR, "%" "e" RR, "%" RR, "foo" RR, "%" RR "l"
#define S_R(RR)     "%r" RR, "%r" RR "d", "%r" RR "w", "foo" RR, "%r" RR "l"
#define S_RIP       "%rip", "%eip", "ip_foo", "ip_bar", "ip_baz"

#define container_of(ptr, type, member) ({ \
                const typeof( ((type *)0)->member ) *__mptr = (ptr); \
                (type *)( (char *)__mptr - offsetof(type,member) );})
enum e_registers {
//  0           1           2           3
    E_X(A),     E_X(B),     E_X(C),     E_X(D),
//  4           5           6           7
    E_IP(DI),   E_IP(SI),   E_IP(BP),   E_IP(SP),
//  8           9           10          11
    E_R(8),     E_R(9),     E_R(10),    E_R(11),
//  12          13          14          15
    E_R(12),    E_R(13),    E_R(14),    E_R(15),
//  16          17          Per-CPU
    E_RIP,      RCOUNT,     GS_REG,     INVALID = 255,
};

enum e_instructions {
    LEAVE, UD2, NOP, 
    MOVZBL, MOVZWL, MOVSLQ, MOVSBL, MOVABS, MOV,
    CMOVcc,
    PUSHF, PUSH, POPF, POP,
    SUB, CALL, LEA, RET, XOR,
    BTS, BTR, BT, CMP, TEST, INC, DEC, JMP, Jcc,
//    JAE, JNE, JNZ, JBE, JNA, JNS, JMP,
//    JA, JB, JC, JE, JZ, JL, JS, OTHER_JUMP,
    SHL, SHR, SAR, IMUL,
    SBB, XADD, ADD, NOT, AND, OR,
    ICOUNT
};

enum e_condition {
    COND_A = 0, COND_AE, COND_B, COND_BE,
    COND_C, COND_E, COND_L, COND_S, COND_Z,
    COND_COUNT, COND_INVALID = 255
};

enum e_reliability {
    RELIABLE_NO     = 0,
    RELIABLE_ABS    = 1,
    RELIABLE_REG    = 2,
};

typedef struct parameter_registers {
    DECLARE_REG_UNION_X(a);
    DECLARE_REG_UNION_X(b);
    DECLARE_REG_UNION_X(d);
    DECLARE_REG_UNION_X(c);
    DECLARE_REG_UNION_IP(si);
    DECLARE_REG_UNION_IP(di);
    DECLARE_REG_UNION_IP(bp);
    DECLARE_REG_UNION_IP(sp);
    DECLARE_REG_UNION_R(8);
    DECLARE_REG_UNION_R(9);
    DECLARE_REG_UNION_R(10);
    DECLARE_REG_UNION_R(11);
    DECLARE_REG_UNION_R(12);
    DECLARE_REG_UNION_R(13);
    DECLARE_REG_UNION_R(14);
    DECLARE_REG_UNION_R(15);
    DECLARE_REG_UNION_RIP;
    uint64_t    params_mask;
    uint8_t     params_regs[RCOUNT];
    enum e_reliability reliable[RCOUNT];
    uint64_t    was_touched;
    uint8_t     zf; // Zero Flag
    uint8_t     cf; // Carry Flag
    uint8_t     sf; // Sign Flag
    uint8_t     of; // Overflow Flag
} __pr;

enum line_status {
    LINE_STATUS_UNKNOWN   = -1,
    LINE_STATUS_RESERVED    =  0,
    LINE_STATUS_WILL_RET      =  1,
    LINE_STATUS_DESTINATION      =  2,
};

struct code_line {
    uint64_t            rip;
    uint8_t             hit;
    char                cmd[256];
    char                first[256];
    char                second[256];
    char                third[256];
    char                raw[256];
    enum line_status    will_ret;
    enum e_instructions instr;
    enum e_condition    cond;
    uint8_t             cond_negate;
    int                 width;
};

struct stack_frame_t {
    char                        symbol[64];
    uint8_t                     is_exception;
    uint64_t                    nearest;
    uint64_t                    rip;
    uint64_t                    rsp;
    uint32_t                    len;
    uint32_t                    allocated;
    struct code_line            *code;
    struct parameter_registers  regs;
};

struct stack_parser_context {
    uint8_t         frames_count;
    uint8_t         to_be_processed;
    uint8_t         should_get_stack_value;
    int64_t         irq_count;
    uint64_t        irq_count_offset;
    uint64_t        gs_base;
    struct stack_frame_t        *frames;
    struct task_context         *tc;
    struct stack_parser_context *parent;
};

struct list { uint64_t addr; struct list *next; };

#define REGEXP_RANGE(s, i) \
        s + matchptr[i].rm_so, matchptr[i].rm_eo - matchptr[i].rm_so

#define p_regs(R) ((char *)regs + offsets[R])
#define p_prev_regs(R) ((char *)prev_regs + offsets[R])

#define REGISTER_64BIT(r) (((r) / 5) * 5)

#define GET_MINIMAL(a,b) ((a) < (b) ? (a) : (b))
#define GET_MAXIMAL(a,b) ((a) > (b) ? (a) : (b))

/*
 * Operation Suffixes
 * b = byte (8 bit)
 * s = short (16 bit integer) or single (32-bit floating point)
 * w = word (16 bit)
 * l = long (32 bit integer or 64-bit floating point)
 * q = quad (64 bit)
 * t = ten bytes (80-bit floating point)
 */

uint64_t registers_mask[] = {
    0xffffffffffffffff,0x00000000ffffffff, 0x000000000000ffff,
    0x00000000000000ff, 0x00000000000000ff,
};
uint64_t registers_msb[] = {
    1ULL << 63, 1ULL << 31, 1ULL << 15, 1ULL << 7, 1ULL << 7,
};
const char *op_suffixes[]           = {"b", "s", "w", "l", "q"};
const unsigned char op_width[]      = { 8,   8,   16,  32,  64,};

/* TODO
 * Add conditional suffixes like `z`, `e`, `s` etc
 * for instructions `J`, `CMOV`, `SET`
 */
const char *conditions[] = { "a", "ae", "b", "be", "c", "e", "l", "s", "z", 0 };

const char *s_instructions[] = {
    "leave", "ud2", "nop", 
    "movzbl", "movzwl", "movslq", "movsbl", "movabs", "mov",
    "cmov",
    "pushf", "push", "popf", "pop", 
    "sub", "call", "lea", "ret", "xor", 
    "bts", "btr", "bt", "cmp", "test", "inc", "dec", "jmp", "j",
//    "jae", "jne", "jnz", "jbe", "jna", "jns", "jmp",
//    "ja", "jb", "jc", "je", "jz", "jl", "js", "j",
    "shl", "shr", "sar", "imul",
    "sbb", "xadd", "add", "not", "and", "or",
};

char *s_registers[] = {
    S_X("a"),   S_X("b"),   S_X("c"),   S_X("d"),
    S_IP("di"), S_IP("si"), S_IP("bp"), S_IP("sp"),
    S_R("8"),   S_R("9"),   S_R("10"),  S_R("11"),
    S_R("12"),  S_R("13"),  S_R("14"),  S_R("15"),
    S_RIP,
};

int16_t offsets[] = {
    OFF_X(a),   OFF_X(b),   OFF_X(c),   OFF_X(d),
    OFF_IP(di), OFF_IP(si), OFF_IP(bp), OFF_IP(sp),
    OFF_R(8),   OFF_R(9),   OFF_R(10),  OFF_R(11),
    OFF_R(12),  OFF_R(13),  OFF_R(14),  OFF_R(15),
    OFF_RIP,
};

char *traps_symbols[] = {
    "divide_error",                     // 0
    "debug",                            // 1
    "nmi",                              // 2
    "int3",                             // 3
    "overflow",                         // 4
    "bounds",                           // 5
    "invalid_op",                       // 6
    "device_not_available",             // 7
    "double_fault",                     // 8
    "coprocessor_segment_overrun",      // 9
    "invalid_TSS",                      // 10
    "segment_not_present",              // 11
    "stack_segment",                    // 12
    "general_protection",               // 13
    "page_fault",                       // 14
    "spurious_interrupt_bug",           // 15
    "coprocessor_error",                // 16
    "alignment_check",                  // 17
    "machine_check",                    // 18
    "simd_coprocessor_error",           // 19
    0
};

enum e_registers x86_64_abi_parameters[] = { RDI, RSI, RDX, RCX, R8, R9, R10 };
// struct per_cpu_variable *per_cpu_variables;

void parse_stack(struct bt_info *bt);

static uint8_t try_disassemble(const char *, uint64_t);
static void fill_mapped_register(struct stack_parser_context *, enum e_registers);
static void disassemble_frame(struct stack_frame_t *, unsigned char, uint8_t);
static uint8_t parse_frame(
        struct stack_parser_context *ctx, uint8_t, uint8_t, uint8_t,
        uint8_t (*)(enum e_instructions, char*, char*)
);
static uint8_t parse_argument(
        struct stack_parser_context *, struct parameter_registers *,
        char *, enum e_registers *, uint64_t *, enum e_reliability *
);
static void update_flags(
        uint64_t, enum e_registers, uint64_t, enum e_registers,
        uint64_t, unsigned char, struct parameter_registers *
);

static enum e_registers find_register(char *);
static enum e_instructions find_instr(const char *, int *);

static uint64_t str2dec(const char *, const char *);
static int8_t get_exception_no(const char *);
static int8_t get_exception_no_by_postprocess(const char *);
static uint64_t get_exception_displacement(int8_t);
static uint8_t is_apic_interrupt(const char *);

static uint8_t get_register_width(enum e_registers);
static uint8_t is_stack_register(enum e_registers);
static uint8_t is_param_register(enum e_registers);
static uint8_t is_callee_save_register(enum e_registers);
static uint8_t is_compare_instruction(enum e_instructions);
static uint8_t is_jump_instruction(enum e_instructions);

// static uint8_t save_args_callback(enum e_instructions, char *, char *);

static enum e_registers get_mapped(struct parameter_registers *, enum e_registers);
static uint8_t is_mapped(struct parameter_registers *, enum e_registers);
static void set_mapping(struct parameter_registers *, enum e_registers, enum e_registers);
static void clean_mapping(struct parameter_registers *, enum e_registers);
static void set_reliable(struct parameter_registers *, enum e_registers, enum e_reliability);
static void clean_reliable(struct parameter_registers *, enum e_registers);
static enum e_reliability get_reliable_state(struct parameter_registers *, enum e_registers);
static uint8_t wasnt_touched(struct parameter_registers *, enum e_registers);

static uint64_t get_reg(struct parameter_registers *, enum e_registers);
static void set_reg(struct parameter_registers *, enum e_registers, uint64_t);
static void add_reg(struct parameter_registers *, enum e_registers, int64_t);

static uint64_t get_stack_value(struct stack_parser_context *, uint64_t, unsigned char);
static void split_command(const char *, char *, char *, char *, char *, char *);
static uint8_t get_memory_operand(char *, struct parameter_registers *, uint64_t *, enum e_reliability *);

static uint8_t fill_frames(struct bt_info *, struct stack_parser_context *);
static uint8_t function_returns_value(const char *);
static void print_proto(struct stack_frame_t *, uint8_t, struct parameter_registers *);
static uint64_t get_frame_size(struct stack_parser_context *,char *, uint64_t, uint8_t);

static uint64_t pop_list (struct list **);
static void push_list (struct list **, uint64_t);
static uint8_t get_gdb_line(char *, char *);
static uint8_t error_occured_while_reading;

static enum e_condition find_cond(const char *);
static void print_mark(uint8_t, char *, struct code_line *);

static uint8_t try_disassemble(const char *c, uint64_t cip) {
    char b[BUFSIZE];

    if(!c || !*c)
        return 0;

    open_tmpfile();

    if(!strcmp(c, "system_call_fastpath"))
        c = "system_call";
    if(!strcmp(c, "ret_from_intr"))
        c = "common_interrupt";
    sprintf(b, "disassemble %s", c);
    if (gdb_pass_through(b, fp, GNU_RETURN_ON_ERROR))
        return 1;

    if(cip && strcmp(c, "error_entry"))
        sprintf(b, "disassemble %s, 0x%lx", c, cip);
    else
        sprintf(b, "x/150i %s", c);

    if (!gdb_pass_through(b, fp, GNU_RETURN_ON_ERROR)) {
        if (CRASHDEBUG(1)) fprintf(fp, "Error while disassembling '%s'\n", b);
        close_tmpfile();
        return 0;
    }
    return 1;
}

static void push_list (struct list **l, uint64_t v) {
    struct list *n = malloc(sizeof(struct list));
    n->next = *l;
    n->addr = v;
    *l = n;
}

static uint64_t pop_list (struct list **l) {
    struct list *o = *l;
    uint64_t v = o ? o->addr : 0;
    if(*l) {
        *l = (*l)->next;
        free(o);
    }
    return v;
}

static uint64_t str2dec(const char *s, const char *e) {
    long long int r = 0, hex = 0, neg = 0;
    if(0 == (s && *s))
        return 0;
    neg = (*s == '-');
    s += neg;
    s += *s == '$' ? 1 : 0;
    hex = (*s == '0' && *(s + 1) == 'x');
    s += hex << 1;

    while(e ? (s < e) : *s) {
        r *= (hex ? 16 : 10);
        if('0' <= (*s | 0x20) && (*s | 0x20) <= '9')
            r += (*s | 0x20) - '0';
        else if('a' <= (*s | 0x20) && (*s | 0x20) <= 'f')
            r += (*s | 0x20) - 'a' + 10;
        s++;
    }

    return (neg ? -1 : 1) * r;
}

static uint8_t get_gdb_line(char *i, char *o) {
    open_tmpfile2();
    if (!gdb_pass_through(i, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
        close_tmpfile2();
        fprintf(fp, "gdb request failed: %s\n", i);
        return 0;
    }
    rewind(pc->tmpfile2);
    fgets(o, BUFSIZE, pc->tmpfile2);
    if(*(o + strlen(o) - 1) == '\n')
        *(o + strlen(o) - 1) = 0;   // Chop trailing '\n'
    close_tmpfile2();

    return 1;
}

static int8_t get_exception_no_by_postprocess(const char *s) {
    uint8_t i;
    if(0 == (s && *s))
        return -1;

    if(strncmp(s, "do_", 3))
        return -1;

    for(i = 0; i < 19; i++)
        if(!strcmp(traps_symbols[i], s + 3))
            return i;

    return -1;
}

static int8_t get_exception_no(const char *s) {
    uint8_t i;

    if(0 == (s && *s))
        return -1;

    for(i = 0; i < 19; i++)
        if(!strcmp(traps_symbols[i], s))
            return i;

    if(STREQ(s, "system_call_fastpath") ||
       STREQ(s, "tracesys"))
        return 125;

    if(STREQ(s, "common_interrupt"))
        return 126;

    if(is_apic_interrupt(s))
        return 127;

    return -1;
}

static uint8_t is_apic_interrupt(const char *s) {
    const char *ai[] = {
        "thermal_interrupt", "threshold_interrupt",
        "reschedule_interrupt", "invalidate_interrupt",
        "call_function_interrupt", "apic_timer_interrupt",
        "error_interrupt", "spurious_interrupt", 0
    };
    uint8_t i = 0;
    if(0 == (s && *s))
        return 0;

    while(ai[i]) {
        if(STREQ(s, ai[i]))
            return 1;
        i++;
    }

    return 0;
}

static uint64_t get_exception_displacement(int8_t e) {
    if(0 <= e && e <= 7)
        return 5 * 0x8;
    switch(e) {
        case 9:
        case 15:
        case 16:
        case 18:
        case 19:
            return 5 * 0x8;
        case 126: /* common_interrupt */
            /* 0x8 - is for earlier pushed IRQ number (ENTRY irq_entries_start) */
            return 0x28 + 0x8;
        case 127: /* apic interrupt */
            return 0x28;
        default:
            return 6 * 0x8;
    }
}


static uint8_t is_param_register(enum e_registers reg) {
    uint8_t i;
    if(reg == INVALID)
        return 0;
    for(i = 0; i < 7; i++)
        if(REGISTER_64BIT(reg) == x86_64_abi_parameters[i])
            return 1;
    return 0;
}

static uint8_t is_callee_save_register(enum e_registers reg) {
    if(reg == INVALID)
        return 0;
    switch(REGISTER_64BIT(reg)) {
        case RBX:
        case RBP:
        case R12:
        case R13:
        case R14:
        case R15:
            return 1;
        default:
            return 0;
    }
}

static uint8_t is_stack_register(enum e_registers r) {
    switch(REGISTER_64BIT(r)) {
        case RBP:
        case RSP:
            return 1;
        default:
            return 0;
    }
}

static uint8_t is_compare_instruction(enum e_instructions i) {
    switch(i) {
        case BT:
        case BTS:
        case BTR:
        case CMP:
        case TEST:
            return 1;
        default:
            return 0;
    }
}

static uint8_t is_jump_instruction(enum e_instructions i) {
    switch(i) {
/*        case JAE:
        case JNE:
        case JNZ:
        case JBE:
        case JNA:
        case JNS:
        case JMP:
        case JA:
        case JB:
        case JC:
        case JE:
        case JZ:
        case JL:
        case OTHER_JUMP:*/
        case Jcc:
            return 1;
        default:
            return 0;
    }
}

static enum e_registers find_register(char *r) {
    int i;
    if(r && *r)
        for (i = 0; i < RCOUNT; i++)
            if(!strcmp(r, s_registers[i]))
                return i;

    return INVALID;
}

static enum e_condition find_cond(const char *c) {
    uint8_t i;
    for(i = 0; i < COND_COUNT; i++)
        if(STREQ(c, conditions[i]))
            return i;
    return COND_INVALID;
}

static uint8_t check_condition(struct parameter_registers *r, enum e_condition c, uint8_t cond_negate) {
    int res = 0;
    if(NULL == r)
        return 0;

    switch(c) {
        case COND_A:
            res = (r->zf == 1);
        case COND_AE:
            res &= (r->cf == 1);
            return cond_negate ^ res;
        case COND_C:
        case COND_B:
            return cond_negate ^ (r->cf == 1);
        case COND_BE:
            return cond_negate ^ (r->cf == 1 || r->zf == 1);
        case COND_L:
            return cond_negate ^ (r->of != r->sf);
        case COND_S:
            return cond_negate ^ (r->sf == 1);

        case COND_E:
        case COND_Z:
            return cond_negate ^ (r->zf == 1);
        default:
            return 0;
    }
}

enum e_instructions find_instr(const char *s, int *width) {
    int i, j;
    if(NULL == s || '\0' == *s)
        return -1;
    if(s && *s)
        for(i = 0; i < ICOUNT; i++)
            if(!strncmp(s, s_instructions[i], strlen(s_instructions[i])))
                break;
    if(i == ICOUNT)
        return -1;

    if(i == Jcc || i == CMOVcc)
        return i;
    if(strlen(s_instructions[i]) == strlen(s)) {
        if(width) *width = 64;
        return i;
    }

    for(j = 0; j <= 4; j++)
        if(0 == strcmp(s + strlen(s_instructions[i]), op_suffixes[j])) {
            if(width) *width = op_width[j];
            return i;
        }

    return -1;
}

static void fill_instruction(const char *s, int *width, struct code_line *cl) {
    if(NULL == cl)
        return;

    cl->instr = find_instr(s, width);
    if(cl->instr == Jcc || cl->instr == CMOVcc) {
        if(*(s + 1) == 'n') {
            cl->cond_negate = 1;
            cl->cond = find_cond(s + 2);
        } else {
            cl->cond_negate = 0;
            cl->cond = find_cond(s + 1);
        }
    } else
        cl->cond = COND_INVALID;
}


/* XXX Should be deleted XXX
static uint8_t save_args_callback(enum e_instructions instr_i, char *src, char *dst) {
    if(instr_i == PUSH && RBP == find_register(src))
        return 1;
    return 0;
}
*/

static uint8_t last_frame_to_process(char *s) {
    if(NULL == s)
        return 0;
    if(
        STREQ(s, "__schedule") ||
        STREQ(s, "kthread") ||
        STREQ(s, "cpu_idle") ||
        STREQ(s, "child_rip")
    )
        return 1;

    return 0;
}

static void set_reliable(struct parameter_registers *regs, enum e_registers r, enum e_reliability rel) {
    enum e_registers tr;
    if(r >= RCOUNT || NULL == regs) return;

    for(tr = REGISTER_64BIT(r); tr < r; tr++)
        regs->reliable[tr] = RELIABLE_NO;
    for(tr = r; tr < REGISTER_64BIT(r + 5); tr++)
        regs->reliable[tr] = rel;

    if(r == RIP)
        return;
    if (CRASHDEBUG(3))
        fprintf(fp, "\n\t\t\t\tSET RELIABLE (frame: %s) status '%d' for register: %s",
                (container_of(regs, struct stack_frame_t, regs))->symbol, rel, s_registers[r]);
}

static void clean_reliable(struct parameter_registers *regs, enum e_registers r) {
    set_reliable(regs, r, RELIABLE_NO);
}

enum e_reliability get_reliable_state(struct parameter_registers *regs, enum e_registers r) {
    if(r == INVALID)
        return RELIABLE_NO;
    return regs->reliable[r];
}

static uint64_t get_reg(struct parameter_registers *regs, enum e_registers r) {
    if(r >= RCOUNT) return 0;
    return (*((uint64_t*)p_regs(r)) & registers_mask[r % 5]);
}

static uint8_t get_register_width(enum e_registers r) {
    if(r >= RCOUNT) return 0;

    switch(r % 5) {
        case 0: return 64;
        case 1: return 32;
        case 2: return 16;
        case 3: return 8;
        case 4: return 8;
        default: return 0;
    }
}

static void set_reg(struct parameter_registers *regs, enum e_registers r, uint64_t value) {
    if(r >= RCOUNT) return;

    value = value & registers_mask[r % 5];

    switch(r % 5) {
        case 0:
            *((uint64_t*)p_regs(r)) = value; break;
        case 1:
            *((uint32_t*)p_regs(r)) = value; break;
        case 2:
            *((uint16_t*)p_regs(r)) = value; break;
        case 3:
            *((uint8_t*)p_regs(r)) = value; break;
        case 4:
            *((uint8_t*)p_regs(r)) = value; break;
    }
}

static void add_reg(struct parameter_registers *regs, enum e_registers r, int64_t delta) {
    set_reg(regs, r, get_reg(regs, r) + delta);
}

static uint8_t is_mapped(struct parameter_registers *regs, enum e_registers r) {
    if(r == INVALID || r >= RCOUNT)
        return 0;
    return !!(regs->params_mask & (1 << (r / 5)));
}

static void set_mapping(struct parameter_registers *regs, enum e_registers cs, enum e_registers p) {
    if(cs == INVALID || p == INVALID || cs >= RCOUNT || p >= RCOUNT)
        return;
    clean_mapping(regs, cs);
    clean_mapping(regs, p);
    // If we have instruction
    //    mov %rbx,%rdi
    // let's make our life easier with mutual mapping, that is
    // - rbx => rdi
    // - rdi => rbx

    regs->params_mask |= (1 << (cs / 5)) | (1 << (p / 5));
    regs->params_regs[cs] = p;
    regs->params_regs[p] = cs;
    if (CRASHDEBUG(3)) fprintf(fp, "\n\t\t\t\tSET MAPPING (frame '%s'): Value of %s <=> %s", 
            (container_of(regs, struct stack_frame_t, regs))->symbol, s_registers[cs], s_registers[p]);
}

static void clean_mapping(struct parameter_registers *regs, enum e_registers r) {
    enum e_registers i, rm = INVALID;
    if(INVALID == r || !is_mapped(regs, r))
        return;
    rm = get_mapped(regs, r);

    if(INVALID == (rm = get_mapped(regs, r))) {
        if (CRASHDEBUG(1)) fprintf(fp, "\t\tsomething wrong while cleaning mapping for register '%s'", s_registers[r]);
        return;
    }

    regs->params_mask &= ~( (1 << (r / 5)) | (1 << (rm / 5)));

    for(i = REGISTER_64BIT(r); i < REGISTER_64BIT(r + 5); i++)
        regs->params_regs[i] = INVALID;
    for(i = REGISTER_64BIT(rm); i < REGISTER_64BIT(rm + 5); i++)
        regs->params_regs[i] = INVALID;

    if (CRASHDEBUG(3))
        fprintf(fp, "\n\t\t\t\tREMOVE MAPPING (frame '%s') for register: %s (%s) <=> %s (%s)", 
            (container_of(regs, struct stack_frame_t, regs))->symbol,
            s_registers[REGISTER_64BIT(r)], s_registers[r],
            s_registers[REGISTER_64BIT(rm)], s_registers[rm]
        );
}

static enum e_registers get_mapped(struct parameter_registers *regs, enum e_registers r) {
    enum e_registers i;
    if(0 == is_mapped(regs, r))
        return INVALID;
    for(i = REGISTER_64BIT(r); i < REGISTER_64BIT(r + 5); i++)
        if(regs->params_regs[i] != INVALID)
            return regs->params_regs[i];
    return INVALID;
}

static uint8_t wasnt_touched(struct parameter_registers *regs, enum e_registers r) {
    return !(regs->was_touched & (1 << (r / 5)));
}
// XXX TODO:
// Frame 1:
//      mov    %r15,%rsi
// Frame 2:
//      mov    %rsi,%r12
//      mov    %r12,%rsi
// Frame 3:
//      mov    %r15,-0x8(%rbp)
// So, we definitely know, the value of R15 and consequently
// value of RSI at the beginning of frame 2
//
// XXX TODO:
//
// Frame 1:
//      mov    %r15,%rsi
// Frame 2:
//      mov    %rbx,%rsi <-- smash RSI
//      mov    %r15,-0x8(%rbp)  <--- wasnt_touched(regs, R15) == 0
//                              So, we CAN NOT restore RSI for current frame,
//                              but since R15 wasn't touch, we CAN restore
//                              RSI for the previous frame.
//
// For instance:
//      <worker_thread at    0xffffffff80049aaf <+232>:	mov    %rbx,%rdi SET MAPPING (frame 'worker_thread'): Value of %rbx <=> %rdi
//      <worker_thread at    0xffffffff80049ab2 <+235>:	callq  0xffffffff8004d0b2 <run_workqueue>
//  ...
//      <run_workqueue at    0xffffffff8004d0ba <+8>:	mov    %rdi,%r12 REMOVE MAPPING (frame 'run_workqueue') for register: %rdi (%rdi) <=> %rbx (%rbx)
//      <run_workqueue at    0xffffffff8004d0be <+12>:	push   %rbx                                                                                                                               
// >>>> OR <<<<
//      <cache_reap at    0xffffffff800d802a <+157>:	mov    %r12,%rdi
//      <cache_reap at    0xffffffff800d802d <+160>:	callq  0xffffffff800d74b5 <drain_array>
//  ...
//      <drain_array at    0xffffffff800d74b7 <+2>:	mov    %rdi,%r15 REMOVE MAPPING (frame 'drain_array') for register: %rdi (%rdi) <=> %r12 (%r12)
//      <drain_array at    0xffffffff800d74c4 <+15>:	push   %r12
// 
// XXX TODO:
static void fill_mapped_register(
        struct stack_parser_context *ctx,
        enum e_registers r
) {
    struct parameter_registers *regs, *prev_regs;
    enum e_registers untouched = INVALID, mr = INVALID /*Mapped register */;
    uint8_t mapping = 1; /* At first let's deal with mappings */
    uint32_t f;

    if(0 == ctx->to_be_processed || INVALID == r)
        return;

    for(f = ctx->to_be_processed; f < ctx->frames_count - 1;) {
        regs        = &(ctx->frames + f)->regs;
        prev_regs   = &(ctx->frames + f + 1)->regs;

        if(NULL == prev_regs || NULL == regs)
            return;
        if(mapping) {
            // Start with mapped registers
            if(is_mapped(regs, r) && wasnt_touched(regs, r)) {
                // It was mapped but for some reason we can't
                // determine which register it was mapped to.
                if(INVALID == (mr = get_mapped(prev_regs, r)))
                    break;

                if(mr != get_mapped(regs, r))
                    break;

                set_reg(regs, mr, get_reg(regs, r));
                set_reg(prev_regs, mr, get_reg(regs, r));
                set_reg(prev_regs, r, get_reg(regs, r));

                set_reliable(regs, mr, get_reliable_state(regs, r));
                set_reliable(prev_regs, mr, get_reliable_state(regs, mr));
                set_reliable(prev_regs, r, get_reliable_state(regs, r));

                clean_mapping(regs, r);

                if (CRASHDEBUG(1)) fprintf(fp, "\n\t\t\t\tMAPPING for frame '%s': Values: %s is 0x%lx and %s is 0x%lx now", 
                        (ctx->frames + f + 1)->symbol,
                        s_registers[mr],
                        get_reg(prev_regs, mr),
                        s_registers[r],
                        get_reg(prev_regs, r)
                );
            }
            if(0 == (r != INVALID && mr != INVALID))
                return;
            if(is_param_register(r) && wasnt_touched(regs, r))
                untouched = r;
            else if(is_param_register(mr) && wasnt_touched(regs, mr))
                untouched = mr;
            else
                return;

            mapping = 0;
        } else {
            // Afterwards try to fill registers which
            // were not touched while frame executing
            if(untouched == INVALID)
                break;

/* TODO Check, whether it's necessary. Apparently not.
            if((ctx->frames + f)->is_exception)
                break;
*/

            // TODO XXX
            // Track reliability of all stack memory,
            // for instance:
            //      mov     %rdi,0x78(%rsp)
            //      ...... and afterwards
            //      mov     0x12,0x78(%rsp)
            // that means, that RDI can't be reliable.
            // TODO XXX
            if(wasnt_touched(regs, untouched) 
               && RELIABLE_NO == get_reliable_state(prev_regs, untouched)) {
                set_reg(prev_regs, untouched, get_reg(regs, untouched));
                set_reliable(prev_regs, untouched, get_reliable_state(regs, untouched));
                regs->was_touched |= (1 << (untouched / 5));

                if (CRASHDEBUG(1)) fprintf(fp, "\n\t\t\t\tPOSTMAPPING for frame '%s': Values: %s is 0x%lx now",
                        (ctx->frames + f + 1)->symbol,
                        s_registers[untouched],
                        get_reg(prev_regs, untouched)
                );
            } else
                break;

        }
        f++;
    }

    return;
}

static uint64_t get_stack_value(struct stack_parser_context *ctx, uint64_t addr, unsigned char width) {
    uint64_t t = 0;
    ulong vma;
    char *vma_buf;
    int res = FALSE;
    error_occured_while_reading = 0;
    if(ctx && !ctx->should_get_stack_value) {
        error_occured_while_reading = 1;
        return 0;
    }

    if(!width)
        width = 64;

    if (IS_KVADDR(addr))
        res = readmem(addr, KVADDR, &t, width / 8, "long integer", RETURN_ON_ERROR | QUIET);
    else {
        if(0 == (vma = vm_area_dump(ctx->tc->task, UVADDR|VERIFY_ADDR, addr, 0)))
            return 0;
        if(NULL == (vma_buf = fill_vma_cache(vma)))
            return 0;
        if(
                (ULONGLONG(vma_buf + OFFSET(vm_area_struct_vm_start)) <= addr &&
                 addr <= ULONGLONG(vma_buf + OFFSET(vm_area_struct_vm_end)))
          )
            res = readmem(addr, UVADDR, &t, width / 8, "long integer", RETURN_ON_ERROR | QUIET);
    }

/*    else if (IS_UVADDR(addr, CURRENT_CONTEXT()))
        res = readmem(addr, UVADDR, &t, width / 8, "long integer", RETURN_ON_ERROR | QUIET); */

    if(FALSE == res)
        error_occured_while_reading = 1;

    return t;
/*
    if(FALSE == readmem(addr, KVADDR, &t, width / 8, "long integer", RETURN_ON_ERROR | QUIET))
        if(FALSE == readmem(addr, UVADDR, &t, width / 8, "long integer", RETURN_ON_ERROR | QUIET))
            error_occured_while_reading = 1;

    return t;
*/
}

static void split_command(const char *b, char *command, char *first, char *second, char *third, char *addr) {
        char re_s[] = "^[ \t]*(0x[a-f0-9]+)"                                // Address 
                            ".*:[ \t]+(lock[ \t]+)?([a-z0-9]+)([ \t]+)?"    // Some rubbish + command
                            "([^ ]+)?( +[<#].*)?\n";                        // Single/both parameters (in single match)
                                                                            // and <func name> in `call`

        unsigned char p = 0;
        char *m, *mm;   // Main marker & middle marker
        regex_t re;
        regmatch_t matchptr[7];
        regcomp(&re, re_s, REG_EXTENDED);
        if(regexec(&re, b, 7, matchptr, 0)) {
            regfree(&re);
            // If we can't parse particular command
            // try to parse its address at least
            regcomp(&re, "^[ \t]*(0x[a-f0-9]+)", REG_EXTENDED);
            if(0 == regexec(&re, b, 7, matchptr, 0)) {
                memcpy(addr, REGEXP_RANGE(b, 1));
                *first  = 0;
                *second = 0;
                *third  = 0;
            }
            regfree(&re);
            return;
        }

        if(addr)
            memcpy(addr, REGEXP_RANGE(b, 1));

        memcpy(command, REGEXP_RANGE(b, 3));
        *second = 0;
        *third = 0;

        if(-1 != matchptr[5].rm_so) {
            memcpy(first, REGEXP_RANGE(b, 5));
            m = first;
            while(1) {
                if (*m == '\0')
                    break;
                else if(*m == '(')
                    p = 1;
                else if(*m == ')')
                    p = 0;
                else if(0 == p && 0 == *second && *m == ',') {
                    strcpy(second, m + 1);
                    mm = m + 1;
                    *m = '\0';
                } else if(!p && *m == ',') {
                    *(second + (m - mm)) = '\0';
                    strcpy(third, m + 1);
                    *m = '\0';
                }
                m++;
            }
        } else
            *first = 0;
        regfree(&re);
}

static uint8_t get_memory_operand(
        char *arg, struct parameter_registers *regs,
        uint64_t *p_val, enum e_reliability *p_rel
) {
    char displ[16] = {0}, base[8] = {0}, offs[8] = {0}, mul[16] = {0};
    enum e_registers base_r, offs_r;
    /* If there are no either offset or base
     * considered them as absolutely reliable */
    enum e_reliability rel_b = RELIABLE_ABS, rel_o = RELIABLE_ABS;

    char *pb1, *pc1, *pc2, *pb2;

    *p_val = 0;
    if(p_rel)
        *p_rel = RELIABLE_NO;

    if(NULL != (pb1 = strstr(arg, "("))) {
        pb2 = strstr(pb1, ")");
        if(NULL != (pc1 = strstr(pb1 + 1, ",")))
            pc2 = strstr(pc1 + 1, ",");
        // We've got:
        // displacement(base register, offset register, scalar multiplier)
        //             |             |                |                  |
        //             pb1          pc1              pc2                pb2
        strncpy(displ, arg, pb1 - arg);
        if(pc1) {
            strncpy(base, pb1 + 1, pc1 - pb1 - 1);
            if(pc2)
                strncpy(offs, pc1 + 1, pc2 - pc1 - 1);
            else
                pc2 = pc1;
            strncpy(mul, pc2 + 1, pb2 - pc2 - 1);
        } else {
            strncpy(base, pb1 + 1, pb2 - pb1 - 1);
            strcpy(mul, "1");
        }
        if(*offs) {
            offs_r = find_register(offs);
            if(INVALID != offs_r) {
                if(RELIABLE_NO != (rel_o = get_reliable_state(regs, offs_r)))
                    *p_val = get_reg(regs, offs_r) * str2dec(mul, NULL);
                else
                    return 0; // Unreliable register
            }
        }
        if(*base) {
            base_r = find_register(base);
            if(INVALID != base_r) {
                if(RELIABLE_NO != (rel_b = get_reliable_state(regs, base_r)))
                    *p_val += get_reg(regs, base_r);
                else
                    return 0; // Unreliable register
            }
        }

        *p_val += str2dec(displ, NULL);
    } else {
        if('%' == *arg) {
            // Register here
        } else {
            // Immediate here
            *p_val = str2dec(arg, NULL);
        }
    }

    if(p_rel)
        *p_rel = rel_b > rel_o ? rel_o : rel_b;
    return 1;
}

// XXX Don't touch cause these functions might be helpful XXX

#if 0

static unsigned int find_frame_pointer(char *fname, ulong rip, FILE *ofp) {
        char b[BUFSIZE];
        char next_call[20];
        unsigned int offset = 0;
        if(!try_disassemble(fname, rip, ofp)) {
                return 0;
        }
        rewind(pc->tmpfile);
        char addr[19] = {0};
        while(fgets(b, BUFSIZE, pc->tmpfile)) {
                char command[64] = {0}, src[64] = {0}, dst[64] = {0};
                if(!*command)
                    continue;
                split_command(b, command, src, dst, addr);
                if(CALL == (find_instr(command, NULL))) {
                        strncpy(next_call, src, 20);
                        continue;
                }
                if(str2dec(addr, NULL) == rip)
                        break;
        }
        close_tmpfile();

        // Found call address
        if(str2dec(addr, NULL) == rip && *addr == '0' && *(addr + 1) == 'x') {
                if(!try_disassemble(next_call, 0, ofp))
                        return 0;
        } else
                return 0;

        rewind(pc->tmpfile);

        while(fgets(b, BUFSIZE, pc->tmpfile)) {
                char command[64] = {0}, src[64] = {0}, dst[64] = {0};
                split_command(b, command, src, dst, addr);
                if(PUSH == find_instr(command, NULL)) {
                        if(RBP == find_register(src)) {
                                close_tmpfile();
                                return offset;
                        }
                        else
                                offset += 8;
                }
        }
        close_tmpfile();

        return 0;
}

uint64_t get_call_address_before_rip(uint64_t rip) {
    char b[BUFSIZE], b2[BUFSIZE];
    if(!try_disassemble(closest_symbol(rip), rip, fp))
        return 0;
    rewind(pc->tmpfile);
    while(fgets(b, BUFSIZE, pc->tmpfile)) {
        char command[64] = {0}, src[64] = {0}, dst[64] = {0}, addr[19] = {0};
        split_command(b, command, src, dst, addr);
        if(!*command)
            continue;
        if(*b2 && *addr && (str2dec(addr, NULL) == rip)) {
            split_command(b2, command, src, dst, addr);
            if(!*src)
                return 0;
            close_tmpfile();
            return str2dec(src, NULL);
        }
        strncpy(b2, b, BUFSIZE);
    }
    close_tmpfile();
    return 0;
}

uint64_t get_per_cpu_by_address(uint64_t addr) {
    struct per_cpu_variable *pc_temp = per_cpu_variables;
    struct per_cpu_variable *pc_new;

    while(pc_temp) {
        if(pc_temp->addr == addr)
            return pc_temp->val;
        pc_temp = pc_temp->next;
    }

    new = malloc(sizeof(struct per_cpu_variable));
    new->addr = addr;
    new->val  = get_stack_value(NULL, addr, 64);
    new->next = per_cpu_variables;    
    per_cpu_variables = pc_new;

    return pc_new->val;
}

void set_per_cpu_by_address(uint64_t addr, uint64_t val) {
    struct per_cpu_variable *pc = per_cpu_variables;
    struct per_cpu_variable *new;

    while(pc) {
        if(pc->addr == addr) {
            pc->val = val;
            return;
        }
        pc = pc->next;
    }

    new = malloc(sizeof(struct per_cpu_variable));
    new->addr = addr;
    new->val  = val;
    new->next = per_cpu_variables;    
    per_cpu_variables = new;
}
#endif

static uint64_t get_frame_size(struct stack_parser_context *ctx, char *symbol, uint64_t rip, uint8_t may_return) {
    struct stack_frame_t frame = {
        .rip    = rip,
        .rsp    = 0,
    };

    if(NULL == symbol)
        return 0;

    memset(frame.regs.params_regs, 0xff, sizeof(uint8_t) * RCOUNT);
    memset(frame.regs.reliable, 0x0, sizeof(enum e_reliability) * RCOUNT);

    strncpy(frame.symbol, symbol, 64);
    disassemble_frame(&frame, may_return, 0);

    struct stack_parser_context t_ctx = {
        .frames = &frame,
        .frames_count = 1,
        .to_be_processed = 0,
        .should_get_stack_value = 0,
        .tc = ctx->tc,
        .irq_count_offset = ctx->irq_count_offset,
        .irq_count = ctx->irq_count,
        .gs_base = ctx->gs_base,
        .parent = NULL,
    };

    // Pretty dirty hack, TODO XXX
    parse_frame(&t_ctx, 1, 1, (may_return ? 0 : 1), NULL);
    ctx->irq_count_offset = t_ctx.irq_count_offset;
    ctx->irq_count = t_ctx.irq_count;
    if (CRASHDEBUG(1))
        fprintf(fp, "\nSize of `%s` frame of 0x%lx\n", symbol, 0 - frame.regs.rsp);

    return 0x0 - frame.regs.rsp;
}

static uint8_t fill_frames(struct bt_info *bt, struct stack_parser_context *ctx) {
    uint64_t frame_stack_rip_address, frame_stack_rip;
    char *frame_stack_sym;
    uint64_t current_frame_start, current_frame_end = bt->stkptr - 8;
    struct syment *sp;
    char buf[BUFSIZE], o_buf[BUFSIZE], *t;
    uint64_t init_tss, ist;
    struct stack_frame_t *p_cframe = ctx->frames;
    int8_t except_no;
    uint8_t calculate_frame_start = 1;
    uint8_t may_return = 0;
    uint64_t i;
    uint8_t exception_encountered = 0;

    memset(ctx->frames, 0, sizeof(struct stack_frame_t) * 64);

    if(!CRASHDEBUG(1)) {
        fprintf(fp, ".");
        fflush(fp);
    }


    frame_stack_rip_address = current_frame_end + 0x8;

    while(current_frame_end && ctx->frames_count <= 63) {
        // Here we should have:
        // - RIP of frame
        // - frame end address
        // - (optionally) frame start address

        if(CRASHDEBUG(4))
            fprintf(fp, "current_frame_end: 0x%lx, frame_stack_rip_address: 0x%lx",
                    current_frame_end, frame_stack_rip_address);

        frame_stack_sym = NULL;

        if(!CRASHDEBUG(1)) {
            fprintf(fp, ".");
            fflush(fp);
        }

        if(!is_kernel_data(current_frame_end)) {
            if (CRASHDEBUG(1))
                fprintf(fp, "rsp (0x%lx) is not within data section\n", current_frame_end);
            return 1;
        }
        if(!is_kernel_data(frame_stack_rip_address)) {
            if (CRASHDEBUG(1))
                fprintf(fp, "RIP address (0x%lx) is not within data section\n", frame_stack_rip_address);
            return 1;
        }

        readmem(frame_stack_rip_address, KVADDR, &frame_stack_rip, 8, "long integer", RETURN_ON_ERROR | QUIET);

        if(frame_stack_rip) {
            if(!is_kernel_text(frame_stack_rip)) {
                if (CRASHDEBUG(1))
                    fprintf(fp, "RIP (0x%lx) by address RSP + 8 (0x%lx) is not within text section\n", frame_stack_rip, frame_stack_rip_address);
                return 1;
            }
            frame_stack_sym = closest_symbol(frame_stack_rip - 5);
            if(NULL == frame_stack_sym)
                return 1;
        } else
            return 1;

        if(last_frame_to_process(frame_stack_sym))
            return 0;

        except_no = get_exception_no(frame_stack_sym);
        if(-1 == except_no && ctx->frames_count > 0) {
            except_no = get_exception_no_by_postprocess((p_cframe - 1)->symbol);
            if(-1 != except_no)
                frame_stack_sym = traps_symbols[except_no];
        }

        memset(&p_cframe->regs, 0x0, sizeof(struct parameter_registers));

        memset(p_cframe->regs.params_regs, 0xff, sizeof(uint8_t) * RCOUNT);
        memset(p_cframe->regs.reliable, 0x0, sizeof(enum e_reliability) * RCOUNT);

        if(STREQ(frame_stack_sym, "system_call_fastpath") ||
                STREQ(frame_stack_sym, "tracesys"))
            strcpy(p_cframe->symbol, "system_call");
        else
            strcpy(p_cframe->symbol, frame_stack_sym);

        p_cframe->regs.was_touched = 0;
        p_cframe->rip = frame_stack_rip;

        disassemble_frame(p_cframe, may_return, 0);

        // Not exception, calculate RSP
        if(-1 == except_no) {
            p_cframe->is_exception = 0;

            /* Try to find start of frame.
             * Keep in mind, current_frame_start
             * contains address within frame
             */
            if(exception_encountered) {
                current_frame_start = current_frame_start +
                    get_frame_size(ctx, p_cframe->symbol, frame_stack_rip, 1) - 0x10;
                exception_encountered = 0;
            } else if (calculate_frame_start)
                current_frame_start = current_frame_end +
                    get_frame_size(ctx, p_cframe->symbol, frame_stack_rip, may_return);

            p_cframe->rsp = current_frame_start + 0x8/* + (may_return ? 0 : 8) */;

            current_frame_end = current_frame_start;

            if (CRASHDEBUG(1))
                fprintf(fp, "RSP: 0x%lx; RIP: 0x%lx; symbol: %s\n", 
                        p_cframe->rsp, p_cframe->rip, p_cframe->symbol);

            p_cframe++;
            ctx->frames_count++;
            ctx->to_be_processed++;
            frame_stack_rip_address = current_frame_end + 0x8;
            calculate_frame_start = 1;
            may_return = 0;

            continue;
        }

        p_cframe->is_exception = 1;
        // System call entry point
        if(except_no == 125) {
            uint64_t read_rsp = 0;
            char *p;

            if(!ctx || !ctx->tc)
                return 1;

            for(i = 0; i < p_cframe->len; i++) {
                if(MOV == find_instr(p_cframe->code[i].cmd, NULL)) {
                    // Read the current RSP
                    if(RSP == find_register(p_cframe->code[i].second)) {
                        if(NULL == (p = strstr(p_cframe->code[i].first, "%gs:")))
                            continue;
                        read_rsp = str2dec(p + 4, NULL) + ctx->gs_base;
                        break;
                    }
                }
            }
            if(!read_rsp)
                return 1;
            readmem(
                    read_rsp, KVADDR, &p_cframe->rsp,
                    8, "long integer", RETURN_ON_ERROR | QUIET);

            if (CRASHDEBUG(1))
                fprintf(fp, "RSP: 0x%lx; RIP: 0x%lx; symbol: %s\n", 
                        p_cframe->rsp, p_cframe->rip, p_cframe->symbol);

            ctx->frames_count++;

            return 0; // We're not going to user-space
        }

        // Oops, exception.

        // Here we will read corresponding IST
        // from per_cpu__init_tss.ist[index].
        // Index will be read from idt_table[interrupt_#].ist
        if(except_no < 20) {
            // Read IST value from IDT
            sprintf(buf, "p/x idt_table[%d].ist", except_no);
            if(0 == get_gdb_line(buf, o_buf))
                return 1;
            if(0 == (t = strstr(o_buf, "= ")))
                return 1;
            else
                ist = str2dec(t + 2, NULL);
            if(CRASHDEBUG(3))
                fprintf(fp, "Found IST: %lu\n", ist);
        } else
            ist = 0;

        // RSP doesn't belong to this frame but to crashed function
        // So, going to find crashed function name
        if(ist) {
            // If IST specify, read it
            sp = per_cpu_symbol_search("init_tss");
            if(NULL == sp)
                return 1;
            init_tss = sp->value + kt->__per_cpu_offset[ctx->tc->processor];

            if(MEMBER_EXISTS("tss_struct", "ist")) {
                sprintf(buf, "p/x (( struct tss_struct *) 0x%lx).ist[%lu]", init_tss, ist - 1);
            } else {
                sprintf(buf, "p/x (( struct tss_struct *) 0x%lx).x86_tss.ist[%lu]", init_tss, ist - 1);
            }
            if(0 == get_gdb_line(buf, o_buf))
                return 1;

            if(0 == (t = strstr(o_buf, "= ")))
                return 1;
            else
                p_cframe->rsp = str2dec(t + 2, NULL); // Interrupt frame start
        } else if (except_no > 125) {
            /* That are 'common' and 'apic_timer' interrupts */
            // Interrupt entry point
            if(ctx->irq_count) {
                // Don't switch IRQ stack
                current_frame_start = current_frame_end +
                    get_frame_size(ctx, p_cframe->symbol, frame_stack_rip, 0);
                p_cframe->rsp = (current_frame_start + 8) & ~((uint64_t )0x8);
            } else {
                // Switch 'em al
                readmem(current_frame_end + 0x10, KVADDR,
                        &current_frame_start, 8, "long integer", RETURN_ON_ERROR | QUIET);
                current_frame_start += 0x88;
                p_cframe->rsp = current_frame_start & ~((uint64_t )0x8);

                ctx->irq_count = -1;
            }
        } else {
            /* 1..19 Interrupts within existing stack */
            // Don't switch IRQ stack
            p_cframe->rsp = ((p_cframe - 1)->rsp + 0xa8 + 0x10 - (get_exception_displacement(except_no) - 0x28));
            p_cframe->rsp &= ~((uint64_t )0x8);
        }
        // XXX Previous RSP (1)
        // That is RSP of function which was interrupted
        // (neither start or end - somewhere within),
        // so we need to calculate frame start
        readmem(p_cframe->rsp - 0x10, KVADDR,
                &current_frame_start, 8, "long integer", RETURN_ON_ERROR | QUIET);
        may_return = 1;

        if (CRASHDEBUG(1))
            fprintf(fp, "RSP: 0x%lx; RIP: 0x%lx; symbol: %s\n", 
                    p_cframe->rsp, p_cframe->rip, p_cframe->symbol);

        // Read unconditionally saved RIP
        readmem(p_cframe->rsp - 0x28, KVADDR,
                &frame_stack_rip, 8, "long integer", RETURN_ON_ERROR | QUIET);

        //
        // If saved RIP is zero, probably is was caused by `call 0`,
        // so, let's read return RIP
        //
        if(frame_stack_rip)
            frame_stack_rip_address = p_cframe->rsp - 0x28;
        else {
            readmem(p_cframe->rsp, KVADDR,
                    &frame_stack_rip, 8, "long integer", RETURN_ON_ERROR | QUIET);
            if(frame_stack_rip)
                frame_stack_rip_address = p_cframe->rsp;
            else
                return 1;
            // We should add 0x8 which were used for pushing
            // return RIP while making `call 0`
            current_frame_start += 0x8;
        }

        exception_encountered = 1;

        p_cframe++;
        ctx->frames_count++;
        ctx->to_be_processed++;
    }

    if(!CRASHDEBUG(1)) {
        fprintf(fp, "\n");
        fflush(fp);
    }

    return 0;
}

static uint8_t function_returns_value(const char *name) {
    char b[BUFSIZE];
    char *dot;
    if(!name)
        return 0;
    sprintf(b, "whatis %s", name);
    if(NULL != (dot = strstr(b, ".")))
        *dot = '\0';

    open_tmpfile2();

    if (!gdb_pass_through(b, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
        close_tmpfile2();
        if (CRASHDEBUG(1)) fprintf(fp, "\ngdb request failed: whatis %s\n", name);
        // Can't figure out, whether function returns value
        // Consider the worst case - it returns, we'll mark
        // RAX as unreliable
        return 1;
    }

    rewind(pc->tmpfile2);
    if(NULL == fgets(b, BUFSIZE, pc->tmpfile2))
        return 1;

    close_tmpfile2();
    if(b == strstr(b, "type = void ("))
        return 0;
    return 1;
}

static void print_proto(struct stack_frame_t *f, uint8_t n, struct parameter_registers *regs) {
    const char *sym = f->symbol;
    char b[BUFSIZE], type[BUFSIZE] = "p sizeof(", type_buf[BUFSIZE];
    char *dot;
    uint8_t param_size;
    char *s, *e;
    enum e_registers params[] = {RDI, RSI, RDX, RCX, R8, R9}, curr_param;
    uint64_t param_mask;
    uint8_t r_i = 0;
    uint8_t parentheses = 0;

    if(!sym || !*sym)
        return;

    sprintf(b, "whatis %s", sym);
    if(NULL != (dot = strstr(b, ".")))
        *dot = '\0';
    open_tmpfile2();

    if (!gdb_pass_through(b, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
        close_tmpfile2();
        fprintf(fp, "gdb request failed: whatis %s\n", sym);
        return;
    }

    rewind(pc->tmpfile2);
    while (fgets(b, BUFSIZE, pc->tmpfile2)) {
        if (NULL != (s = strstr(b, "type = ")))
            break;
    }

    close_tmpfile2();

    fprintf(fp, "#%4d: [RSP: 0x%lx, RIP: 0x%lx] %s (", n, f->rsp, f->rip, sym);
    if((NULL == (s = strstr(b, "("))) || strstr(b, "...)")) {
        if(f->is_exception)
            fprintf(fp, "void)\n");
        else {
            if(strstr(b, "...)"))
                fprintf(fp, " ... )\n\t< Argument list for symbol: %s\n", sym);
            else
                fprintf(fp, "?, ?, ?)\n\t< Can't get prototype for symbol: %s\n", sym);
            fprintf(fp, "\t\tRDI: 0x%lx,\tRSI: 0x%lx,\tRDX: 0x%lx\n", get_reg(regs, RDI), get_reg(regs, RSI), get_reg(regs, RDX));
            fprintf(fp, "\t\tRCX: 0x%lx,\tR8: 0x%lx,\tR9: 0x%lx\n", get_reg(regs, RCX), get_reg(regs, R8), get_reg(regs, R9));
        }
        return;
    }
    s++;
    e = s;

    for(; *e; e++) {
        if(0 == strncmp(s, "void)", 5))
            break;
        if((*e == ')' || *e == ',') && s < e && parentheses == 0) {
            strncpy(type + 9, s, e - s);
            type[9 + e - s] = ')';
            type[10 + e - s] = 0;
            open_tmpfile2();
            if (!gdb_pass_through(type, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
                close_tmpfile2();
                fprintf(fp, "gdb request failed: %s\n", type);
                return;
            }
            rewind(pc->tmpfile2);
            fgets(type_buf, BUFSIZE, pc->tmpfile2);
            type_buf[strlen(type_buf) - 1] = 0; // Chop trailing '\n'
            close_tmpfile2();


            for(; s < e; s++)
                fprintf(fp, "%c", *s);

            if(0 == (s = strstr(type_buf, " = ")))
                return;
            param_mask = 0;
            param_size = str2dec(s + 3, NULL);
            switch(param_size) {
                case 8:
                    param_mask |= 0xffffffffffffffff;
                case 4:
                    param_mask |= 0x00000000ffffffff;
                case 2:
                    param_mask |= 0x000000000000ffff;
                case 1:
                    param_mask |= 0x00000000000000ff;
            }

            curr_param = params[r_i];
            curr_param += (param_size == 4 ? 1 : (param_size == 2 ? 2 : (param_size == 1 ? 3 : 0)));

            if(RELIABLE_ABS == get_reliable_state(regs, curr_param))
                fprintf(fp, " arg = 0x%lx", param_mask & get_reg(regs, curr_param));
            else if(get_reliable_state(regs, params[r_i]))
                fprintf(fp, " arg = 0x%lx (*)", param_mask & get_reg(regs, curr_param));
            else
                fprintf(fp, " arg = unknown");

            r_i++;
            if(*e == ')') break;
            fprintf(fp, ", ");
            s = e;
            while(*s == ',' || *s == ' ') s++;
            e = s;
        }
        if(*e == '(')
            parentheses++;
        else if(*e == ')' && *(e + 1))
            parentheses--;
    }
    fprintf(fp, ")\n");
}

static void print_mark(uint8_t i, char *st, struct code_line *cl) {
    if (CRASHDEBUG(3))
        fprintf(fp,
                "%d: Set `%s` for '0x%lx: %s %s,%s,%s'\n",
                i, st, cl->rip, cl->cmd,
                cl->first,
                cl->second, cl->third
               );
}

/* TODO
 * Remove all will_ret magic,
 * make it more obvious :)
 */

static void disassemble_frame(struct stack_frame_t *frame, unsigned char will_ret, uint8_t recursive) {
#define MIN_CODE_BUFFER     1024
    char b[BUFSIZE];
    enum e_instructions instr_i;
    uint64_t jump_to;
    int32_t i, j, k;
    int32_t last_checkpoint = 0;
    struct load_module *lm;
    uint8_t external_marked, internal_marked;
    struct list *l = NULL;
    uint64_t jump_addr = 0;
    int64_t return_idx = -1;
    char command[256], addr[20];
    char first[256], second[256], third[256];
    struct code_line *c;
    

    if(module_symbol(frame->rip, NULL, &lm, NULL, 0)) {
        if (CRASHDEBUG(1))
            fprintf(fp, "Module: %s\n", lm->mod_name);
        load_module_symbols_helper(lm->mod_name);
    }

    if(!try_disassemble(frame->symbol, frame->rip)) {
        if (CRASHDEBUG(1)) fprintf(fp, "Oops: %s .. 0x%lx\n", frame->symbol, frame->rip);
        return;
    }

    do {
process_sym:
        rewind(pc->tmpfile);
        while(fgets(b, BUFSIZE, pc->tmpfile)) {
#define current_line (frame->code[frame->len])
            memset(addr, 0, sizeof(char) * 20);
            memset(command, 0, sizeof(char) * 256);
            memset(first, 0, sizeof(char) * 256);
            memset(second, 0, sizeof(char) * 256);
            memset(third, 0, sizeof(char) * 256);

            split_command(b, command, first, second, third, addr);

            if(frame->len == frame->allocated) {
                c = realloc(frame->code, sizeof(struct code_line) * (MIN_CODE_BUFFER + frame->allocated));
                if(NULL != c) {
                    frame->code = c;
                    frame->allocated += MIN_CODE_BUFFER;
                } else
                    error(FATAL, "Can't allocate memory for disassembled code");
            }

            memset(&frame->code[frame->len], 0, sizeof(struct code_line));
            current_line.instr  = INVALID;
            current_line.cond   = COND_INVALID;
            current_line.cond_negate = 0;

            if(*addr) {
                b[strlen(b) - 1] = '\0';
                strncpy(current_line.raw, b, 255);
                current_line.rip = str2dec(addr, NULL);
                current_line.hit = 0;
                current_line.will_ret = LINE_STATUS_UNKNOWN;
            } else continue;

            if(0 == *command) {
                frame->len++;
                continue;
            }

            strncpy(current_line.cmd, command, 255);
            strncpy(current_line.first, first, 255);
            strncpy(current_line.second, second, 255);
            strncpy(current_line.third, third, 255);
            if(is_jump_instruction(find_instr(command, NULL))) {
                char *sym = closest_symbol(str2dec(first, NULL));
                if(!STREQ(sym, frame->symbol)) {
                    push_list(&l, str2dec(first, NULL));
                }
            }

            fill_instruction(current_line.cmd, &(current_line.width), &current_line);

            frame->len++;
#undef current_line
        }
        // Loop every found jump destination address
        while(0 != (jump_addr = pop_list(&l))) {
            for(i = 0; i < frame->len; i++)
                if(frame->code[i].rip == jump_addr)
                    break;

            // Found within disassembled code - try next
            if((i < frame->len) && (frame->code[i].rip == jump_addr))
                continue;
            // Otherwise disassemble it
            char *sym = closest_symbol(jump_addr);
            if(sym) {
                close_tmpfile();
                if(!try_disassemble(sym, frame->rip)) {
                    if (CRASHDEBUG(1)) fprintf(fp, "Can't disassemble symbol '%s'\n", sym);
                    return;
                }
                goto process_sym;
            }
        }
        break;
    } while(1);
#undef MIN_CODE_BUFFER

    close_tmpfile();

    if(recursive)
        return;

    if(CRASHDEBUG(3))
        fprintf(fp, "Filling will_ret field for symbol '%s'\n", frame->symbol);

    // Let's mark some instructions as destination.
    for(j = frame->len - 1; j >= 0; j--) {
        if(frame->rip == frame->code[j].rip && j > 1 /* j should be (and would be) more than 1 */) {
            return_idx = j;
            for(i = j - 1; i > 0; i--) {
                if(
                    *frame->code[i].cmd &&
                    (
                        is_jump_instruction(frame->code[i].instr) ||
                        frame->code[i].instr == RET
                    )
                )
                    break;
                if(frame->code[i].will_ret != LINE_STATUS_DESTINATION) {
                    frame->code[i].will_ret = LINE_STATUS_DESTINATION;
                    print_mark(5, "LINE_STATUS_DESTINATION", &frame->code[i]);
                }
            }

            break;
        }
    }

    // Mark some regions with LINE_STATUS_WILL_RET to indicate that
    // we shouldn't process them.
    // Before marking check, whether region contains instruction
    // with address specified in `frame->rip`.

    // The 0-th pass
    for(j = 0; j < frame->len; j++) {
        if(0 == *frame->code[j].cmd)
            continue;
        instr_i = find_instr(frame->code[j].cmd, NULL);

        if(
                is_jump_instruction(instr_i) ||
                // Instruction after CALL is the return address
                (CALL == instr_i && (j + 1) < frame->len && frame->code[j + 1].rip == frame->rip)
        ) {
            jump_to = str2dec(frame->code[j].first, NULL);  // .first parameter == jump address
            if(is_jump_instruction(instr_i)) {
                if(frame->nearest) {
                    if((j + 1 < frame->len) && (frame->code[j].rip < frame->rip) && (frame->code[j].rip > frame->nearest))
                        frame->nearest = frame->code[j + 1].rip;
                } else if((j + 1 < frame->len) && frame->code[j].rip < frame->rip) {
                    frame->nearest = frame->code[j + 1].rip;
                }
            }
            last_checkpoint = j;
        }

        // This hack is necessary for the following case:
        //
        // callq  0xffffffff81503180 <kprobe_fault_handler>
        // test   %eax,%eax
        // je     0xffffffff8104457e <__do_page_fault+494>
        // mov    -0x28(%rbp),%rbx
        // mov    -0x20(%rbp),%r12
        // mov    -0x18(%rbp),%r13
        // mov    -0x10(%rbp),%r14
        // mov    -0x8(%rbp),%r15
        // leaveq 
        // retq
        //
        // When we have no idea about return value but we'll
        // definitely jump and not return.
        // XXX Additional condition is that region we're going to mark
        // XXX doesn't contain frame->rip. This is necessary for
        // XXX calculating interrupted frame size
        if(instr_i == RET && last_checkpoint) {
            for(i = 1 + last_checkpoint; i <= j; i++) {
                if(frame->code[i].will_ret == LINE_STATUS_UNKNOWN) {
                    frame->code[i].will_ret = LINE_STATUS_WILL_RET;
                    print_mark(1, "LINE_STATUS_WILL_RET", &frame->code[i]);
                }
            }
            last_checkpoint += 1;
        }
    }

    // Main rule for every case:
    //
    // for regions which contain return RIP
    // put markers LINE_STATUS_WILL_RET partially
    // for those which previously have marker
    // LINE_STATUS_UNKNOWN
    //      LINE_STATUS_DESTINATION  => 0xffffffff8149cac4 <+48>:   je     0xffffffff8149cace
    //      LINE_STATUS_DESTINATION  => 0xffffffff8149cac6 <+50>:   mov    %r12,%rdi
    //      LINE_STATUS_DESTINATION  => 0xffffffff8149cac9 <+53>:   callq  0xffffffff81093050 <crash_kexec>
    //      LINE_STATUS_WILL_RET  => 0xffffffff8149cace <+58>:   xor    %edi,%edi
    //      LINE_STATUS_WILL_RET  => 0xffffffff8149cad0 <+60>:   callq  0xffffffff81243ddc
    //      LINE_STATUS_WILL_RET  => 0xffffffff8149cad5 <+65>:   mov    $0x7,%edi
    //      LINE_STATUS_WILL_RET  => 0xffffffff8149cada <+70>:   movl   $0xffffffff,0x5b1cb4(%rip)
    //      LINE_STATUS_WILL_RET  => 0xffffffff8149cae4 <+80>:   callq  0xffffffff81050eaa
    //      LINE_STATUS_WILL_RET  => 0xffffffff8149cae9 <+85>:   mov    0x9e5565(%rip),%eax
    //      LINE_STATUS_WILL_RET  => 0xffffffff8149caef <+91>:   dec    %eax
    //      LINE_STATUS_WILL_RET  => 0xffffffff8149caf1 <+93>:   test   %eax,%eax
    //      LINE_STATUS_WILL_RET  => 0xffffffff8149caf3 <+95>:   mov    %eax,0x9e555b(%rip)
    //      LINE_STATUS_WILL_RET  => 0xffffffff8149caf9 <+101>:  jne    0xffffffff8149cb02
    
    do {
        external_marked = 0;
        
        // This is the pass for cases:
        //
        //      nopw   0x0(%rax,%rax,1)
        //      mov    -0xe8(%rbp),%rdi
        //      callq  0xffffffff81097740 <up_read>
        //      jmp    0xffffffff81044554 <__do_page_fault+452>
        //
        // where the last jump address is the address marked
        // on the previous pass.
        //
        // OR
        //
        //      callq  0xffffffff81043f40 <bad_area_nosemaphore>
        //      jmpq   0xffffffff81044554 <__do_page_fault+452>
        // 
        // Here we'll mark only the JMP line, because the first one
        // is the call of subsequent function.
        //
        // OR
        //
        //      leaveq              <--------------------------------|
        //      retq                                                 |
        //      mov    -0xe8(%rbp),%rdi                              |
        //      callq  0xffffffff81097740 <up_read>                  |
        //      jmp    0xffffffff81044554 <__do_page_fault+452> -----|
        // 
        // In this case we'll mask only `mov`, `call` and `jmp`
        do {
            internal_marked = 0;
            last_checkpoint = 0;
            for(j = 0; j < frame->len; j++) {
                if(0 == *frame->code[j].cmd || frame->code[j].will_ret == LINE_STATUS_WILL_RET)
                    continue;
                instr_i = find_instr(frame->code[j].cmd, NULL);
                if(
                        (is_jump_instruction(instr_i) && instr_i != JMP) ||
                        (CALL == instr_i && (j + 1) < frame->len && frame->code[j + 1].rip == frame->rip) ||
                        (RET == instr_i)
                  ) {
                    last_checkpoint = j;
                } else if(instr_i == JMP && last_checkpoint) {
                    jump_to = str2dec(frame->code[j].first, NULL);
                    for (i = 0; i < frame->len; i++) {
                        if(jump_to != frame->code[i].rip)
                            continue;
                        else
                            break;
                    }
                    if(jump_to == frame->code[i].rip && frame->code[i].will_ret == LINE_STATUS_WILL_RET) {
                        for(k = last_checkpoint + 1; k <= j; k++) {
                            if(frame->code[k].will_ret == LINE_STATUS_UNKNOWN) {
                                frame->code[k].will_ret = LINE_STATUS_WILL_RET;
                                print_mark(2, "LINE_STATUS_WILL_RET", &frame->code[k]);
                                internal_marked = 1;
                            }
                        }
                    }
                    last_checkpoint = j;
                }
            }
        } while(internal_marked);

        // This is the pass for case:
        //      mov    0x28(%rbx),%rax
        //      or     $0x84,%dh
        //      mov    %edx,0x50(%rbx)
        //      mov    0x38(%rax),%rdx
        //      test   %rdx,%rdx
        //      je     0xffffffff810de31d <handle_edge_irq+349>
        //
        //  when the next line after JE instruction already marked
        //  (will_ret = LINE_STATUS_WILL_RET) and the instruction at <handle_edge_irq+349> 
        //  is also marked (will_ret = LINE_STATUS_WILL_RET), that means we can't get into
        //  current block.
    
        do {
            internal_marked = 0;
            last_checkpoint = 0;
            for(j = 0; j < frame->len; j++) {
                if(0 == *frame->code[j].cmd)
                    continue;
                instr_i = find_instr(frame->code[j].cmd, NULL);
                if(is_jump_instruction(instr_i) && instr_i != JMP && last_checkpoint && ((j + 1) < frame->len && frame->code[j + 1].will_ret == LINE_STATUS_WILL_RET)) {
                    jump_to = str2dec(frame->code[j].first, NULL);
                    for (i = 0; i < frame->len; i++) {
                        if(jump_to != frame->code[i].rip)
                            continue;
                        else
                            break;
                    }
                    if(jump_to == frame->code[i].rip && frame->code[i].will_ret == LINE_STATUS_WILL_RET) {
                        for(k = last_checkpoint + 1; k <= j; k++) {
                            if(frame->code[k].will_ret == LINE_STATUS_UNKNOWN) {
                                frame->code[k].will_ret = LINE_STATUS_WILL_RET;
                                print_mark(3, "LINE_STATUS_WILL_RET", &frame->code[k]);
                                internal_marked = 1;
                                external_marked = 1;
                            }
                        }
                    }
                    last_checkpoint = 0;
                } else if(
                        is_jump_instruction(instr_i) ||
                        (CALL == instr_i && (j + 1) < frame->len && frame->code[j + 1].rip == frame->rip)
                ) {
                    last_checkpoint = j;
                }
            }
        } while(internal_marked);

        // For case:
        //     0xffffffff8150417b <+203>:	mov    $0xffffffff81689a94,%rdi
        //     0xffffffff81504182 <+210>:	xor    %eax,%eax
        //     0xffffffff81504184 <+212>:	callq  0xffffffff8150036c <panic>
        //     0xffffffff81504189 <+217>:	mov    $0xffffffff81689a77,%rdi
        //     0xffffffff81504190 <+224>:	xor    %eax,%eax
        //     0xffffffff81504192 <+226>:	callq  0xffffffff8150036c <panic>
        // where 0xffffffff81504192 is the last instruction. So we need to move
        // upward and mark every command until we encounter return RIP or jump
        // instruction.
        // 
        // OR
        //
        //     0xffffffff81105155 <+149>:	callq  0xffffffff81080fb0 <warn_slowpath_fmt>
        //     0xffffffff8110515a <+154>:	movb   $0x1,%gs:0x1cf098
        //     0xffffffff81105163 <+163>:	pop    %rbp
        //     0xffffffff81105164 <+164>:	retq   
        //     0xffffffff81105165 <+165>:	mov    %ecx,%esi
        //     0xffffffff81105167 <+167>:	mov    $0xffffffff819e7cd8,%rdi
        //     0xffffffff8110516e <+174>:	callq  0xffffffff8161734c <panic>
        // if we're going to next frame by means of last `call` instruction
        // (and consequently we don't have instruction with return RIP)
        // let's mark every command until we encounter jump/call instruction or
        // instruction we have already marked.
        if(
                find_instr(frame->code[frame->len - 1].cmd, NULL) == CALL &&
                frame->code[frame->len - 1].rip >= frame->rip
        ) {
            for(j = frame->len - 1; j > 0; j--) {
                if(0 == *frame->code[j].cmd)
                    continue;
                instr_i = find_instr(frame->code[j].cmd, NULL);
                if(is_jump_instruction(instr_i))
                    break;
                if(frame->code[j].will_ret == LINE_STATUS_UNKNOWN) {
                    frame->code[j].will_ret = LINE_STATUS_WILL_RET;
                    print_mark(2, "LINE_STATUS_WILL_RET", &frame->code[j]);
                    external_marked = 1;
                }
                if(frame->rip == frame->code[j].rip)
                    break;
            }
        } else if(
                find_instr(frame->code[frame->len - 1].cmd, NULL) == CALL &&
                frame->code[frame->len - 1].rip < frame->rip
        ) {
            for(j = frame->len - 1; j > 0; j--) {
                if(0 == *frame->code[j].cmd)
                    continue;
                instr_i = find_instr(frame->code[j].cmd, NULL);
                if(is_jump_instruction(instr_i) || CALL == instr_i)
                    break;
                if(frame->code[j].will_ret != LINE_STATUS_UNKNOWN)
                    break;
                if(frame->code[j].will_ret == LINE_STATUS_UNKNOWN) {
                    frame->code[j].will_ret = LINE_STATUS_DESTINATION;
                    print_mark(2, "LINE_STATUS_DESTINATION", &frame->code[j]);
                    external_marked = 1;
                }
                if(frame->rip == frame->code[j].rip)
                    break;
            }
        }
    } while(external_marked);
}

static void update_flags(
        uint64_t s, enum e_registers sreg_i,
        uint64_t d, enum e_registers dreg_i,
        uint64_t r, unsigned char cf,
        struct parameter_registers *regs
) {
    regs->cf = cf;
    if(r)
        regs->zf = 0;
    else
        regs->zf = 1;

    if(r & registers_msb[dreg_i % 5])
        regs->sf = 1;
    else
        regs->sf = 0;

    // Sign-extension of source & destination
    if(s & registers_msb[sreg_i % 5])
        s |= !(registers_mask[dreg_i % 5]);
    if(d & registers_msb[sreg_i % 5])
        d |= !(registers_mask[dreg_i % 5]);

    if(((int64_t)d > (int64_t)s))
        regs->of = regs->sf;
    else if(((int64_t)d < (int64_t)s))
        regs->of = regs->sf ? 0 : 1;
    else
        regs->of = 0;
}

static uint8_t parse_argument(
        struct stack_parser_context *ctx, struct parameter_registers *r,
        char *s_arg, enum e_registers *reg_i, uint64_t *arg,
        enum e_reliability *reliable
) {
    char *p;
    uint64_t displ;

    if(reliable)
        *reliable = RELIABLE_ABS;
    if(reg_i)
        *reg_i = find_register(s_arg);
    if(0 == (s_arg && *s_arg))
        return 0;
    if(INVALID != *reg_i)
        *arg = get_reg(r, *reg_i);
    else if(strstr(s_arg, "(")) {
        get_memory_operand(s_arg, r, arg, reliable);
        return 1;
    } else if(NULL != (p = strstr(s_arg, "%gs:"))) {
        displ = str2dec(p + 4, NULL);
        *arg = displ + ctx->gs_base;
        *reg_i = GS_REG;
    } else
        *arg = str2dec(s_arg, NULL);

    return 0;
}

static void print_value(struct parameter_registers *regs, enum e_registers r) {
    if (CRASHDEBUG(1)) fprintf(fp, "\n\t\t\t\tValue of %s is 0x%lx now", s_registers[r], get_reg(regs, r));
}

static uint8_t parse_frame(
        struct stack_parser_context *ctx,
        uint8_t may_call,
        uint8_t update_sp,
        uint8_t calculating_frame_size,
        uint8_t (*callback)(enum e_instructions, char*, char*))
{
    enum e_registers reg_i[3]; /* indices for operands */
    enum e_instructions instr_i;
    enum e_condition cond;
    uint8_t cond_negate;
    int width;
    char *e;
    int line_i, old_line_i;
    uint64_t arg, arg2, res = 0;
    uint8_t cf;
    uint8_t is_s_memory_operand, is_d_memory_operand;
    char *calling_symbol;
    uint64_t jump_to = 0;
    char *jmp_symbol = NULL;
    int8_t except_no;
    struct stack_frame_t *frame = ctx->frames + ctx->to_be_processed;
    struct parameter_registers *regs = &frame->regs;
    uint64_t temp_rsp;

    if(!frame->rip && !frame->symbol[0]) {
        if (CRASHDEBUG(1)) fprintf(fp, ">>> Calling a NULL-pointer\n");
        return (uint8_t)-1;     // In fact, abnormal return
    }

    if (CRASHDEBUG(1))
        fprintf(fp, "\nSymbol: %s; RIP: 0x%lx; RSP: tracked: 0x%lx, calculated: 0x%lx\n", 
                frame->symbol, frame->rip, get_reg(regs, RSP), frame->rsp);

    except_no = get_exception_no(frame->symbol);

    if(frame->rsp)
        set_reg(regs, RSP, frame->rsp);
    else
        add_reg(regs, RSP, -0x8);

    set_reliable(regs, RSP, RELIABLE_ABS);
    print_value(regs, RSP);

    if(-1 != except_no) {
        *((uint64_t *)p_regs(RSP)) &= ~((uint64_t )0x8); // Stack in exceptions aligned
        // Stack in case of exceptions:
        //
        // +0x00 - Error code
        // +0x08 - Return RIP
        // +0x10 - Returt CS
        // +0x18 - Returt RFLAGS
        // +0x20 - Returt RSP
        // +0x28 - Returt SS
        //
        // But for some exceptions there is no error-code on stack
        add_reg(regs, RSP, 0 - get_exception_displacement(except_no));
        set_reliable(regs, RSP, RELIABLE_ABS);
        if (CRASHDEBUG(1))
            fprintf(fp, "\nException: %s\t\tValue of %s is 0x%lx now\n",
                    frame->symbol, s_registers[RSP], get_reg(regs, RSP));
    }

    // shortcuts
#define sreg_i  (reg_i[0])
#define dreg_i  (reg_i[1])
#define command (frame->code[line_i].cmd)
#define first   (frame->code[line_i].first)
#define second  (frame->code[line_i].second)
#define third   (frame->code[line_i].third)

    if(!CRASHDEBUG(1)) {
        fprintf(fp, ".");
        fflush(fp);
    }

    regs->was_touched = 0ULL;
    for(line_i = 0; line_i < frame->len; ) {
        if (CRASHDEBUG(1)) fprintf(fp, "\n");

        uint64_t addr   = frame->code[line_i].rip;
        enum e_reliability reliable_s_memory_operand = RELIABLE_NO,
                           reliable_d_memory_operand = RELIABLE_NO;
        int unreliable_flags = 0;

        regs->rip = frame->code[line_i + 1].rip;
        set_reliable(regs, RIP, RELIABLE_ABS);

        frame->code[line_i].hit++;

        // Loop occurs somewhere
        if(10 < frame->code[line_i].hit)
            return (uint8_t)-1;

        if(2 < frame->code[line_i].hit) {
            // If we got stuck, then clean all registers
            // and flags and start parsing with the
            // nearest to `call` address
            while(frame->code[line_i].rip != frame->nearest) {
                if(frame->code[line_i].rip < frame->nearest)
                    line_i++;
                else if(frame->code[line_i].rip > frame->nearest)
                    line_i--;
                if(line_i < 0 || line_i > frame->len)
                    return (uint8_t)-1;
            }

            regs->params_mask       = 0ULL;
            regs->was_touched       = (unsigned long long) -1LL;

            memset(regs->reliable, 0x0, sizeof(enum e_reliability) * RCOUNT);
            memset(regs->params_regs, 0xff, sizeof(uint8_t) * RCOUNT);

            set_reliable(regs, RBP, RELIABLE_ABS);
            set_reliable(regs, RSP, RELIABLE_ABS);

            regs->zf = -1;
            regs->cf = -1;
            regs->sf = -1;
            continue;
        }

        // Last check used to prevent the following:
        //     0xffffffff810552e0 <+60>:	je     0xffffffff8105532c <do_group_exit+136>
        //     ........
        //     0xffffffff81055327 <+131>:	callq  0xffffffff810548c6 <do_exit>
        //     0xffffffff8105532c <+136>:	lea    0x370(%r14),%rax
        // We encounter return RIP 0xffffffff8105532c 
        // but through JMP, not CALL
        if(frame->rip && addr == frame->rip && line_i > 1 && frame->code[line_i - 1].hit)
            break;

        if('\0' == *command) {
            line_i++;
            continue;
        }

//        instr_i = find_instr(command, &width);

        instr_i = frame->code[line_i].instr;
        cond    = frame->code[line_i].cond;
        cond_negate = frame->code[line_i].cond_negate;
        width   = frame->code[line_i].width;

        if(0 == frame->rip && instr_i == RET)
            break;
        if (CRASHDEBUG(1)) fprintf(fp, "++++ <%s at %s", frame->symbol, frame->code[line_i].raw);

        // op   src,dst
        // arg  - source
        // arg2 - destination
        is_s_memory_operand = parse_argument(ctx, regs, first, reg_i + 0, &arg, &reliable_s_memory_operand);
        if(instr_i != PUSHF && instr_i != PUSH && instr_i != POPF && instr_i != POP)
            if(RELIABLE_NO == reliable_s_memory_operand) {
                if(INVALID != (dreg_i = find_register(second)))
                    regs->was_touched |= (1 << (dreg_i / 5));
                line_i++;
                continue;
            }

        is_d_memory_operand = parse_argument(ctx, regs, second, reg_i + 1, &arg2, &reliable_d_memory_operand);
        if(instr_i != PUSHF && instr_i != PUSH && instr_i != POPF && instr_i != POP)
            if(RELIABLE_NO == reliable_d_memory_operand) {
                line_i++;
                continue;
            }
        reg_i[2] = INVALID;

        switch(instr_i) {
            case NOP:
                break;
            case DEC:
            case INC:
                if(INVALID != sreg_i) {
                    if(sreg_i == GS_REG && 0 == ctx->irq_count_offset) {
                        // We didn't find irq_count symbol, so we don't
                        // know exact value of per-cpu IRQ counter
                        regs->zf = -1;
                        break;
                    }
                    if(sreg_i == GS_REG && arg == ctx->irq_count_offset) {
                        // While we calculating frame size,
                        // we're going inside out the stack.
                        // So we're going to decrement every
                        // per_cpu__irq_count to determine
                        // whether we should switch stack
                        if(calculating_frame_size && instr_i == INC) {
                            if(0 == ctx->irq_count)
                                regs->zf = 1;
                            else
                                regs->zf = 0;
                            ctx->irq_count -= 1;
                            break;
                        }

                        ctx->irq_count += (instr_i == INC ? 1 : -1);
                        arg = ctx->irq_count;
                        if (CRASHDEBUG(1)) fprintf(fp, "\t\tPERCPU IRQ: %lu\t", arg);
                    } else {
                        add_reg(regs, sreg_i, (instr_i == INC ? 1 : -1));
                    }
                    if(0 == arg)
                        regs->zf = 1;
                    else
                        regs->zf = 0;
                }
                break;
            case LEA:
            case MOV:
            case MOVABS:
            case MOVSBL:
            case MOVSLQ:
            case MOVZBL:
            case MOVZWL:
            case CMOVcc:
/*            case CMOVE:
            case CMOVNE:
            case CMOVNS:*/
                // Look at the end of `case MOV`.
                // If dest register is callee-save,
                // then we'll clean 
                // created 'callee-save => parameter' mapping
                if(dreg_i < RCOUNT)
                    clean_mapping(regs, dreg_i);
                if(0 == ctx->should_get_stack_value)
                    break;

                if(instr_i == CMOVcc && 0 == check_condition(regs, cond, cond_negate))
                    break;
/*                if(instr_i == CMOVE && 0 == regs->zf)
                    break;
                if(instr_i == CMOVNE && 1 == regs->zf)
                    break;
                if(instr_i == CMOVNS && 1 == regs->sf)
                    break;
*/
                if(sreg_i == GS_REG) {
                    if(INVALID != dreg_i && (update_sp || !is_stack_register(dreg_i) ))
                        set_reg(regs, dreg_i, get_stack_value(ctx, arg, width));
                    print_value(regs, dreg_i);
                    set_reliable(regs, dreg_i, RELIABLE_ABS);
                    break;
                }

                if(dreg_i == GS_REG) {
                    if(INVALID == sreg_i)
                        break;
                    if(INVALID != sreg_i && (update_sp || !is_stack_register(sreg_i)))
                        set_reg(regs, sreg_i, get_stack_value(ctx, arg2, width));
                    print_value(regs, sreg_i);
                    set_reliable(regs, sreg_i, RELIABLE_ABS);
                    break;
                }

                // If instruction is like
                // 'lea    %rax,(%rdx,%rcx,4)'
                // 'mov    %rdi,0x78(%rsp)'
                if(is_d_memory_operand) {
                    if(!arg2)
                        break;
                    if(instr_i == MOV)
                        arg2 = get_stack_value(ctx, arg2, width);
                    if(sreg_i == INVALID)    // Can't do anything useful here, just skip
                        break;
                    set_reg(regs, sreg_i, arg2);
                    print_value(regs, sreg_i);

                    if(error_occured_while_reading)
                        clean_reliable(regs, dreg_i);
                    else
                        set_reliable(regs, sreg_i, reliable_d_memory_operand);

                    if(instr_i == MOV) {
                        // Meanwhle let's fill registers from
                        // previous frames
                        if(0 == may_call && 0 != ctx->parent) {
                            set_reg(&(ctx->parent->frames + ctx->parent->to_be_processed)->regs, sreg_i, get_reg(regs, sreg_i));
                            set_reliable(&(ctx->parent->frames + ctx->parent->to_be_processed)->regs, sreg_i, reliable_d_memory_operand);
                            fill_mapped_register(ctx->parent, sreg_i);
                        } else
                            fill_mapped_register(ctx, sreg_i);
                    }
                    break;
                }

                // If instruction is like
                // 'mov    0x42(%rdx,%rax,1),%r13d'
                if(is_s_memory_operand) {
                    if(!arg)
                        break;

                    if(instr_i == MOVZBL || instr_i == MOVSBL)
                        width = 8;
                    if(instr_i == MOVZWL)
                        width = 16;
                    if(instr_i == MOVSLQ)
                        width = 32;
                    if(instr_i != LEA)
                        arg = get_stack_value(ctx, arg, width);
                    if(instr_i == MOVSBL && (arg > 0x7f))
                        arg = 0xffffffffffffff00 | arg;
                    if(instr_i == MOVSLQ && (arg > 0x7fffffff))
                        arg = 0xffffffff00000000 | arg;

                    set_reg(regs, dreg_i, arg);
                    print_value(regs, dreg_i);

                    if(error_occured_while_reading)
                        clean_reliable(regs, dreg_i);
                    else
                        set_reliable(regs, dreg_i, reliable_s_memory_operand);

                    break;
                }

                if(INVALID != dreg_i) {
                    // <`Basic architecture` manual>
                    // 3.4.1.1 General-Purpose Registers in 64-Bit Mode
                    if(32 == get_register_width(dreg_i)/* && 32 == get_register_width(sreg_i)*/)
                        set_reg(regs, REGISTER_64BIT(dreg_i), 0);
                    // </`Basic architecture` manual>

                    // INVALID here means that src
                    // is immediate operand, so it's
                    // reliable
                    if(INVALID == sreg_i)
                        set_reliable(regs, dreg_i, RELIABLE_ABS);
                    else
                        set_reliable(regs, dreg_i, get_reliable_state(regs, sreg_i));

                    // <`Basic architecture` manual>
                    // 3.4.1.1 General-Purpose Registers in 64-Bit Mode
                    if(32 == get_register_width(dreg_i)/* && 32 == get_register_width(sreg_i)*/) {
                        if(INVALID == sreg_i)
                            set_reliable(regs, REGISTER_64BIT(dreg_i), RELIABLE_ABS);
                        else
                            set_reliable(regs, REGISTER_64BIT(dreg_i), get_reliable_state(regs, sreg_i));
                    }
                    // </`Basic architecture` manual>
                    set_reg(regs, dreg_i, arg);
                    print_value(regs, dreg_i);
                }


                // Let's follow registers passed as parameters
                // for next function, that is
                //      mov    %r13,%rcx
                //      mov    %rax,%rdx
                //      mov    %r12,%rsi
                //      mov    %rbx,%rdi
                //      callq  *%r8
                // 1. If mapping 'callee-save => parameter' found
                // go through array and clean previous (is exists)
                // mapping.
                // 2. Create new mapping
                if(
                        ((INVALID != dreg_i && is_param_register(dreg_i)) &&
                         (INVALID != sreg_i && is_callee_save_register(sreg_i))) ||
                        ((INVALID != sreg_i && is_param_register(sreg_i)) && 
                         (INVALID != dreg_i && is_callee_save_register(dreg_i))
                        )
                  )
                    set_mapping(regs, sreg_i, dreg_i);
                break;
            case PUSHF:
                // XXX TODO
                // At the moment we'll skip pushf
                // Later we should handle sequences like
                //
                //      pushfq
                //      pop rax
                //  OR
                //      push rdi
                //      popfq
                //
                // Probably we should keep pushed registers (flags) and
                // later check mask while pop'ing register

                add_reg(regs, RSP, -8);
                print_value(regs, RSP);
                break;
            case PUSH:
                add_reg(regs, RSP, -8);
                print_value(regs, RSP);
                if(0 == calculating_frame_size && INVALID != sreg_i) {
                    arg = get_stack_value(ctx, get_reg(regs, RSP), width);
                    set_reg(regs, sreg_i, arg);
                    print_value(regs, sreg_i);
                    set_reliable(regs, sreg_i, RELIABLE_ABS);
                    fill_mapped_register(ctx, sreg_i);
                }
                break;
            case POPF:
            case POP:
                add_reg(regs, RSP, 8);
                print_value(regs, RSP);
                break;
            case NOT:
                if(INVALID == sreg_i)
                    break;
                arg = ~arg;
                set_reg(regs, sreg_i, arg);
                regs->zf = arg ? 0 : 1;
                print_value(regs, sreg_i);
                break;
            case SUB:
            case SBB:
            case ADD:
            case XADD:
            case AND:
            case OR:
            case XOR:
                if(instr_i == SBB && regs->cf == -1) // CF unknown, can't process
                    break;

                if(INVALID == dreg_i || GS_REG == dreg_i) // Can't do anything useful here, just skip
                    break;

/*                if(calculating_frame_size && ADD == instr_i && RSP == dreg_i && arg < ((uint64_t)1 << 63))
                    break;
*/
                if(
                        // Same register as `src` and `dst`
                        ((dreg_i == sreg_i) && (instr_i == XOR || get_reliable_state(regs, sreg_i))) ||
                        // Reliable `dst` and (reliable `src` || not register as `src`)
                        (instr_i != XADD && (INVALID == sreg_i || get_reliable_state(regs, sreg_i)) && get_reliable_state(regs, dreg_i)) ||
                        (instr_i == XADD && (INVALID == dreg_i || get_reliable_state(regs, dreg_i)) && get_reliable_state(regs, sreg_i))
                  ) {
                    if(instr_i == SBB)
                        arg += regs->cf;

                    if (CRASHDEBUG(1)) fprintf(fp, "\t\tOperands: 0x%lx and 0x%lx", arg, arg2);

                    if(ADD == instr_i || XADD == instr_i)
                        cf = ((arg + arg2) < arg) && ((arg + arg2) < arg2);
                    else if(instr_i == SUB || instr_i == SBB)
                        cf = arg > arg2;
                    else
                        cf = 0;

                    switch(instr_i) {
                        case SUB:
                        case SBB:   res = arg2 - arg; break;
                        case XADD:
                        case ADD:   res = arg2 + arg; break;
                        case AND:   res = arg2 & arg; break;
                        case OR:    res = arg2 | arg; break;
                        case XOR:   res = arg2 ^ arg; break;
                        default: break;
                    }

                    update_flags(arg, sreg_i, arg2, dreg_i, res, cf, regs);

                    if(instr_i == OR || instr_i == XOR || instr_i == AND)
                        regs->of = 0;

                    // <`Basic architecture` manual>
                    // 3.4.1.1 General-Purpose Registers in 64-Bit Mode
                    if(32 == get_register_width(dreg_i))
                        set_reg(regs, REGISTER_64BIT(dreg_i), 0);
                    // </`Basic architecture` manual>

                    if(instr_i == XADD) {
                        if(INVALID != sreg_i)
                            set_reg(regs, sreg_i, arg2);
                        if(INVALID != dreg_i)
                            set_reg(regs, dreg_i, res);
                    } else
                        set_reg(regs, dreg_i, res);
                    if(sreg_i != INVALID)
                        clean_mapping(regs, sreg_i);
                    clean_mapping(regs, dreg_i);
                    set_reliable(regs, dreg_i,
                            reliable_s_memory_operand > reliable_d_memory_operand ?
                            reliable_d_memory_operand :
                            reliable_s_memory_operand
                            );
                    // <`Basic architecture` manual>
                    // 3.4.1.1 General-Purpose Registers in 64-Bit Mode
                    if(32 == get_register_width(dreg_i))
                        set_reliable(regs, REGISTER_64BIT(dreg_i),
                            reliable_s_memory_operand > reliable_d_memory_operand ?
                            reliable_d_memory_operand :
                            reliable_s_memory_operand
                            );
                    // </`Basic architecture` manual>
                    print_value(regs, dreg_i);
                }

                break;
            case CALL:
                if(first && *first) {
                    e = strstr(first, " ");
                    calling_symbol = closest_symbol(str2dec(first, e));
                    if(calling_symbol)
                        if (CRASHDEBUG(1)) fprintf(fp, "\t\tcalling '%s'", calling_symbol);
                    if(may_call && calling_symbol &&
                            (
                             0 == strcmp(calling_symbol, "error_entry") ||
                             0 == strcmp(calling_symbol, "irq_to_desc") ||
                             0 == strcmp(calling_symbol, "save_args") ||
                             0 == strcmp(calling_symbol, "save_paranoid") ||
                             0 == strncmp(calling_symbol, "__get_user_", 11)
                            )
                      ) {
                        if (CRASHDEBUG(1)) fprintf(fp, "\t\tprocessing call\n");

                        temp_rsp = get_reg(regs, RSP);

                        // Call recursively
                        add_reg(regs, RSP, -8);
                        struct stack_frame_t recursive_frame = {
                            .rip    = 0,
                            .rsp    = get_reg(regs, RSP)
                        };
                        strncpy(recursive_frame.symbol, calling_symbol, 64);
                        disassemble_frame(&recursive_frame, 1, 1);
                        memcpy(&recursive_frame.regs, regs, sizeof(struct parameter_registers));
                        recursive_frame.regs.was_touched = regs->was_touched;

                        struct stack_parser_context t_ctx = {
                            .frames = &recursive_frame,
                            .frames_count = 1,
                            .to_be_processed = 0,
                            .should_get_stack_value = ctx->should_get_stack_value,
                            .tc = ctx->tc,
                            .irq_count_offset = ctx->irq_count_offset,
                            .irq_count = ctx->irq_count,
                            .gs_base = ctx->gs_base,
                            .parent = ctx,
                        };
                        parse_frame(&t_ctx, 0, update_sp, calculating_frame_size, callback);

                        memcpy(regs, &recursive_frame.regs, sizeof(struct parameter_registers));

                        regs->was_touched = recursive_frame.regs.was_touched;
                        ctx->irq_count = t_ctx.irq_count;
//                        add_reg(regs, RSP, 8);
                        set_reg(regs, RSP, temp_rsp);
//                        print_value(regs, RSP);
                    } else if(function_returns_value(closest_symbol(str2dec(first, e)))) {
                        set_reg(regs, RAX, 0xdeadbeaf);
                        clean_reliable(regs, RAX);
                    }
                }
                break;
/*            case JA:
            case JB:
            case JE:
            case JZ:
            case JL:
            case JS:
            case JAE:
            case JBE:
            case JNE:
            case JNZ:
            case JNS:*/
            case JMP:
            case Jcc:
                if (CRASHDEBUG(1)) fprintf(fp, "\n");
                // Just Smile And Wave Boys, Smile And Wave 

                // next_line.will_ret marked as destination, DO NOT jump
                if(frame->code[line_i].will_ret == LINE_STATUS_DESTINATION) {
                    line_i++;
                    continue;
                }

                // Find line
                jump_to = str2dec(first, NULL);
                jmp_symbol = closest_symbol(jump_to);
                old_line_i = line_i;

                while(frame->code[line_i].rip != jump_to) {
                    if(frame->code[line_i].rip < jump_to)
                        line_i++;
                    else if(frame->code[line_i].rip > jump_to)
                        line_i--;
                    if(line_i < 0 || (line_i >= frame->len)) {
                        // For some kernels exception/interrupt entry points use
                        // `jmp error_entry` but don't contain `error_entry`
                        // body. See `disassemble_frame` for details.
                        for(line_i = frame->len - 1; line_i >= 0; line_i--)
                            if(frame->code[line_i].rip == jump_to)
                                break;
                        if(frame->code[line_i].rip == jump_to)
                            break;
                        return (uint8_t)-1;
                    }
                }
/*                
                while(frame->code[line_i].rip != jump_to) {
                    if(
                            (frame->code[line_i].rip < jump_to) ||
                            // 'error_entry' symbol will be further
                            (jmp_symbol && 0 == strcmp(jmp_symbol, "error_entry"))
                      )
                        line_i++;
                    else if(frame->code[line_i].rip > jump_to)
                        line_i--;
                    if(line_i < 0 || (line_i >= frame->len))
                        return (uint8_t)-1;
                }
*/
                // jump_line.will_ret marked as destination, DO jump
                if(frame->code[line_i].will_ret == LINE_STATUS_DESTINATION)
                    continue;
                // Next line after jump instruction marked as destination, DO NOT jump
                if(((old_line_i + 1) < frame->len) && frame->code[old_line_i + 1].will_ret == LINE_STATUS_DESTINATION) {
                    // Don't jump
                    line_i = old_line_i + 1;
                    continue;
                }

                // Line right after Jxx marked LINE_STATUS_WILL_RET
                // and jump_line.will_ret != LINE_STATUS_WILL_RET
                // let's jump ...
                if((LINE_STATUS_WILL_RET != frame->code[line_i].will_ret) && ((old_line_i + 1) < frame->len) && frame->code[old_line_i + 1].will_ret == LINE_STATUS_WILL_RET)
                    // Do jump
                    continue;
                // and vice versa
                else
                if((LINE_STATUS_WILL_RET == frame->code[line_i].will_ret) && ((old_line_i + 1) < frame->len) && (frame->code[old_line_i + 1].will_ret != LINE_STATUS_WILL_RET)) {
                    // Don't jump
                    line_i = old_line_i + 1;
                    continue;
                }

                if(frame->code[line_i].will_ret == LINE_STATUS_WILL_RET) {
                    // Don't jump
                    line_i = old_line_i + 1;
                    continue;
                }

                // Don't jump, while calculating frame size
                if(calculating_frame_size) {
                    line_i = old_line_i + 1;
                    continue;
                }

                // Check flags
                if(instr_i == JMP ||
                        check_condition(regs, cond, cond_negate) ||
//                      (may_call == 1 && instr_i != JMP && frame->code[line_i].will_ret == LINE_STATUS_WILL_RET) ||
//                        ((instr_i == JE || instr_i == JZ) && regs->zf == 1) ||
//                        ((instr_i == JNE || instr_i == JNZ) && regs->zf == 0) ||
//                        (instr_i == JA && regs->cf == 1 && regs->zf == 1) ||
//                        (instr_i == JAE && regs->cf == 1) ||
//                        (instr_i == JNS && regs->sf == 0) ||
//                        ((instr_i == JB || instr_i == JC) && regs->cf == 1) ||
//                        ((instr_i == JL) && regs->of != regs->sf) ||
//                        ((instr_i == JL) && regs->sf == 1) ||
//                        ((instr_i == JBE || instr_i == JNA) && (regs->cf == 1 || regs->zf == 1)) ||
//                        (instr_i == JMP) ||
                        (((line_i + 1) < frame->len) && frame->code[line_i + 1].will_ret == LINE_STATUS_WILL_RET)
                  )
                    continue;
                else
                    line_i = old_line_i + 1;
                continue;
            case BT:
            case BTS:
            case CMP:
            case TEST:
                unreliable_flags = 1;
                if(INVALID != sreg_i && RELIABLE_NO == get_reliable_state(regs, sreg_i))
                    break;   // Unreliable;
                if(INVALID != dreg_i && RELIABLE_NO == get_reliable_state(regs, dreg_i))
                    break;   // Unreliable;
                if(is_s_memory_operand)
                    arg = get_stack_value(ctx, arg, width);
                if(is_d_memory_operand)
                    arg2 = get_stack_value(ctx, arg2, width);

                if (CRASHDEBUG(1)) fprintf(fp, "\t\t testing 0x%lx <=> 0x%lx", arg, arg2);
                if(instr_i == CMP)
                    update_flags(arg, sreg_i, arg2, dreg_i, arg2 - arg, arg > arg2, regs);
                else if(instr_i == TEST) {
                    update_flags(arg, sreg_i, arg2, dreg_i, arg & arg2, 0, regs);
                    regs->of = 0;
                } else if(instr_i == BT || instr_i == BTS || instr_i == BTR) {
                    regs->cf = (arg2 & (arg % width)) ? 1 : 0;
                    if (CRASHDEBUG(1)) fprintf(fp, "\t\tCarry set to %d", regs->cf);
                }

                unreliable_flags = 0;
                break;
            case SHL:
            case SHR:
            case SAR:
                // SHL and SHR - Logical shift
                // SAR and SAL - Arithmetic shift
                if((INVALID != dreg_i && (RELIABLE_NO == get_reliable_state(regs, dreg_i))) ||
                   (INVALID != sreg_i && (RELIABLE_NO == get_reliable_state(regs, sreg_i))))
                    break; // Unreliable

                if(*second) {
                    if(INVALID == dreg_i)
                        break;
                    arg2 = get_reg(regs, dreg_i);
                } else {
                    arg2 = arg;
                    dreg_i = sreg_i;
                    arg = 1;
                }
                while(arg) {
                    if(instr_i == SHL) {
                        regs->cf = !((arg2 << 1) == ((arg2 << 1) & registers_mask[dreg_i % 5]));
                        arg2 = (arg2 << 1) & registers_mask[dreg_i % 5];
                    } else {
                        regs->cf = arg2 & 0x1ULL;
                        if(instr_i == SAR) {
                            if(registers_msb[dreg_i % 5] & arg2)
                                arg2 = (arg2 >> 1) | registers_msb[dreg_i % 5];
                            else
                                arg2 = (arg2 >> 1);
                        } else
                            arg2 = arg2 >> 1;
                    }
                    arg--;
                }
                if(0 == arg2)
                    regs->zf = 1;
                else
                    regs->zf = 0;
                set_reg(regs, dreg_i, arg2);
                print_value(regs, dreg_i);
                break;
            case IMUL:
                if(INVALID != sreg_i && RELIABLE_NO == get_reliable_state(regs, sreg_i))
                    break;
                if(INVALID != dreg_i && RELIABLE_NO == get_reliable_state(regs, dreg_i))
                    break;

                if (CRASHDEBUG(1)) fprintf(fp, "\t\tOperands: 0x%lx and 0x%lx", arg, arg2);
                res = (uint64_t)arg * (uint64_t)arg2;

                // Three-operand form
                if(*third) {
                    reg_i[2] = find_register(third);
                    set_reg(regs, reg_i[2], res);
                    print_value(regs, reg_i[2]);
                    set_reliable(regs, reg_i[2], get_reliable_state(regs, sreg_i) > get_reliable_state(regs, dreg_i) ?
                                                 get_reliable_state(regs, dreg_i) : get_reliable_state(regs, sreg_i));
                } else if(INVALID != dreg_i) {
                    set_reg(regs, dreg_i, res);
                    print_value(regs, dreg_i);
                }

                update_flags(
                        arg, sreg_i, arg2, dreg_i, res,
                        ((arg < res) || (arg2 < res)), regs
                        );
                break;
            case LEAVE:
                // Don't leave me now
                if(calculating_frame_size)
                    break;
                set_reg(regs, RSP, get_reg(regs, RBP));
                set_reg(regs, RBP, get_stack_value(ctx, get_reg(regs, RSP), 64));
                add_reg(regs, RSP, 0x8);
                print_value(regs, RSP);
                print_value(regs, RBP);
                break;
            default:
                if (CRASHDEBUG(1)) fprintf(fp, "\t\tUNKN");
                unreliable_flags = 1;
                break;
        }
        if(!is_compare_instruction(instr_i)) {
            if(*third && INVALID != reg_i[2])
                regs->was_touched |= (1 << (reg_i[2] / 5));
            else if(0 == *third && INVALID != dreg_i)
                regs->was_touched |= (1 << (dreg_i / 5));
        }
        if(unreliable_flags) {
            regs->zf = -1;
            regs->cf = -1;
            regs->sf = -1;
            regs->of = -1;
            if(dreg_i != INVALID)
                clean_reliable(regs, dreg_i);
        }
        if(NULL != callback)
            if(1 == callback(instr_i, first, second)) {
                if (CRASHDEBUG(1)) fprintf(fp, "\ncallback returns successfully: %s %s, %s\n", command, first, second);
                return 1;
            }
        line_i++;
        error_occured_while_reading = 0;
    }

    for(line_i = 0; line_i < frame->len; line_i++) {
        enum e_registers r;
        enum e_instructions instr_i;
        if(0 == *command)
            continue;
        instr_i = find_instr(command, NULL);

        if(instr_i == PUSHF || instr_i == PUSH || instr_i == POPF || instr_i == POP)
            continue;
        if(frame->code[line_i].will_ret == LINE_STATUS_WILL_RET)
            continue;
        if(third && *third)
            r = find_register(third);
        else if(second && *second)
            r = find_register(second);
        else if(first && *first)
            r = find_register(first);
        else
            continue; /* Instructions without arguments */
        if(r == INVALID)
            continue;
        if(!is_compare_instruction(instr_i)) {
            regs->was_touched |= (1 << (r / 5));
            if(CRASHDEBUG(2)) fprintf(fp, "\nSet `was_touched` for register '%s' (symbol '%s') - 0x%lx", s_registers[r], frame->symbol, regs->was_touched);
        }
    }

#undef sreg_i
#undef dreg_i
#undef command
#undef first
#undef second
#undef third
    return 0;
}

void parse_stack(struct bt_info *bt) {
        unsigned int i;
        struct parameter_registers *regs, *prev_regs = NULL;
        char buf[BUFSIZE], o_buf[BUFSIZE];
        char *t;
        struct syment *sp;

        struct stack_parser_context ctx;
        struct stack_frame_t *frame;

//        per_cpu_variables = NULL;

        ctx.parent = NULL;
        ctx.frames_count = 0;
        ctx.to_be_processed = 0;
        ctx.frames = calloc(64, sizeof(struct stack_frame_t));
        ctx.tc = task_to_context(bt->task);
        if(symbol_search("_cpu_pda") &&
           MEMBER_EXISTS("x8664_pda", "kernelstack")) 
        {
            sprintf(buf, "p/x _cpu_pda[%d]", ctx.tc->processor);

            if(0 == get_gdb_line(buf, o_buf))
                return;

            if(0 == (t = strstr(o_buf, "= ")))
                return;
            else
                ctx.gs_base = str2dec(t + 2, NULL); // GS Base
        } else if(THIS_KERNEL_VERSION >= LINUX(2,6,32))
            ctx.gs_base = kt->__per_cpu_offset[ctx.tc->processor];

        sp = per_cpu_symbol_search("irq_count");

        if(sp) {
            ctx.irq_count_offset = kt->__per_cpu_offset[ctx.tc->processor] + sp->value;
            ctx.should_get_stack_value = 1;
            ctx.irq_count = get_stack_value(&ctx, ctx.irq_count_offset, 32);
            ctx.should_get_stack_value = 0;
        } else if (symbol_value("_cpu_pda") && MEMBER_EXISTS("x8664_pda", "irqcount")) {
            sprintf(buf, "p/x _cpu_pda[%d]->irqcount", ctx.tc->processor);

            if(0 == get_gdb_line(buf, o_buf))
                return;

            if(0 == (t = strstr(o_buf, "= ")))
                return;
            ctx.irq_count = str2dec(t + 2, NULL);

            sprintf(buf, "p/x &_cpu_pda[%d].irqcount", ctx.tc->processor);

            if(0 == get_gdb_line(buf, o_buf))
                return;

            if(0 == (t = strstr(o_buf, "= ")))
                return;
            ctx.irq_count_offset = str2dec(t + 2, NULL);
        } else {
            ctx.irq_count_offset = 0;
            ctx.irq_count = -1;
        }


        ctx.should_get_stack_value = 0;
        if(fill_frames(bt, &ctx) || (0 == ctx.frames_count)) {
            if (CRASHDEBUG(1))
                fprintf(fp, "\nError while parsing stack\n");
            return;
        }

        ctx.irq_count = -1;
        ctx.should_get_stack_value = 1;

        for(i = ctx.frames_count - 1; i > 0; i--) {
                ctx.to_be_processed = i;
                frame = ctx.frames + i;
                regs = &frame->regs;
                if(prev_regs)
                    memcpy(regs, prev_regs, sizeof(struct parameter_registers));
/* TODO Check, whether it's necessary             
                // Clean mapping
                if(frame->is_exception) {
                regs->params_mask = 0;
                memset(cframe->regs.params_regs, 0xff, RCOUNT);
                }
*/
                parse_frame(&ctx, 1, 1, 0, NULL);
                prev_regs = regs;
        }
        fprintf(fp, "\n\nBacktrace:\n");
        
        for(i = 0; i < ctx.frames_count - 1; i++)
            print_proto(ctx.frames + i, i, &(ctx.frames + i + 1)->regs);

        for(i = 0; i < ctx.frames_count; i++)
            if((ctx.frames + i)->allocated)
                free((ctx.frames + i)->code);
        free(ctx.frames);
}


/* Extension part */
void fp_init(void);
void fp_fini(void);

void cmd_fp(void);
char *help_fp[];

static struct command_table_entry command_table[] = {
        { "fp", cmd_fp, help_fp, 0},            /* One or more commands, */
        { NULL },                               /* terminated by NULL, */
};

char *help_fp[] = {
        "fp",
        "Obtaining functions' parameters from stack frames.",
        " ",
        "  This command simply disassembles every function within stack",
        "  and just emulates execution of commands.",
        NULL
};

void __attribute__((constructor)) fp_init(void)
{
        register_extension(command_table);
}
 
void __attribute__((destructor)) fp_fini(void) { }

void
cmd_fp(void)
{
        uint64_t rip, rsp;
        struct bt_info bt;
        BZERO(&bt, sizeof(struct bt_info));

        bt.tc = CURRENT_CONTEXT();
        bt.task = CURRENT_TASK();
        bt.stackbase = GET_STACKBASE(bt.tc->task);
        bt.stacktop = GET_STACKTOP(bt.tc->task);
	fill_stackbuf(&bt);

        if(DISKDUMP_DUMPFILE())
            get_netdump_regs_x86_64(&bt, &rip, &rsp);
        else if(KDUMP_DUMPFILE())
            get_kdump_regs(&bt, &rip, &rsp);
        else {
            fprintf(fp, "Doesn't have support yet\n");
            return;
        }

        bt.stkptr = rsp;
        parse_stack(&bt);
}



