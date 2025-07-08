#ifndef VFM_H
#define VFM_H

/* VelocityFilterMachine Stub Header
 * This is a placeholder for the actual VFM single-header library
 * Replace this with the real VFM from:
 * https://github.com/MonkeyIsNull/VelocityFilterMachine
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* VFM opcodes (simplified) */
typedef enum {
    VFM_OP_LOAD,
    VFM_OP_STORE,
    VFM_OP_ADD,
    VFM_OP_SUB,
    VFM_OP_AND,
    VFM_OP_OR,
    VFM_OP_XOR,
    VFM_OP_JMP,
    VFM_OP_JEQ,
    VFM_OP_JGT,
    VFM_OP_RET
} vfm_opcode;

/* VFM context */
typedef struct vfm_context {
    const uint8_t* bytecode;
    size_t bytecode_len;
    uint32_t pc;              /* Program counter */
    uint32_t accumulator;     /* Accumulator register */
    uint32_t registers[16];   /* General purpose registers */
    uint32_t stack[64];       /* Stack */
    uint32_t sp;              /* Stack pointer */
} vfm_context;

/* VFM functions (stub) */
static inline vfm_context* vfm_create(const uint8_t* bytecode, size_t len) {
    vfm_context* ctx = calloc(1, sizeof(vfm_context));
    if (ctx) {
        ctx->bytecode = bytecode;
        ctx->bytecode_len = len;
    }
    return ctx;
}

static inline void vfm_destroy(vfm_context* ctx) {
    free(ctx);
}

static inline int vfm_execute(vfm_context* ctx, const uint8_t* packet, size_t len) {
    /* Stub implementation - always accept */
    (void)ctx;
    (void)packet;
    (void)len;
    return 1; /* Accept */
}

static inline const char* vfm_version(void) {
    return "VFM Stub 0.0.1";
}

#ifdef __cplusplus
}
#endif

#endif /* VFM_H */
