//===---------- NVTMain.c - The Noninterference Verification Tool ---------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/**
 * \defgroup NVT_CLIENT NVT Client Module
 * \ingroup NVT
 * \brief Client module for DynamoRIO.
 *
 * For each dynamic basic block that is loaded into the DynamoRIO cache during
 * execution, the NVT inserts inline assembly to record the program counter
 * (pc) address at the beginning of the basic block. The NVT then traverses the
 * basic block, searching for instructions which access memory.  For each such
 * instruction and each such memory access, inline assembly is inserted to
 * record the address being accessed, the type of access (read/write), and the
 * size of the operand being read/written.
 *
 * During program execution, this information is all recorded into the memory
 * trace buffer. At the end of each basic block, a call is inserted to hash the
 * basic block's trace into the trace digest, and then reset the trace buffer.
 * Storage outputs (i.e. through a file descriptor) are also recorded in a
 * separate outputs trace.
 *
 * For each test, the inputs are fuzzed N times. The first fuzz iteration for
 * each test establishes benchmark memory and output trace digests, against
 * which all subsequent fuzz iterations are compared. For a given test, if the
 * traces of any fuzz iteration differs from the benchmark traces, then the NVT
 * terminates and reports the discrepancy.
 * @{
 */
#include "MD5.h"
#include "drfuzz.h"
#include "drmemory_framework.h"
#include "drmgr.h"
#include "drreg.h"
#include "drsyms.h"
#include "drutil.h"
#include "drwrap.h"

#ifndef _MSC_VER
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef UNIX
#ifdef MACOS
#include <sys/syscall.h>
#else
#include <syscall.h>
#endif
#endif

#include "NVT/NVTCommon.h"
#include "NVTOptions.h"

// Event Handlers
static dr_emit_flags_t event_bb_app2app(void *drcontext, void *tag,
                                        instrlist_t *bb, bool for_trace,
                                        bool translating);
static bool event_syscall(void *drcontext, int sysnum);
static dr_emit_flags_t event_instruction(void *drcontext, void *tag,
                                         instrlist_t *bb, instr_t *where,
                                         bool for_trace, bool translating,
                                         void *user_data);
static void event_module_load(void *drcontext, const module_data_t *info,
                              bool loaded);
static void event_exit(void);

///////////////////////////////////////////////////////////////////////////////
// Log/Error Helpers
///////////////////////////////////////////////////////////////////////////////

#define NVT_PFX "NVT: "

#ifndef NDEBUG
#define LOG(drcontext, mask, loglevel, ...)                                    \
  dr_log(drcontext, mask, loglevel, NVT_PFX __VA_ARGS__);
#define ASSERT_MSG(x, msg) DR_ASSERT_MSG(x, msg)
#define ASSERT(x) DR_ASSERT(x)
#else
#define LOG(drcontext, mask, loglevvel, msg, ...)
#define ASSERT_MSG(x, msg)
#define ASSERT(x)
#endif

#define NVT_LOG_TOP 0x01000000
#define NVT_LOG_SYSCALL 0x02000000
#define NVT_LOG_INSTRUMENT 0x04000000
#define NVT_LOG_FUZZER 0x08000000
#define NVT_LOG_APPLICATION_HEAP 0x10000000

#undef EXPECT
#define EXPECT(cond, ...)                                                      \
  ((void)((!(cond))                                                            \
              ? (dr_fprintf(STDERR, NVT_PFX "EXPECT FAILURE: %s:%d: %s (",     \
                            __FILE__, __LINE__, #cond),                        \
                 dr_fprintf(STDERR, __VA_ARGS__), dr_fprintf(STDERR, ")\n"),   \
                 dr_abort(), 0)                                                \
              : 0))

#define DR_FUZZ_LABEL "Dr. Fuzz"

#ifdef WINDOWS
#define MALLOC_NAME "HeapAlloc"
#define FREE_NAME "HeapFree"
#else
#define MALLOC_NAME "malloc"
#define FREE_NAME "free"
#endif

#define KB (1 << 10)
#define MB (1 << 20)

/// \brief Translate a Dr.\ Memory error code into a string and emit to \c
/// stderr.
///
/// \param label prefix to use when emitting an error
/// \param error Dr. Memory error code to process
/// \param warning_as_error treat a Dr. Memory warning as an error
/// \return \c true when \c error is an actual error, or a warning being treated
/// as an error
static bool process_drmf_status(const char *label, drmf_status_t error,
                                bool warning_as_error) {
#define EMIT_ERROR(msg) dr_fprintf(STDERR, "%s -- %s\n", label, msg)
  bool ret;
  switch (error) {
  case DRMF_SUCCESS:
    ret = false;
    break;
  case DRMF_ERROR:
    EMIT_ERROR("Operation failed");
    ret = true;
    break;
  case DRMF_ERROR_INCOMPATIBLE_VERSION:
    EMIT_ERROR("Operation failed: incompatible version");
    ret = true;
    break;
  case DRMF_ERROR_INVALID_PARAMETER:
    EMIT_ERROR("Operation failed: invalid parameter");
    ret = true;
    break;
  case DRMF_ERROR_INVALID_SIZE:
    EMIT_ERROR("Operation failed: invalid size");
    ret = true;
    break;
  case DRMF_ERROR_NOT_IMPLEMENTED:
    EMIT_ERROR("Operation failed: not yet implemented");
    ret = true;
    break;
  case DRMF_ERROR_FEATURE_NOT_AVAILABLE:
    EMIT_ERROR("Operation failed: not available");
    ret = true;
    break;
  case DRMF_ERROR_NOMEM:
    EMIT_ERROR("Operation failed: not enough memory");
    ret = true;
    break;
  case DRMF_ERROR_DETAILS_UNKNOWN:
    EMIT_ERROR("Operation failed: answer not yet known");
    ret = true;
    break;
  case DRMF_ERROR_NOT_FOUND:
    EMIT_ERROR("Operation failed: query not found");
    ret = true;
    break;
  case DRMF_ERROR_INVALID_CALL:
    EMIT_ERROR("Operation failed: pre-req for call not met");
    ret = true;
    break;
  case DRMF_ERROR_NOT_ENOUGH_REGS:
    EMIT_ERROR("Operation failed: not enough registers for use");
    ret = true;
    break;
  case DRMF_ERROR_ACCESS_DENIED:
    EMIT_ERROR("Operation failed: access denied");
    ret = true;
    break;
  case DRMF_WARNING_ALREADY_INITIALIZED:
    EMIT_ERROR("Operation aborted: already initialized");
    ret = warning_as_error;
    break;
  case DRMF_ERROR_NOT_INITIALIZED:
    EMIT_ERROR("Operation failed: not initialized");
    ret = true;
    break;
  case DRMF_ERROR_INVALID_ADDRESS:
    EMIT_ERROR("Operation failed: invalid address");
    ret = true;
    break;
  case DRMF_WARNING_UNSUPPORTED_KERNEL:
    EMIT_ERROR("Continuing not advised: unsupported kernel");
    ret = warning_as_error;
    break;
  }

  return ret;
#undef EMIT_ERROR
}

///////////////////////////////////////////////////////////////////////////////
// NVT Context Types
///////////////////////////////////////////////////////////////////////////////

#define TRACE_BUFFER_REFS 4096
#define HEAP_INSTR_REFS 4096
#define TRACE_BUFFER_SIZE (sizeof(mem_ref_t) * TRACE_BUFFER_REFS)

#define MINSERT instrlist_meta_preinsert

/// \brief A tag representing the type of memory access.
enum {
  REF_TYPE_BB = 0,    ///< dynamic basic block
  REF_TYPE_READ = 1,  ///< memory read
  REF_TYPE_WRITE = 2, ///< memory write
};

/// \brief Characterizes a single memory access.
typedef struct {
  int Type; ///< r(0), w(1), or bb(2)
  union {
    int Size;      ///< mem ref size or instr length
    int NumBlocks; ///< Number of cache blocks touched
  };
  app_pc Addr; ///< mem ref addr or instr pc
} mem_ref_t;

typedef struct {
  uint8_t *input1;
  uint8_t *input2;
} test_result_t;

/// global context
typedef struct {
  nvt_options_t opts;
  FILE *_log;
  int test_num;
  generic_func_t test_begin_addrs[NVT_MAX_NUM_TESTS];
  test_result_t test_results[NVT_MAX_NUM_TESTS];
  generic_func_t test_end_addr;
  generic_func_t fuzz_target_addr;
  byte *fuzz_arg; ///< points to the buffer holding fuzzed data
  drfuzz_mutator_t *mutator;
  instr_t *heap_instrs[HEAP_INSTR_REFS];
  int num_heap_instrs;
  void *application_heap;
} ctx_t;

/// per-test context
typedef struct {
  generic_func_t test_begin_addr;
  int fuzz_iter;
  byte memory_trace_hash[MD5_BLOCK_SIZE];
  byte output_trace_hash[MD5_BLOCK_SIZE];
} test_ctx_t;

/// per-fuzz iteration context
typedef struct {
  MD5_CTX memory_hash_ctx;              ///< hash digest of the memory trace
  MD5_CTX output_hash_ctx;              ///< hash digest of the output trace
  mem_ref_t tbuffer[TRACE_BUFFER_REFS]; ///< memory trace buffer
  mem_ref_t *current;                   ///< memory trace buffer pointer
  bool recording; ///< if true, record memory accesses into the memory trace
                  ///< buffer
  void *application_heap_ptr;
} iter_ctx_t;

#define TRACE_BUFFER_IS_EMPTY(ctx) (ctx.current == ctx.tbuffer)

///////////////////////////////////////////////////////////////////////////////
// NVT Context Definitions
///////////////////////////////////////////////////////////////////////////////

/// \hideinitializer
static ctx_t ctx = {._log = NULL,
                    .test_num = 0,
                    .test_begin_addrs = {0},
                    .test_results = {{0}},
                    .fuzz_target_addr = NULL,
                    .mutator = NULL,
                    .heap_instrs = {0},
                    .num_heap_instrs = 0};
static test_ctx_t test_ctx;
/// \hideinitializer
static iter_ctx_t iter_ctx = {.recording = false};

///////////////////////////////////////////////////////////////////////////////
// Inline Assembly Helpers
///////////////////////////////////////////////////////////////////////////////

/// \details Inserts instructions at \p where to load the current value of the
/// memory trace buffer pointer into \p buf_ptr.
static void insert_load_buf_ptr(void *drcontext, instrlist_t *ilist,
                                instr_t *where, reg_id_t buf_ptr,
                                reg_id_t scratch) {
  instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)&iter_ctx.current,
                                   opnd_create_reg(scratch), ilist, where, NULL,
                                   NULL);
  MINSERT(ilist, where,
          XINST_CREATE_load(drcontext, opnd_create_reg(buf_ptr),
                            OPND_CREATE_MEMPTR(scratch, 0)));
}

/// \details Inserts instructions at \p where to reset \p buf_ptr to point to
/// the beginning of the memory trace buffer.
static void insert_reset_buf_ptr(void *drcontext, instrlist_t *ilist,
                                 instr_t *where, reg_id_t buf_ptr) {
  MINSERT(ilist, where,
          XINST_CREATE_load_int(drcontext, opnd_create_reg(buf_ptr),
                                OPND_CREATE_INTPTR(iter_ctx.tbuffer)));
}

/// \details Inserts instructions at \p where to increment \p buf_ptr by the
/// value \p adjust.
static void insert_update_buf_ptr(void *drcontext, instrlist_t *ilist,
                                  instr_t *where, reg_id_t buf_ptr,
                                  reg_id_t scratch, int adjust) {
  MINSERT(ilist, where,
          XINST_CREATE_add(drcontext, opnd_create_reg(buf_ptr),
                           OPND_CREATE_INT16(adjust)));
  instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)&iter_ctx.current,
                                   opnd_create_reg(scratch), ilist, where, NULL,
                                   NULL);
  MINSERT(ilist, where,
          XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(scratch, 0),
                             opnd_create_reg(buf_ptr)));
}

/// \details Inserts instructions at \p where to save \p type into \p buf_ptr at
/// mem_ref_t::Type.
static void insert_save_type(void *drcontext, instrlist_t *ilist,
                             instr_t *where, reg_id_t buf_ptr, reg_id_t scratch,
                             int type) {
  scratch = reg_resize_to_opsz(scratch, OPSZ_4);
  MINSERT(ilist, where,
          XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch),
                                OPND_CREATE_INT32(type)));
  MINSERT(ilist, where,
          XINST_CREATE_store(
              drcontext, OPND_CREATE_MEM32(buf_ptr, offsetof(mem_ref_t, Type)),
              opnd_create_reg(scratch)));
}

/// \details Inserts instructions at \p where to save \p size into \p buf_ptr at
/// mem_ref_t::Size.
static void insert_save_size(void *drcontext, instrlist_t *ilist,
                             instr_t *where, reg_id_t buf_ptr, reg_id_t scratch,
                             int size) {
  scratch = reg_resize_to_opsz(scratch, OPSZ_4);
  MINSERT(ilist, where,
          XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch),
                                OPND_CREATE_INT32(size)));
  MINSERT(ilist, where,
          XINST_CREATE_store(
              drcontext, OPND_CREATE_MEM32(buf_ptr, offsetof(mem_ref_t, Size)),
              opnd_create_reg(scratch)));
}

/// \details Inserts instructions at \p where to save \p pc into \p buf_ptr at
/// mem_ref_t::Addr.
static void insert_save_pc(void *drcontext, instrlist_t *ilist, instr_t *where,
                           reg_id_t buf_ptr, reg_id_t scratch, app_pc pc) {
  instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)pc,
                                   opnd_create_reg(scratch), ilist, where, NULL,
                                   NULL);
  MINSERT(ilist, where,
          XINST_CREATE_store(
              drcontext, OPND_CREATE_MEMPTR(buf_ptr, offsetof(mem_ref_t, Addr)),
              opnd_create_reg(scratch)));
}

/// \details Inserts instructions at \p where to save \p reg_addr into \p
/// buf_ptr at mem_ref_t::Addr.
static void insert_save_addr(void *drcontext, instrlist_t *ilist,
                             instr_t *where, opnd_t ref, reg_id_t buf_ptr,
                             reg_id_t reg_addr, reg_id_t scratch) {
  /* we use reg_ptr as scratch to get addr */
  EXPECT(drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_addr,
                                    scratch),
         "");
  MINSERT(ilist, where,
          XINST_CREATE_store(
              drcontext, OPND_CREATE_MEMPTR(buf_ptr, offsetof(mem_ref_t, Addr)),
              opnd_create_reg(reg_addr)));
}

/// \details Inserts instructions at \p where to write \p value to \p target.
static void insert_update_bool(void *drcontext, bool *target, instrlist_t *bb,
                               instr_t *where, reg_id_t scratch, bool value) {
  MINSERT(bb, where,
          XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch),
                                OPND_CREATE_INTPTR(target)));
  MINSERT(bb, where,
          XINST_CREATE_store_1byte(drcontext, OPND_CREATE_MEM8(scratch, 0),
                                   OPND_CREATE_INT8(value)));
}

///////////////////////////////////////////////////////////////////////////////
// Clean Calls
///////////////////////////////////////////////////////////////////////////////

/// \brief Add the memory trace buffer to the memory trace digest.
///
/// If the NVT is recording an execution trace, hash the memory trace buffer
/// and add it to the memory trace digest.
static void process_buf(void) {
  if (iter_ctx.recording) {
    const intptr_t bits = ctx.opts.mask_bits;
    if (bits) {
      const intptr_t mask = ~((1 << bits) - 1);
      for (mem_ref_t *i = iter_ctx.tbuffer; i < iter_ctx.current; ++i) {
        if (ctx.opts.blocks_only) {
          i->NumBlocks =
              (int)(1 + ((((intptr_t)i->Addr & ~mask) + i->Size - 1) >> bits));
        }
        i->Addr = (app_pc)((intptr_t)i->Addr & mask);
      }
    }
    if (ctx._log) {
      // Pretty-print the memory trace buffer to the log.
      for (const mem_ref_t *i = iter_ctx.tbuffer; i < iter_ctx.current; ++i) {
        if (ctx.opts.blocks_only) {
          for (int k = 0; k < i->NumBlocks; ++k) {
            fprintf(ctx._log, "%p: %s\n", (void *)(i->Addr + (k * (1 << bits))),
                    i->Type == REF_TYPE_BB
                        ? "bb"
                        : (i->Type == REF_TYPE_READ ? "r" : "w"));
          }
        } else {
          fprintf(ctx._log, "%p: %2d, %s\n", (void *)i->Addr, i->Size,
                  i->Type == REF_TYPE_BB
                      ? "bb"
                      : (i->Type == REF_TYPE_READ ? "r" : "w"));
        }
      }
    }
    const uint8_t *begin = (const uint8_t *)iter_ctx.tbuffer;
    const uint8_t *end = (const uint8_t *)iter_ctx.current;
    md5_update(&iter_ctx.memory_hash_ctx, begin, end - begin);
  }
}

int mem_ref_t_cmp(const void *x, const void *y) {
  const mem_ref_t *_x = x, *_y = y;
  if (_x->Addr < _y->Addr) {
    return -1;
  } else if (_x->Addr > _y->Addr) {
    return 1;
  } else {
    return 0;
  }
}

/// \brief Records the memory addresses touched by an AVX2 VSIB instruction
void vsib_mem_callback(instr_t *instr, int size) {
  dr_mcontext_t mc = {sizeof(mc),
                      DR_MC_CONTROL | DR_MC_INTEGER | DR_MC_MULTIMEDIA};
  dr_get_mcontext(dr_get_current_drcontext(), &mc);
  int i = 0;
  app_pc addr;
  bool is_write;
  mem_ref_t buf[32], *buf_iter = buf;
  while (instr_compute_address_ex(instr, &mc, i, &addr, &is_write)) {
    if (ctx.opts.blocks_only) {
      // this is really ugly. For VSIB, we need to do some preprocessing of the
      // memory touches
      const intptr_t mask = ~((1 << ctx.opts.mask_bits) - 1);
      size_t NumBlocks =
          1 + ((((intptr_t)addr & ~mask) + size - 1) >> ctx.opts.mask_bits);
      for (size_t j = 0; j < NumBlocks; ++j) {
        *buf_iter++ =
            (mem_ref_t){.Type = is_write ? REF_TYPE_WRITE : REF_TYPE_READ,
                        .Size = 1,
                        .Addr = (app_pc)((intptr_t)addr & mask) +
                                j * ((intptr_t)1 << ctx.opts.mask_bits)};
      }
    } else {
      *buf_iter++ =
          (mem_ref_t){.Type = is_write ? REF_TYPE_WRITE : REF_TYPE_READ,
                      .Size = size,
                      .Addr = addr};
    }
    ++i;
  }

  // For a VSIB instruction like vpgatherdd, each address is accessed at
  // essentially the same time (assuming a software-only adversary). To produce
  // consistent test results, we simply sort the accesses.
  if (ctx.opts.software_adversary) {
    qsort(buf, buf_iter - buf, sizeof(mem_ref_t), mem_ref_t_cmp);
  }

  for (const mem_ref_t *I = buf, *const E = buf_iter; I != E; ++I) {
    if (!ctx.opts.software_adversary || I == buf ||
        memcmp(I - 1, I, sizeof(mem_ref_t))) {
      *iter_ctx.current++ = *I;
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// Instrumentation Helpers
///////////////////////////////////////////////////////////////////////////////

/// \brief Instruments a dynamic basic block.
///
/// Inserts instructions at \p where to record the start address of \p bb in the
/// memory trace buffer.
static void instrument_bb(void *drcontext, instrlist_t *bb, instr_t *where) {
  reg_id_t buf_ptr, scratch;
  app_pc bb_pc = instr_get_app_pc(where);
  LOG(NULL, NVT_LOG_INSTRUMENT, 1, "instrument basic block '%p'\n", bb_pc);

  EXPECT(drreg_reserve_register(drcontext, bb, where, NULL, &buf_ptr) ==
             DRREG_SUCCESS,
         "Failed to reserve a register");
  EXPECT(drreg_reserve_register(drcontext, bb, where, NULL, &scratch) ==
             DRREG_SUCCESS,
         "Failed to reserve a register");

  if (bb_pc == (app_pc)test_ctx.test_begin_addr ||
      bb_pc == (app_pc)ctx.test_end_addr) {
    insert_update_bool(drcontext, &iter_ctx.recording, bb, where, scratch,
                       bb_pc == (app_pc)test_ctx.test_begin_addr ? true
                                                                 : false);
  }

  insert_load_buf_ptr(drcontext, bb, where, buf_ptr, scratch);
  insert_reset_buf_ptr(drcontext, bb, where, buf_ptr);
  insert_save_pc(drcontext, bb, where, buf_ptr, scratch, bb_pc);
  insert_save_type(drcontext, bb, where, buf_ptr, scratch, REF_TYPE_BB);
  insert_save_size(drcontext, bb, where, buf_ptr, scratch,
                   instr_length(drcontext, where));
  insert_update_buf_ptr(drcontext, bb, where, buf_ptr, scratch,
                        sizeof(mem_ref_t));

  EXPECT(drreg_unreserve_register(drcontext, bb, where, buf_ptr) ==
             DRREG_SUCCESS,
         "Failed to unreserve a register");
  EXPECT(drreg_unreserve_register(drcontext, bb, where, scratch) ==
             DRREG_SUCCESS,
         "Failed to unreserve a register");
}

static void instrument_vsib_mem(void *drcontext, instrlist_t *bb,
                                instr_t *where, opnd_t ref) {
#ifndef NDEBUG
  char opnd_str[128];
  opnd_disassemble_to_buffer(drcontext, ref, opnd_str, sizeof(opnd_str));
#endif
  LOG(NULL, NVT_LOG_INSTRUMENT, 2, "instrument VSIB memory operand -- '%s'\n",
      opnd_str);

  instr_t *instr = instr_clone(drcontext, where);
  ctx.heap_instrs[ctx.num_heap_instrs++] = instr;
  int opnd_sz = drutil_opnd_mem_size_in_bytes(ref, instr);
  dr_insert_clean_call(drcontext, bb, where, vsib_mem_callback, false, 2,
                       OPND_CREATE_INTPTR(instr), OPND_CREATE_INT32(opnd_sz));
}

/// \brief Insert instrumentation to record a memory access.
///
/// Inserts instructions at \p where to record the memory address accessed by
/// operand \p ref.
///
/// Before each memory access, we record
/// - The address being accessed
/// - The type of access (read/write)
/// - The size of the operand being read/written
static void instrument_mem(void *drcontext, instrlist_t *bb, instr_t *where,
                           opnd_t ref, bool write) {
#ifndef NDEBUG
  char opnd_str[128];
  opnd_disassemble_to_buffer(drcontext, ref, opnd_str, sizeof(opnd_str));
#endif
  LOG(NULL, NVT_LOG_INSTRUMENT, 2, "instrument memory operand -- '%s'\n",
      opnd_str);
  reg_id_t buf_ptr, scratch, scratch2;

  EXPECT(drreg_reserve_register(drcontext, bb, where, NULL, &buf_ptr) ==
             DRREG_SUCCESS,
         "Failed to reserve a register");
  EXPECT(drreg_reserve_register(drcontext, bb, where, NULL, &scratch) ==
             DRREG_SUCCESS,
         "Failed to reserve a register");
  EXPECT(drreg_reserve_register(drcontext, bb, where, NULL, &scratch2) ==
             DRREG_SUCCESS,
         "Failed to reserve a register");

  // save_addr must be called first
  insert_load_buf_ptr(drcontext, bb, where, buf_ptr, scratch);
  insert_save_addr(drcontext, bb, where, ref, buf_ptr, scratch, scratch2);
  insert_save_type(drcontext, bb, where, buf_ptr, scratch,
                   write ? REF_TYPE_WRITE : REF_TYPE_READ);
  insert_save_size(drcontext, bb, where, buf_ptr, scratch,
                   drutil_opnd_mem_size_in_bytes(ref, where));
  insert_update_buf_ptr(drcontext, bb, where, buf_ptr, scratch,
                        sizeof(mem_ref_t));

  EXPECT(drreg_unreserve_register(drcontext, bb, where, buf_ptr) ==
             DRREG_SUCCESS,
         "Failed to unreserve a register");
  EXPECT(drreg_unreserve_register(drcontext, bb, where, scratch) ==
             DRREG_SUCCESS,
         "Failed to unreserve a register");
  EXPECT(drreg_unreserve_register(drcontext, bb, where, scratch2) ==
             DRREG_SUCCESS,
         "Failed to unreserve a register");
}

/// \brief Inserts instrumentation to record any memory access(es) made by an
/// instruction.
static void instrument_instr(void *drcontext, instrlist_t *bb, instr_t *where) {
#ifndef NDEBUG
  char instr_str[128];
  instr_disassemble_to_buffer(drcontext, where, instr_str, sizeof(instr_str));
#endif
  LOG(NULL, NVT_LOG_INSTRUMENT, 2, "instrument instruction -- '%s'\n",
      instr_str);

  if (instr_reads_memory(where)) {
    for (int i = 0; i < instr_num_srcs(where); i++) {
      opnd_t opnd = instr_get_src(where, i);
      if (opnd_is_memory_reference(opnd)) {
        if (opnd_is_vsib(opnd)) {
          instrument_vsib_mem(drcontext, bb, where, opnd);
        } else {
          instrument_mem(drcontext, bb, where, opnd, false);
        }
      }
    }
  }
  if (instr_writes_memory(where)) {
    for (int i = 0; i < instr_num_dsts(where); i++) {
      if (opnd_is_memory_reference(instr_get_dst(where, i))) {
        instrument_mem(drcontext, bb, where, instr_get_dst(where, i), true);
      }
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// DrWrap Callbacks
///////////////////////////////////////////////////////////////////////////////

static void create_application_heap() {
  ctx.application_heap = dr_nonheap_alloc(ctx.opts.heap_size * MB,
                                          DR_MEMPROT_READ | DR_MEMPROT_WRITE);
  iter_ctx.application_heap_ptr = ctx.application_heap;
  LOG(NULL, NVT_LOG_APPLICATION_HEAP, 1, "Allocated application heap at: %p\n",
      ctx.application_heap);
}

/// \brief Replace calls to `malloc()` with allocation from the NVT's internal
/// heap.
///
/// Calls are only replaced while recording a trace. This is necessary to
/// achieve NVT test consistency because each fuzz iteration which calls
/// `malloc()` any number of times will likely receive different addresses
/// on each trace.
void pre_malloc_cb(void *wrapctx, void **user_data) {
  if (iter_ctx.recording) {
    if (ctx.application_heap == NULL) {
      create_application_heap();
    }

    size_t sz = (size_t)drwrap_get_arg(wrapctx, 0);
    LOG(NULL, NVT_LOG_APPLICATION_HEAP, 1,
        MALLOC_NAME "() called from %p with arg: %ld\n",
        drwrap_get_retaddr(wrapctx), sz);
    void *retval = iter_ctx.application_heap_ptr;
    drwrap_skip_call(wrapctx, retval, 0);
    LOG(NULL, NVT_LOG_APPLICATION_HEAP, 1, MALLOC_NAME "() returning: %p\n",
        retval);
    iter_ctx.application_heap_ptr =
        (void *)((intptr_t)iter_ctx.application_heap_ptr + sz);
    EXPECT((intptr_t)iter_ctx.application_heap_ptr -
                   (intptr_t)ctx.application_heap <=
               ctx.opts.heap_size * MB,
           "Attempted heap alloc beyond end of application heap memory");
  }
}

/// \brief Replace calls to `posix_memalign()` with allocation from the NVT's
/// internal heap.
void pre_posix_memalign_cb(void *wrapctx, void **user_data) {
  if (iter_ctx.recording) {
    if (ctx.application_heap == NULL) {
      create_application_heap();
    }

    void **memptr = drwrap_get_arg(wrapctx, 0);
    size_t alignment = (size_t)drwrap_get_arg(wrapctx, 1);
    size_t size = (size_t)drwrap_get_arg(wrapctx, 2);
    LOG(NULL, NVT_LOG_APPLICATION_HEAP, 1,
        "posix_memalign() called from %p with memptr='%p', alignment='%ld', "
        "size='%ld'\n",
        drwrap_get_retaddr(wrapctx), memptr, alignment, size);
    iter_ctx.application_heap_ptr =
        (void *)(((intptr_t)iter_ctx.application_heap_ptr + alignment) &
                 ~(alignment - 1));
    *memptr = iter_ctx.application_heap_ptr;
    drwrap_skip_call(wrapctx, (void *)0, 0);
    LOG(NULL, NVT_LOG_APPLICATION_HEAP, 1, "posix_memalign() returning: %p\n",
        *memptr);
    iter_ctx.application_heap_ptr =
        (void *)((intptr_t)iter_ctx.application_heap_ptr + size);
    EXPECT((intptr_t)iter_ctx.application_heap_ptr -
                   (intptr_t)ctx.application_heap <=
               ctx.opts.heap_size * MB,
           "Attempted heap alloc beyond end of application heap memory");
  }
}

/// \brief Replace calls to `memalign()` with allocation from the NVT's
/// internal heap.
void pre_memalign_cb(void *wrapctx, void **user_data) {
  if (iter_ctx.recording) {
    if (ctx.application_heap == NULL) {
      create_application_heap();
    }

    size_t alignment = (size_t)drwrap_get_arg(wrapctx, 0);
    size_t size = (size_t)drwrap_get_arg(wrapctx, 1);
    LOG(NULL, NVT_LOG_APPLICATION_HEAP, 1,
        "memalign() called from %p with alignment='%ld', "
        "size='%ld'\n",
        drwrap_get_retaddr(wrapctx), alignment, size);
    iter_ctx.application_heap_ptr =
        (void *)(((intptr_t)iter_ctx.application_heap_ptr + alignment) &
                 ~(alignment - 1));
    void *retval = iter_ctx.application_heap_ptr;
    drwrap_skip_call(wrapctx, retval, 0);
    LOG(NULL, NVT_LOG_APPLICATION_HEAP, 1, "memalign() returning: %p\n",
        retval);
    iter_ctx.application_heap_ptr =
        (void *)((intptr_t)iter_ctx.application_heap_ptr + size);
    EXPECT((intptr_t)iter_ctx.application_heap_ptr -
                   (intptr_t)ctx.application_heap <=
               ctx.opts.heap_size * MB,
           "Attempted heap alloc beyond end of application heap memory");
  }
}

/// \brief Replace calls to `aligned_alloc()` with allocation from the NVT's
/// internal heap.
void pre_aligned_alloc_cb(void *wrapctx, void **user_data) {
  if (iter_ctx.recording) {
    if (ctx.application_heap == NULL) {
      create_application_heap();
    }

    size_t alignment = (size_t)drwrap_get_arg(wrapctx, 0);
    size_t size = (size_t)drwrap_get_arg(wrapctx, 1);
    LOG(NULL, NVT_LOG_APPLICATION_HEAP, 1,
        "aligned_alloc() called from %p with alignment='%ld', "
        "size='%ld'\n",
        drwrap_get_retaddr(wrapctx), alignment, size);
    iter_ctx.application_heap_ptr =
        (void *)(((intptr_t)iter_ctx.application_heap_ptr + alignment) &
                 ~(alignment - 1));
    void *retval = iter_ctx.application_heap_ptr;
    drwrap_skip_call(wrapctx, retval, 0);
    LOG(NULL, NVT_LOG_APPLICATION_HEAP, 1, "aligned_alloc() returning: %p\n",
        retval);
    iter_ctx.application_heap_ptr =
        (void *)((intptr_t)iter_ctx.application_heap_ptr + size);
    EXPECT((intptr_t)iter_ctx.application_heap_ptr -
                   (intptr_t)ctx.application_heap <=
               ctx.opts.heap_size * MB,
           "Attempted heap alloc beyond end of application heap memory");
  }
}

/// \brief Skip calls to `free()` while recording an NVT trace.
void pre_free_cb(void *wrapctx, void **user_data) {
  if (iter_ctx.recording) {
    LOG(NULL, NVT_LOG_APPLICATION_HEAP, 1, FREE_NAME "() call\n");
    drwrap_skip_call(wrapctx, (void *)0, 0);
  }
}

///////////////////////////////////////////////////////////////////////////////
// Test Initialization
///////////////////////////////////////////////////////////////////////////////

/// \brief Find the next test to run, and reset #test_ctx.
static bool init_next_test(void) {
  test_ctx.fuzz_iter = 0;

  while (++ctx.test_num <= NVT_MAX_NUM_TESTS) {
    test_ctx.test_begin_addr = ctx.test_begin_addrs[ctx.test_num - 1];
    if (test_ctx.test_begin_addr) {
      break;
    }
  }
  if (!test_ctx.test_begin_addr) {
    LOG(NULL, NVT_LOG_TOP, 1, "found no more tests to run\n");
    return true;
  }
  if (ctx._log) {
    fprintf(ctx._log, "\nTest %d\n", ctx.test_num);
    fprintf(ctx._log, "==========\n");
  }

  LOG(NULL, NVT_LOG_TOP, 1, "beginning test %d\n", ctx.test_num);
  LOG(NULL, NVT_LOG_FUZZER, 1, "initializing the fuzz mutator\n");
  ASSERT(ctx.fuzz_arg);
  memset(ctx.fuzz_arg, 0, ctx.opts.fuzz_arg_size);
  drmf_status_t res =
      drfuzz_mutator_start(&ctx.mutator, ctx.fuzz_arg, ctx.opts.fuzz_arg_size,
                           ctx.opts.fuzz_cmd_argc, ctx.opts.fuzz_cmd_argv);
  if (process_drmf_status(DR_FUZZ_LABEL, res, true)) {
    dr_abort();
  }

  return false;
}

/// \brief Check whether module referred to by \p info is the test module.
static bool is_NVT_test_module(const module_data_t *info) {
  generic_func_t nvt_symbol =
      dr_get_proc_address(info->handle, TO_STRING(__NVT_TEST_MODULE__));
  if (nvt_symbol != NULL) {
    LOG(NULL, NVT_LOG_TOP, 1, "found the test module\n");
    return true;
  } else {
    return false;
  }
}

/// \brief Find all tests exported by the target NVT test module.
static void process_NVT_test_module(const module_data_t *info) {
  char test_begin_str[32] = TO_STRING(__NVT_TEST_BEGIN__);
  char *const test_begin_str_suffix =
      test_begin_str + sizeof(TO_STRING(__NVT_TEST_BEGIN__)) - 1;
  int i = 1;
  bool found_a_test = false;

  /* if it is the test module, find the addresses of all of the exported
   * tests */
  for (generic_func_t *I = ctx.test_begin_addrs, *const E =
                                                     ctx.test_begin_addrs +
                                                     NVT_MAX_NUM_TESTS;
       I != E; ++I) {
#if defined(__STDC_LIB_EXT1__) || _MSC_VER >= 1800
    sprintf_s(test_begin_str_suffix, test_begin_str_suffix - test_begin_str,
              "%d", i);
#else
    snprintf(test_begin_str_suffix, test_begin_str_suffix - test_begin_str,
             "%d", i);
#endif
    *I = dr_get_proc_address(info->handle, test_begin_str);
    if (*I) {
      LOG(NULL, NVT_LOG_TOP, 1, "found test_begin_%d()\n", i);
      found_a_test = true;
    }
    ++i;
  }

  EXPECT(found_a_test, "could not find any tests");
  init_next_test();
}

static bool find_and_wrap_malloc(const module_data_t *info) {
  app_pc malloc_addr = (app_pc)dr_get_proc_address(info->handle, MALLOC_NAME);
  if (malloc_addr != NULL) {
    LOG(NULL, NVT_LOG_TOP, 1, "found " MALLOC_NAME "() in %s\n",
        info->full_path);
    EXPECT(drwrap_wrap(malloc_addr, pre_malloc_cb, NULL),
           "Failed to wrap " MALLOC_NAME "()");
    return true;
  } else {
    return false;
  }
}

static bool find_and_wrap_posix_memalign(const module_data_t *info) {
  app_pc posix_memalign_addr =
      (app_pc)dr_get_proc_address(info->handle, "posix_memalign");
  if (posix_memalign_addr != NULL) {
    LOG(NULL, NVT_LOG_TOP, 1, "found posix_memalign() in %s\n",
        info->full_path);
    EXPECT(drwrap_wrap(posix_memalign_addr, pre_posix_memalign_cb, NULL),
           "Failed to wrap posix_memalign()");
    return true;
  } else {
    return false;
  }
}

static bool find_and_wrap_memalign(const module_data_t *info) {
  app_pc memalign_addr = (app_pc)dr_get_proc_address(info->handle, "memalign");
  if (memalign_addr != NULL) {
    LOG(NULL, NVT_LOG_TOP, 1, "found memalign() in %s\n", info->full_path);
    EXPECT(drwrap_wrap(memalign_addr, pre_memalign_cb, NULL),
           "Failed to wrap memalign()");
    return true;
  } else {
    return false;
  }
}

static bool find_and_wrap_aligned_alloc(const module_data_t *info) {
  app_pc aligned_alloc_addr =
      (app_pc)dr_get_proc_address(info->handle, "aligned_alloc");
  if (aligned_alloc_addr != NULL) {
    LOG(NULL, NVT_LOG_TOP, 1, "found aligned_alloc() in %s\n", info->full_path);
    EXPECT(drwrap_wrap(aligned_alloc_addr, pre_aligned_alloc_cb, NULL),
           "Failed to wrap aligned_alloc()");
    return true;
  } else {
    return false;
  }
}

static bool find_and_wrap_free(const module_data_t *info) {
  app_pc free_addr = (app_pc)dr_get_proc_address(info->handle, FREE_NAME);
  if (free_addr != NULL) {
    LOG(NULL, NVT_LOG_TOP, 1, "found " FREE_NAME "() in %s\n", info->full_path);
    EXPECT(drwrap_wrap(free_addr, pre_free_cb, NULL),
           "Failed to wrap " FREE_NAME "()");
    return true;
  } else {
    return false;
  }
}

///////////////////////////////////////////////////////////////////////////////
// Dr. Fuzz Callbacks
///////////////////////////////////////////////////////////////////////////////

/// \brief Called before each fuzz iteration.
///
/// Generates new fuzzed data using the Dr. Fuzz mutator.
static void pre_fuzz_cb(void *fuzzctx, generic_func_t target_pc,
                        dr_mcontext_t *mc) {
  LOG(NULL, NVT_LOG_TOP, 1, "beginning fuzz iteration %d\n",
      test_ctx.fuzz_iter);
  EXPECT(drfuzz_mutator_get_next_value(ctx.mutator, ctx.fuzz_arg) ==
             DRMF_SUCCESS,
         "drfuzz mutator did not generate the next value");
  EXPECT(drfuzz_set_arg(fuzzctx, 0, ctx.fuzz_arg) == DRMF_SUCCESS,
         "drfuzz failed to set arg0");
  EXPECT(
      drfuzz_set_arg(fuzzctx, 1, (void *)(ptr_int_t)ctx.opts.fuzz_arg_size) ==
          DRMF_SUCCESS,
      "drfuzz failed to set arg1");

  // init fuzz iteration context
  md5_init(&iter_ctx.memory_hash_ctx);
  md5_init(&iter_ctx.output_hash_ctx);
  iter_ctx.recording = false;
  iter_ctx.current = iter_ctx.tbuffer;
  iter_ctx.application_heap_ptr = ctx.application_heap;

  if (ctx._log) {
    fprintf(ctx._log, "\nFuzz Iteration %d:\n", test_ctx.fuzz_iter);
  }
}

/// \brief Called after each fuzz iteration.
///
/// Finish processing the memory trace digest. If the trace digest for this
/// fuzz iteration differs from any other trace digest produced during this
/// test, report a test failure and exit.
static bool post_fuzz_cb(void *fuzzctx, generic_func_t target_pc) {
  bool continue_fuzzing = true;

  LOG(NULL, NVT_LOG_TOP, 1, "ending fuzz iteration %d\n", test_ctx.fuzz_iter);
  if (test_ctx.fuzz_iter == 0) {
    /* record this iteration as our benchmark hash */
    md5_final(&iter_ctx.memory_hash_ctx, test_ctx.memory_trace_hash);
    md5_final(&iter_ctx.output_hash_ctx, test_ctx.output_trace_hash);

    /* record this input as our benchmark input */
    test_result_t *results = &ctx.test_results[ctx.test_num];
    results->input1 = dr_global_alloc(ctx.opts.fuzz_arg_size);
    memcpy(results->input1, ctx.fuzz_arg, ctx.opts.fuzz_arg_size);
  } else {
    /* compute the hash, and compare against the benchmark */
    byte new_memory_trace_hash[MD5_BLOCK_SIZE];
    md5_final(&iter_ctx.memory_hash_ctx, new_memory_trace_hash);
    byte new_output_trace_hash[MD5_BLOCK_SIZE];
    md5_final(&iter_ctx.output_hash_ctx, new_output_trace_hash);
    /* if the hashes differ, this test has failed */
    if ((memcmp(test_ctx.memory_trace_hash, new_memory_trace_hash,
                MD5_BLOCK_SIZE) != 0) ||
        (memcmp(test_ctx.output_trace_hash, new_output_trace_hash,
                MD5_BLOCK_SIZE) != 0)) {
      /* get the parameters which caused the failure */
      test_result_t *results = &ctx.test_results[ctx.test_num];
      results->input2 = dr_global_alloc(ctx.opts.fuzz_arg_size);
      memcpy(results->input2, ctx.fuzz_arg, ctx.opts.fuzz_arg_size);
      continue_fuzzing = false;
    }
  }

  /* stop fuzzing when we either hit the maximum number of user-specified
   * fuzz iterations, OR the fuzz mutator has exhausted all fuzz permutations */
  if (continue_fuzzing && (++test_ctx.fuzz_iter == ctx.opts.fuzz_iterations ||
                           !drfuzz_mutator_has_next_value(ctx.mutator))) {
    continue_fuzzing = false;
  }

  if (!continue_fuzzing) {
    LOG(NULL, NVT_LOG_TOP, 1, "ending test %d\n", ctx.test_num);
    LOG(NULL, NVT_LOG_FUZZER, 1, "stopping the fuzz mutator\n");
    ASSERT(ctx.mutator);
    drmf_status_t res = drfuzz_mutator_stop(ctx.mutator);
    if (process_drmf_status(DR_FUZZ_LABEL, res, true)) {
      dr_abort();
    }
    (void)init_next_test();
  }

  return continue_fuzzing;
}

///////////////////////////////////////////////////////////////////////////////
// DynamoRIO Event Callbacks
///////////////////////////////////////////////////////////////////////////////

/// \brief Called by DynamoRIO during the application transformation stage.
//
/// Some architectures have a special instruction which iterates through a
/// string. Unfortunately this instruction interferes with our analysis,
/// so we transform the app by expanding all instances of this instruction
/// into a loop
static dr_emit_flags_t event_bb_app2app(void *drcontext, void *tag,
                                        instrlist_t *bb, bool for_trace,
                                        bool translating) {
  EXPECT(drutil_expand_rep_string(drcontext, bb),
         "failed to expand a rep string");
  return DR_EMIT_DEFAULT;
}

/// \brief Records syscall writes to the output trace digest.
static bool event_syscall_write(void *drcontext) {
  LOG(NULL, NVT_LOG_SYSCALL, 1, "Handling a write() system call\n");

  int fd = (int)dr_syscall_get_param(drcontext, 0);
  const void *buf = (const void *)dr_syscall_get_param(drcontext, 1);
  size_t count = dr_syscall_get_param(drcontext, 2);
  md5_update(&iter_ctx.output_hash_ctx, (const uint8_t *)&fd, sizeof(fd));
  md5_update(&iter_ctx.output_hash_ctx, buf, count);
  md5_update(&iter_ctx.output_hash_ctx, (const uint8_t *)&count, sizeof(count));

  return true;
}

/// Called by DynamoRIO whenever the NVT test module makes a system call.
///
/// **NOTE:** Currently, most system calls are not supported.
static bool event_syscall(void *drcontext, int sysnum) {
  LOG(NULL, NVT_LOG_SYSCALL, 1, "syscall %d\n", sysnum);
  if (iter_ctx.recording) {
    switch (sysnum) {
    case SYS_write:
      return event_syscall_write(drcontext);
    case SYS_fstat:
      return true; // whitelisted
    default:
      /* FIXME: some syscalls should be allowed and supported! */
      dr_fprintf(STDERR, "Error: Unknown syscall '%d'\n", sysnum);
      dr_abort();
    }
  }

  return true;
}

/// \brief Callback for instruction instrumentation.
///
/// This function is called whenever DynamoRIO pulls new instructions into the
/// code cache. It performs three tasks:
/// 1. If \p where is the first instruction in \p bb, add instrumentation to
/// record the basic block address.
/// 2. Always insert instrumentation to record memory accesses, if any of the
/// instruction's operands is a memory reference.
/// 3. If \p where is the last instruction in \p bb, add a clean call after \p
/// where to hash the memory trace buffer into the trace digest, reset the trace
/// buffer, and emit any logging information, if necessary.
static dr_emit_flags_t event_instruction(void *drcontext, void *tag,
                                         instrlist_t *bb, instr_t *where,
                                         bool for_trace, bool translating,
                                         void *user_data) {
#ifndef NDEBUG
  app_pc bb_pc = instr_get_app_pc(where);
#endif
  LOG(NULL, NVT_LOG_INSTRUMENT, 1, "event instruction '%p'\n", bb_pc);

  if (drmgr_is_first_instr(drcontext, where)) {
    instrument_bb(drcontext, bb, where);
  }

  instrument_instr(drcontext, bb, where);

  if (drmgr_is_last_instr(drcontext, where)) {
    // process the buffer, then empty the buffer
    dr_insert_clean_call(drcontext, bb, where, process_buf, false, 0);
  }

  return DR_EMIT_DEFAULT;
}

/// \brief Called by DynamoRIO whenever a module is loaded, e.g.\ via dlopen().
///
/// Typically, many modules are loaded during NVT operation. Only one is the
/// target NVT test module. This function looks for the special NVT test module
/// symbol to locate the actual test module. When the test module is loaded,
/// event_module_load() searches for all NVT test symbols and records their
/// addresses.
static void event_module_load(void *drcontext, const module_data_t *info,
                              bool loaded) {
  LOG(NULL, NVT_LOG_TOP, 1, "Loaded %s at [%p, %p]\n", info->full_path,
      info->start, info->end);
  if (is_NVT_test_module(info)) {
    process_NVT_test_module(info);
  }
  (void)find_and_wrap_malloc(info);
  (void)find_and_wrap_posix_memalign(info);
  (void)find_and_wrap_memalign(info);
  (void)find_and_wrap_aligned_alloc(info);
  (void)find_and_wrap_free(info);
}

/// \brief Called by DynamoRIO when the target program exits, to perform cleanup
static void event_exit(void) {
  void *drctx = dr_get_current_drcontext();
  char status = ctx.opts.expect_fail;
  for (int i = 0; i < NVT_MAX_NUM_TESTS; ++i) {
    test_result_t *results = &ctx.test_results[i];
    if (results->input2 != NULL) {
      if (ctx.opts.fuzz_arg_size <= 16) {
        dr_fprintf(STDOUT, "Test %d failed: Inputs {", i);
        for (unsigned i = 0; i < ctx.opts.fuzz_arg_size; ++i) {
          dr_fprintf(STDOUT, "%#x%s", results->input1[i],
                     i == ctx.opts.fuzz_arg_size - 1 ? "" : ", ");
        }
        dr_fprintf(STDOUT, "} and {");
        for (unsigned i = 0; i < ctx.opts.fuzz_arg_size; ++i) {
          dr_fprintf(STDOUT, "%#x%s", results->input2[i],
                     i == ctx.opts.fuzz_arg_size - 1 ? "" : ", ");
        }
        dr_fprintf(STDOUT, "} resulted in inconsistent traces\n");
      } else {
        int column = 0;
        dr_fprintf(STDOUT, "Test %d failed: Inputs\n{", i);
        for (unsigned i = 0; i < ctx.opts.fuzz_arg_size; ++i) {
          if (column++ == 16) {
            dr_fprintf(STDOUT, "\n ");
            column = 1;
          }
          dr_fprintf(STDOUT, "%#x%s", results->input1[i],
                     i == ctx.opts.fuzz_arg_size - 1 ? "" : ", ");
        }
        column = 0;
        dr_fprintf(STDOUT, "}\nand\n{");
        for (unsigned i = 0; i < ctx.opts.fuzz_arg_size; ++i) {
          if (column++ == 16) {
            dr_fprintf(STDOUT, "\n ");
            column = 1;
          }
          dr_fprintf(STDOUT, "%#x%s", results->input2[i],
                     i == ctx.opts.fuzz_arg_size - 1 ? "" : ", ");
        }
        dr_fprintf(STDOUT, "}\nresulted in inconsistent traces\n");
      }
      status = !ctx.opts.expect_fail;
    }
  }

  LOG(NULL, NVT_LOG_TOP, 2, "unregistering bb_app2app event\n");
  EXPECT(drmgr_unregister_bb_app2app_event(event_bb_app2app),
         "Failed to unregister event_bb_app2app");

  LOG(NULL, NVT_LOG_TOP, 2, "unregistering module_load event\n");
  EXPECT(drmgr_unregister_module_load_event(event_module_load),
         "Failed to unregister event_module_load");

  LOG(NULL, NVT_LOG_TOP, 2, "unregistering bb_instrumentation event\n");
  EXPECT(drmgr_unregister_bb_insertion_event(event_instruction),
         "Failed to unregister event_instruction");

  LOG(NULL, NVT_LOG_TOP, 2, "unregistering syscall event\n");
  EXPECT(drmgr_unregister_pre_syscall_event(event_syscall),
         "Failed to unregister event_syscall");

  LOG(NULL, NVT_LOG_TOP, 1, "freeing miscellaneous heap objects\n");
  for (int i = 0; i < ctx.num_heap_instrs; ++i) {
    instr_destroy(drctx, ctx.heap_instrs[i]);
  }
  if (ctx._log) {
    fclose(ctx._log);
  }
  if (ctx.fuzz_arg) {
    free(ctx.fuzz_arg);
  }
  for (int i = 0; i < NVT_MAX_NUM_TESTS; ++i) {
    test_result_t *result = &ctx.test_results[i];
    if (result->input1) {
      dr_global_free(result->input1, ctx.opts.fuzz_arg_size);
    }
    if (result->input2) {
      dr_global_free(result->input2, ctx.opts.fuzz_arg_size);
    }
  }

  // clear the application heap
  if (ctx.application_heap != NULL) {
    dr_nonheap_free(ctx.application_heap, ctx.opts.heap_size * MB);
  }

  LOG(NULL, NVT_LOG_TOP, 1, "exiting extension modules\n");
  drwrap_exit();
  EXPECT(drfuzz_exit() == DRMF_SUCCESS, "drfuzz failed to exit");
  drmgr_exit();
  EXPECT(drreg_exit() == DRREG_SUCCESS, "drreg failed to exit");
  EXPECT(drsym_exit() == DRSYM_SUCCESS, "drsym failed to exit");
  drutil_exit();

  LOG(NULL, NVT_LOG_TOP, 1, "exiting\n");
  if (status) {
    dr_exit_process(status);
  } else {
    dr_fprintf(STDOUT, "All tests passed\n");
  }
}

///////////////////////////////////////////////////////////////////////////////
// NVT Initialization Helpers
///////////////////////////////////////////////////////////////////////////////

/// \brief Initialize DynamoRIO modules.
static void init_modules(client_id_t id) {
  /* We need 3 reg slots beyond drreg's eflags slots => 4 slots */
  drreg_options_t reg_opts = {sizeof(reg_opts), 4, false};
  EXPECT(drmgr_init(), "failed to initialize drmgr");
  EXPECT(drreg_init(&reg_opts) == DRREG_SUCCESS, "failed to initialize drreg");
  EXPECT(drsym_init((ptr_int_t)NULL) == DRSYM_SUCCESS,
         "failed to initialize drsym");
  EXPECT(drutil_init(), "failed to initialize drutil");
  EXPECT(drwrap_init(), "failed to initialize drwrap");
  EXPECT(drfuzz_init(id) == DRMF_SUCCESS, "drfuzz failed to init");
}

/// \brief Register callbacks with DynamoRIO.
static void register_events() {
  bool res;

  LOG(NULL, NVT_LOG_TOP, 2, "registering exit event\n");
  dr_register_exit_event(event_exit);

  LOG(NULL, NVT_LOG_TOP, 2, "registering bb_app2app event\n");
  res = drmgr_register_bb_app2app_event(event_bb_app2app, NULL);
  EXPECT(res, "Failed to register event_bb_app2app\n");

  LOG(NULL, NVT_LOG_TOP, 2, "registering module_load event\n");
  res = drmgr_register_module_load_event(event_module_load);
  EXPECT(res, "Failed to register event_module_load\n");

  LOG(NULL, NVT_LOG_TOP, 2, "registering bb_instrumentation event\n");
  res = drmgr_register_bb_instrumentation_event(NULL, event_instruction, NULL);
  EXPECT(res, "Failed to register event_instruction\n");

  LOG(NULL, NVT_LOG_TOP, 2, "registering syscall event\n");
  res = drmgr_register_pre_syscall_event(event_syscall);
  EXPECT(res, "Failed to register event_syscall\n");
}

/// \brief Helper function to find non-exported symbols.
static ptr_int_t lookup_symbol_address(const module_data_t *mod,
                                       const char *symbol_name) {
  size_t symbol_offset;
  drsym_error_t result =
      drsym_lookup_symbol(mod->full_path, symbol_name, &symbol_offset, 0);
  EXPECT(result == DRSYM_SUCCESS && symbol_offset > 0, "Could not find '%s'",
         symbol_name);
  return (ptr_int_t)(mod->start + symbol_offset);
}

static void init_fuzz_target(module_data_t *module) {
  LOG(NULL, NVT_LOG_TOP, 1, "looking for NVT_FUZZ_TARGET...\n");
  ctx.fuzz_target_addr =
      (generic_func_t)lookup_symbol_address(module, TO_STRING(NVT_FUZZ_TARGET));
  LOG(NULL, NVT_LOG_TOP, 1, "looking for NVT_FUZZ_TARGET... found\n");

  /* set the fuzz target to NVT_FUZZ_TARGET */
  drmf_status_t res =
      drfuzz_fuzz_target(ctx.fuzz_target_addr, 2, 0, DRWRAP_CALLCONV_DEFAULT,
                         pre_fuzz_cb, post_fuzz_cb);
  if (process_drmf_status(DR_FUZZ_LABEL, res, true)) {
    dr_abort();
  }
}

///////////////////////////////////////////////////////////////////////////////
// NVT main()
///////////////////////////////////////////////////////////////////////////////

/// \brief Performs initialization.
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
  dr_set_client_name(
      "Covert C++ Noninterference Verification Tool (NVT)",
      "https://nemmerle.hpdc.syr.edu/sdconsta/covert-cpp/issues");
  LOG(NULL, NVT_LOG_TOP, 1, "initializing\n");

#ifdef __STDC_LIB_EXT1__
  set_constraint_handler_s(abort_handler_s);
#endif

  dr_set_process_exit_behavior(DR_EXIT_MULTI_THREAD | DR_EXIT_SKIP_THREAD_EXIT);
#ifndef NDEBUG
  disassemble_set_syntax(DR_DISASM_ATT);
#endif

  /* get the command-line options */
  LOG(NULL, NVT_LOG_TOP, 1, "parsing command line options\n");
  parse_options(&ctx.opts, argc, argv);
  if (ctx.opts.log_file) {
#if defined(__STDC_LIB_EXT1__) || _MSC_VER >= 1800
    fopen_s(&ctx._log, ctx.opts.log_file, "w");
#else
    ctx._log = fopen(ctx.opts.log_file, "w");
#endif
  }

  LOG(NULL, NVT_LOG_TOP, 1, "initializing extension modules\n");
  init_modules(id);

  LOG(NULL, NVT_LOG_TOP, 1, "registering callback events\n");
  register_events();

  module_data_t *app = dr_get_main_module();
  EXPECT(app, "failed to get DynLoader module");

  /* find the NVT_TEST_END address */
  LOG(NULL, NVT_LOG_TOP, 1, "looking for NVT_TEST_END... \n");
  drsym_debug_kind_t kind;
  EXPECT(drsym_get_module_debug_kind(app->full_path, &kind) == DRSYM_SUCCESS,
         "target does not have symbols.\n");
  ctx.test_end_addr =
      (generic_func_t)lookup_symbol_address(app, TO_STRING(NVT_TEST_END));
  LOG(NULL, NVT_LOG_TOP, 1, "looking for NVT_TEST_END... found\n");

  ctx.fuzz_arg = malloc(ctx.opts.fuzz_arg_size); // allocate the fuzz buffer
  init_fuzz_target(app);

  /* cleanup */
  dr_free_module_data(app);
}

/** @} */
