# Remill Power-User Reference

## Lifting API Levels

Three levels of abstraction — pick the right one:

| API | Manages | You manage |
|---|---|---|
| `LiftIntoBlock` | One instruction → IR | Everything else (blocks, CFG, worklist) |
| `TraceLifter` | CFG traversal, basic blocks, direct calls | Byte reading, indirect targets |
| `remill-lift` binary | Everything | Nothing (CLI only) |

---

## Architecture Variants

```cpp
// x86 — two backends, four variants
kArchX86              // 32-bit, remill native semantics
kArchX86_SLEIGH       // 32-bit, Ghidra SLEIGH backend
kArchAMD64            // 64-bit, remill native (most complete)
kArchAMD64_SLEIGH     // 64-bit, SLEIGH backend
kArchAMD64_AVX        // AVX support
kArchAMD64_AVX512     // AVX-512 support

// ARM — three distinct archs
kArchAArch64LittleEndian              // AArch64
kArchAArch32LittleEndian              // ARM32
kArchThumb2LittleEndian               // Thumb2 (SLEIGH only)
kArchAArch64LittleEndian_SLEIGH       // AArch64 via SLEIGH

// Other
kArchSparc32 / kArchSparc64
kArchSparc32_SLEIGH
kArchPPC                              // PowerPC via SLEIGH
```

**Factory methods:**
```cpp
// Cached (global): use for single-threaded or single-arch use
auto arch = remill::Arch::Get(context, "linux", "amd64");

// Uncached: use for multi-arch or multi-threaded scenarios
auto arch = remill::Arch::Build(&context, remill::kOSLinux, remill::kArchAMD64);

// Recover arch from an already-prepared module
auto arch = remill::Arch::GetModuleArch(*module);
```

**SLEIGH thread safety** — SLEIGH architectures share global state, must be serialized:
```cpp
{
    auto lock = remill::Arch::Lock(remill::kArchAMD64_SLEIGH); // RAII
    // ... SLEIGH operations here ...
} // lock released
```

**ARM ISA mode switching**: `Instruction::branch_taken_arch_name` changes the arch at a
branch target (Thumb ↔ A32). `DecodingContext` with `TMode` controls decoding mode
per-instruction:
```cpp
auto ctx = arch->CreateInitialContext();
ctx.UpdateContextReg("TMode", 1);  // decode as Thumb2
```

---

## Decoder Behaviors

### Idiom Fusion

`DecodeInstruction` fuses multi-instruction idioms by default:
- x86: `call $+5; pop rax` → fused into one PC-load idiom
- SPARC: `sethi; or` → fused into one load-immediate idiom

To decode one instruction at a time without fusion:
```cpp
size_t min = arch->MinInstructionSize(ctx);
size_t max = arch->MaxInstructionSize(ctx, /*permit_fuse_idioms=*/false);
// Feed min bytes to start, grow by 1 byte until decode succeeds
```

### Instruction Categories

```cpp
switch (inst.category) {
    case Instruction::kCategoryNormal:
    case Instruction::kCategoryNoOp:
        // Falls through to inst.next_pc
    case Instruction::kCategoryDirectJump:
        // inst.branch_taken_pc is the target
    case Instruction::kCategoryConditionalBranch:
        // inst.branch_taken_pc, inst.branch_not_taken_pc
    case Instruction::kCategoryDirectFunctionCall:
        // inst.branch_taken_pc = callee, inst.branch_not_taken_pc = return site
    case Instruction::kCategoryIndirectJump:
    case Instruction::kCategoryIndirectFunctionCall:
        // Target unknown statically — becomes __remill_jump/__remill_function_call
    case Instruction::kCategoryFunctionReturn:
        // Becomes __remill_function_return
    case Instruction::kCategoryAsyncHyperCall:
        // syscall, int, svc → __remill_async_hyper_call
    case Instruction::kCategoryError:
        // HLT, UD2 → __remill_error
}
```

---

## TraceLifter & TraceManager

### Minimal implementation

```cpp
class MyTraceManager : public remill::TraceManager {
    std::unordered_map<uint64_t, std::vector<uint8_t>> memory;
    std::unordered_map<uint64_t, llvm::Function *> lifted;

    bool TryReadExecutableByte(uint64_t addr, uint8_t *byte) override {
        // Return false to stop lifting at unmapped addresses
        auto it = memory.find(addr & ~0xFFFULL);
        if (it == memory.end()) return false;
        *byte = it->second[addr & 0xFFF];
        return true;
    }

    void SetLiftedTraceDefinition(uint64_t addr, llvm::Function *f) override {
        lifted[addr] = f;
    }
};

MyTraceManager mgr;
remill::TraceLifter lifter(arch.get(), &mgr);
lifter.Lift(entry_address);
```

### Pre-declaring traces

Provide forward declarations before lifting begins (e.g. from a symbol table). This lets
TraceLifter generate correct `call` instructions to not-yet-lifted functions:

```cpp
llvm::Function *GetLiftedTraceDeclaration(uint64_t addr) override {
    if (symbol_table.count(addr))
        return arch->DeclareLiftedFunction(symbol_table[addr], module);
    return nullptr;  // TraceLifter will auto-name it "sub_XXXX"
}
```

### Preventing re-lifting

Return an existing definition to skip already-lifted code:

```cpp
llvm::Function *GetLiftedTraceDefinition(uint64_t addr) override {
    auto it = lifted.find(addr);
    return it != lifted.end() ? it->second : nullptr;
}
```

### Devirtualization

Turn indirect jumps/calls into concrete edges. Without this, indirect jumps become
`__remill_jump` intrinsics (opaque). This is the key hook for VM handler dispatch:

```cpp
void ForEachDevirtualizedTarget(
    const remill::Instruction &inst,
    std::function<void(uint64_t, remill::DevirtualizedTargetKind)> func) override {

    // Example: resolve a jump table
    for (uint64_t target : resolve_jump_table(inst.pc)) {
        func(target, remill::DevirtualizedTargetKind::kTraceHead);
        // kTraceLocal = target is inside the current function (intra-proc branch)
        // kTraceHead  = target starts a new function
    }
}
```

---

## Register Hierarchy

Every register has a full parent/child hierarchy:

```cpp
const remill::Register *rax = arch->RegisterByName("RAX");
const remill::Register *eax = arch->RegisterByName("EAX");
const remill::Register *ah  = arch->RegisterByName("AH");

ah->EnclosingRegister();             // RAX (the 64-bit root)
ah->EnclosingRegisterOfSize(4);      // EAX (smallest enclosing reg ≥ 4 bytes)
rax->EnclosedRegisters();            // [EAX] (direct children only)

// Walk to root manually
const remill::Register *r = some_reg;
while (r->parent) r = r->parent;    // r is now the root register

// Get a typed pointer into State* at runtime
llvm::Value *rax_ptr = rax->AddressOf(state_ptr, ir);  // → i64*

// Enumerate all registers
arch->ForEachRegister([](const remill::Register *reg) {
    llvm::outs() << reg->name << " @ offset " << reg->offset
                 << ", size " << reg->size << "\n";
});

// Look up by byte offset into State struct
const remill::Register *r = arch->RegisterAtStateOffset(offset);
```

---

## Optimization Pipeline

### Standard two-pass approach

```cpp
// Pass 1: inline semantics and run optimization on the semantics module.
// This collapses ISEL_ calls into actual IR and eliminates dead semantic code.
remill::OptimizeModule(arch.get(), semantics.get(), {func1, func2});

// Pass 2: move traces into a clean module and run a second optimization pass
// without remill's semantics infrastructure.
auto clean = std::make_unique<llvm::Module>("output", context);
arch->PrepareModuleDataLayout(clean.get());
remill::MoveFunctionIntoModule(func1, clean.get());
remill::OptimizeBareModule(clean.get());
```

### OptimizationGuide

```cpp
remill::OptimizationGuide guide;
guide.slp_vectorize   = false;  // SLP vectorizer (default off)
guide.loop_vectorize  = false;  // Loop vectorizer (default off)
guide.verify_input    = true;   // Verify module before optimization
guide.verify_output   = true;   // Verify module after optimization
remill::OptimizeModule(arch.get(), semantics.get(), {func}, guide);
```

### Undefined value hints

Tell the optimizer which registers are dead before optimization runs. This eliminates
unnecessary register preservation in the IR:

```cpp
// "I don't care about RCX after this trace"
auto undef = ir.CreateCall(intrinsics->undefined_64, {});
ir.CreateStore(undef, rcx_ptr);
// Optimizer can now eliminate all RCX bookkeeping
```

---

## Intrinsics Reference

### Control flow (you must implement or stub these)

```cpp
// Called for indirect jumps — addr is the computed target in State
Memory *__remill_jump(State &, addr_t addr, Memory *);

// Called for indirect/direct calls — addr is the callee
Memory *__remill_function_call(State &, addr_t addr, Memory *);

// Called at returns — addr is the return address
Memory *__remill_function_return(State &, addr_t addr, Memory *);

// Called when a lifted trace has no continuation (end of lifting)
Memory *__remill_missing_block(State &, addr_t addr, Memory *);

// Called for undefined/illegal instructions
Memory *__remill_error(State &, addr_t addr, Memory *);

// syscall, int, svc etc. — ret_addr is the instruction after the syscall
Memory *__remill_async_hyper_call(State &, addr_t ret_addr, Memory *);

// CPUID, RDTSC, MSR reads/writes etc. (see SyncHyperCall::Name enum)
Memory *__remill_sync_hyper_call(State &, Memory *, SyncHyperCall::Name);
```

### Memory I/O (you must implement these)

```cpp
uint8_t  __remill_read_memory_8(Memory *, addr_t);
uint64_t __remill_read_memory_64(Memory *, addr_t);
// ... 8/16/32/64 variants, plus f32/f64/f80/f128

Memory *__remill_write_memory_8(Memory *, addr_t, uint8_t);
Memory *__remill_write_memory_64(Memory *, addr_t, uint64_t);
// ... 8/16/32/64 variants, plus f32/f64/f80/f128
```

### Atomic operations

```cpp
Memory *__remill_compare_exchange_memory_8(Memory *, addr_t, uint8_t &expected, uint8_t desired);
// ... 16/32/64/128-bit variants

Memory *__remill_fetch_and_add_8(Memory *, addr_t, uint8_t &value);
// ... fetch_and_sub/and/or/xor/nand, 8/16/32/64-bit variants (24 total)
```

### Memory ordering

```cpp
Memory *__remill_barrier_load_load(Memory *);    // lfence
Memory *__remill_barrier_store_load(Memory *);   // mfence
Memory *__remill_barrier_load_store(Memory *);   // load-acquire
Memory *__remill_barrier_store_store(Memory *);  // store-release
Memory *__remill_atomic_begin(Memory *);
Memory *__remill_atomic_end(Memory *);
```

### Flag computation markers

These wrap boolean results of flag calculations so downstream analyses can identify
flag semantics without reverse-engineering arithmetic. They are NOPs that return their
input — their value is as analysis markers:

```cpp
bool __remill_flag_computation_zero(bool result, ...);     // ZF
bool __remill_flag_computation_sign(bool result, ...);     // SF
bool __remill_flag_computation_overflow(bool result, ...); // OF
bool __remill_flag_computation_carry(bool result, ...);    // CF
```

### x86-specific hyper calls

```cpp
// I/O ports
uint8_t  __remill_read_io_port_8(Memory *, addr_t);
Memory  *__remill_write_io_port_8(Memory *, addr_t, uint8_t);
// ... 16/32-bit variants

// Privileged operations (triggered via __remill_sync_hyper_call)
// kX86CPUID, kX86ReadTSC, kX86ReadTSCP
// kX86ReadModelSpecificRegister, kX86WriteModelSpecificRegister
// kX86SysCall, kX86SysEnter, kX86SysExit
// kX86SetSegmentES/SS/DS/FS/GS
// kX86SetControlReg0/1/2/3/4, kAMD64SetControlReg0/1/2/3/4/8
// kX86LoadGlobalDescriptorTable, kX86LoadInterruptDescriptorTable
```

---

## Utility Functions

### IR access helpers

```cpp
// Get the standard arguments from within a lifted function/block
llvm::Value *state  = remill::LoadStatePointer(block);
llvm::Value *pc     = remill::LoadProgramCounter(block, *intrinsics);
llvm::Value *mem    = remill::LoadMemoryPointer(block, *intrinsics);
llvm::Value *nextpc = remill::LoadNextProgramCounter(block, *intrinsics);
llvm::Value *retpc  = remill::LoadReturnProgramCounterRef(block);  // alloca ptr
llvm::Value *taken  = remill::LoadBranchTaken(block);              // i1

// Generate memory accesses for any LLVM type (handles structs/arrays too)
llvm::Value *val  = remill::LoadFromMemory(intrinsics, ir, type, mem_ptr, addr);
llvm::Value *mem2 = remill::StoreToMemory(intrinsics, ir, value, mem_ptr, addr);

// Find a named local variable in a lifted function (register vars, MEMORY, etc.)
auto [ptr, type] = remill::FindVarInFunction(block, "RAX");

// Add calls using remill's 3-argument convention
remill::AddCall(block, target_func, *intrinsics);
remill::AddTerminatingTailCall(block, intrinsics->missing_block, *intrinsics);
```

### Module helpers

```cpp
// Verify and get a readable error message
auto err = remill::VerifyFunctionMsg(func);
if (err) llvm::errs() << "Bad IR: " << *err << "\n";

// Serialize
remill::StoreModuleIRToFile(module, "out.ll");   // human-readable
remill::StoreModuleToFile(module, "out.bc");      // bitcode

// Load
auto mod = remill::LoadModuleFromFile(&context, "out.bc");

// Clone a function across modules (handles cross-module globals, strips debug info)
remill::CloneFunctionInto(src_func, dst_func);

// Move a function to another module (rewires all references)
remill::MoveFunctionIntoModule(func, dest_module);

// Iterate all ISEL slots: ISEL_MOV_GPRv_IMMv_32 → semantic function
remill::ForEachISel(module, [](llvm::GlobalVariable *slot, llvm::Function *sem) {
    // Useful for dead code elimination or semantic analysis
});

// Replace a constant across an entire module
remill::ReplaceAllUsesOfConstant(old_const, new_const, module);

// Get all callers of a function
std::vector<llvm::CallInst*> callers = remill::CallersOf(func);
```

### Semantics search

```cpp
// Find semantics bitcode file without loading it
auto path = remill::FindSemanticsBitcodeFile("amd64");

// Find with extra search paths (searched first, then defaults)
std::vector<std::filesystem::path> extra = {"/my/semantics"};
auto path = remill::FindSemanticsBitcodeFile("amd64", extra);
```

---

## Function Annotation System

Tag functions for pipeline tracking:

```cpp
#include <remill/BC/Annotate.h>

// Tag a function
remill::Annotate<remill::LiftedFunction>(func);
remill::Annotate<remill::EntrypointFunction>(wrapper);

// Hierarchy of available tags:
// BaseFunction
// ├── LiftedFunction        — remill-lifted traces
// ├── EntrypointFunction    — program entry points
// ├── ExternalFunction
// │   ├── AbiLibraries
// │   ├── CFGExternal
// │   └── ExtWrapper
// └── Helper
//     ├── RemillHelper
//     ├── McSemaHelper
//     └── Semantics

// Query
if (remill::HasOriginType<remill::LiftedFunction>(f)) { ... }

// Get all functions of a type from a module
std::vector<llvm::Function*> lifted;
remill::GetFunctionsByOrigin<decltype(lifted), remill::LiftedFunction>(mod, lifted);

// Link two functions bidirectionally (e.g. typed wrapper ↔ sub_XXXX trace)
remill::TieFunctions(entrypoint_func, sub_1234_func);
llvm::Function *trace = remill::GetTied(entrypoint_func);  // → sub_1234_func
```

---

## `remill-lift` CLI

```bash
remill-lift \
  --arch amd64 \
  --os linux \
  --bytes c704ba01000000 \          # hex-encoded bytes to lift
  --address 0x1000 \                # virtual address of first byte
  --entry_address 0x1000 \          # address to start lifting from
  --ir_out /dev/stdout \            # output LLVM IR (.ll)
  --ir_pre_out pre_opt.ll \         # IR before optimization
  --bc_out out.bc                   # output bitcode (.bc)
```

**Signature flag** — wraps the lifted trace in a typed function by mapping arguments to
registers. Useful for quick inspection without writing a State allocator:

```bash
# Wrap result as: uint64_t f(uint64_t rdi, uint64_t rsi) { return rax; }
remill-lift --arch amd64 --os linux \
  --bytes 4801fe \                  # add rsi, rdi
  --signature "rax(rdi,rsi)" \
  --ir_out /dev/stdout
```

**Other flags:**
- `--mute_state_escape` — null out State* in control flow intrinsic calls (cleaner IR
  for analysis)
- `--symbolic_regs` — initialize GPRs with placeholder values instead of zero

---

## ABI Constants

```cpp
#include <remill/BC/ABI.h>

// Argument indices in every lifted function: (State*, addr_t pc, Memory*)
remill::kStatePointerArgNum   // 0
remill::kPCArgNum             // 1
remill::kMemoryPointerArgNum  // 2

// Named local variables inside every lifted function
remill::kMemoryVariableName       // "MEMORY"
remill::kStateVariableName        // "STATE"
remill::kPCVariableName           // "PC"
remill::kNextPCVariableName       // "NEXT_PC"
remill::kReturnPCVariableName     // "RETURN_PC"
remill::kBranchTakenVariableName  // "BRANCH_TAKEN"
```

---

## Module Preparation

Must be called before any lifting into a module:

```cpp
// Full setup: sets triple, data layout, declares all intrinsics
arch->PrepareModule(semantics.get());

// Light setup: only sets triple and data layout (no intrinsic declarations)
arch->PrepareModuleDataLayout(clean_module.get());
```

After `PrepareModule` or `LoadArchSemantics`, the intrinsic table is populated:
```cpp
const remill::IntrinsicTable *intrinsics = arch->GetInstrinsicTable();
```

---

## Subclassing InstructionLifter

Override operand lifting behavior for custom IR generation:

```cpp
class MyLifter : public remill::InstructionLifter {
  MyLifter(const remill::Arch *arch, const remill::IntrinsicTable &intrinsics)
      : InstructionLifter(arch, intrinsics) {}

 protected:
  // Intercept all memory address computations
  llvm::Value *LiftAddressOperand(remill::Instruction &inst,
                                   llvm::BasicBlock *block,
                                   llvm::Value *state_ptr,
                                   llvm::Argument *arg,
                                   remill::Operand &op) override {
      auto *addr = InstructionLifter::LiftAddressOperand(inst, block, state_ptr, arg, op);
      // ... instrument or replace the address value ...
      return addr;
  }

  // Intercept register reads
  llvm::Value *LiftRegisterOperand(remill::Instruction &inst,
                                    llvm::BasicBlock *block,
                                    llvm::Value *state_ptr,
                                    llvm::Argument *arg,
                                    remill::Operand &op) override;

  // Intercept immediate values
  llvm::Value *LiftImmediateOperand(remill::Instruction &inst,
                                     llvm::BasicBlock *block,
                                     llvm::Argument *arg,
                                     remill::Operand &op) override;
};
```

`Instruction::GetLifter()` returns the default lifter. To use your custom lifter, call
`LiftIntoBlock` directly on your subclass instance instead.
