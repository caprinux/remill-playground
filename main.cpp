#include <cstdlib>
#include <filesystem>
#include <string_view>

#include <glog/logging.h>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include <llvm/IR/IRBuilder.h>

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);

  llvm::LLVMContext context;
  auto arch = remill::Arch::Get(context, "linux", "amd64");
  if (!arch) {
    llvm::outs() << "Failed to get architecture\n";
    return EXIT_FAILURE;
  }

  std::vector<std::filesystem::path> sem_dirs;
  if (const char *dir = getenv("REMILL_SEMANTICS_DIR")) {
    sem_dirs.push_back(dir);
  }
  auto semantics = remill::LoadArchSemantics(arch.get(), sem_dirs);
  if (!semantics) {
    llvm::outs() << "Failed to load architecture semantics\n";
    return EXIT_FAILURE;
  }

  auto intrinsics = arch->GetInstrinsicTable();
  if (!intrinsics) {
    llvm::outs() << "Failed to get intrinsic table\n";
    return EXIT_FAILURE;
  }

  // Example 1: Lift a simple instruction (mov rcx, 1337)
  llvm::outs() << "\n=== Lifting: mov rcx, 1337 ===\n";
  {
    uint8_t instr_bytes[] = {0x48, 0xc7, 0xc1, 0x39, 0x05, 0x00, 0x00};
    std::string_view instr_view(reinterpret_cast<char *>(instr_bytes),
                                sizeof(instr_bytes));
    remill::Instruction instruction;
    remill::DecodingContext decoding_context = arch->CreateInitialContext();
    if (!arch->DecodeInstruction(0x1000, instr_view, instruction,
                                 decoding_context)) {
      llvm::outs() << "Failed to decode instruction\n";
      return EXIT_FAILURE;
    }

    auto function = arch->DefineLiftedFunction("lifted_mov", semantics.get());
    auto block = &function->getEntryBlock();
    auto lifter = instruction.GetLifter();
    auto status = lifter->LiftIntoBlock(instruction, block);
    if (status != remill::kLiftedInstruction) {
      llvm::outs() << "Failed to lift instruction\n";
      return EXIT_FAILURE;
    }

    llvm::IRBuilder<> ir(block);
    ir.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));

    remill::OptimizeModule(arch.get(), semantics.get(), {function});
    llvm::outs() << "[optimized]\n";
    function->print(llvm::outs());
  }

  return EXIT_SUCCESS;
}
