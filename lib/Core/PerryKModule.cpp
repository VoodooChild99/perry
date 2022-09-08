#include "klee/Core/Interpreter.h"
#include "klee/Module/KModule.h"
#include "klee/Support/ErrorHandling.h"
#include "klee/Support/ModuleUtil.h"

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Path.h"

#include "SpecialFunctionHandler.h"


using namespace llvm;
using namespace klee;

void KModule::setupAll(std::vector<std::unique_ptr<llvm::Module>> &modules,
                       const Interpreter::ModuleOptions &opts,
                       std::map<std::string, std::string> &SymName)
{
  SmallString<256> LibPath(opts.LibraryDir);
  llvm::sys::path::append(LibPath,
                          "libkleeRuntimeIntrinsic" + opts.OptSuffix + ".bca");
  std::string error;
  if (!klee::loadFile(LibPath.c_str(), modules[0]->getContext(), modules,
                      error))
  {
    klee_error("Could not load KLEE intrinsic file %s", LibPath.c_str());
  }

  // 1.) Link the modules together
  while (link(modules, opts.EntryPoint)) {
    // 2.) Apply different instrumentation
    instrument(opts, &SymName);
  }

  // 3.) Optimise and prepare for KLEE

  // Create a list of functions that should be preserved if used
  std::vector<const char *> preservedFunctions;
  SpecialFunctionHandler::staticPrepare(*this, preservedFunctions);
  for (auto F : opts.TopLevelFunctions) {
    preservedFunctions.push_back(F.c_str());
    preservedFunctions.push_back(("__perry_dummy_" + F).c_str());
  }

  // Preserve the free-standing library calls
  preservedFunctions.push_back("memset");
  preservedFunctions.push_back("memcpy");
  preservedFunctions.push_back("memcmp");
  preservedFunctions.push_back("memmove");

  optimiseAndPrepare(opts, preservedFunctions);
  checkModule();

  // 4.) Manifest the module
  manifestNoOutput();

  // Others things should be done in the Executor
}