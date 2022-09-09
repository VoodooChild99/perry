#include "Passes.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "klee/Support/ErrorHandling.h"

using namespace llvm;
using namespace klee;

char RaiseArmAsmPass::ID = 0;

#define GEN_STUB_FN(Name) gen_stub_ ## Name
#define INSTR_FN_FREFIX(Name) "__inlined_handler_for_" #Name

#define ASM_HANDLE_ENTRY(Name) \
  {#Name, {GEN_STUB_FN(Name), INSTR_FN_FREFIX(Name)}}

RaiseArmAsmPass::HandlerMapTy RaiseArmAsmPass::handlerMap = 
  RaiseArmAsmPass::InitHandlerMap();

RaiseArmAsmPass::IgnoreSetTy RaiseArmAsmPass::ignoreSet = 
  RaiseArmAsmPass::InitIgnoreSet();

static void gen_stub_ldrex(Module &M) {
  LLVMContext &MC = M.getContext();
  // i32 ldrex(i32*)
  FunctionCallee stub_callee = M.getOrInsertFunction(INSTR_FN_FREFIX(ldrex),
                              Type::getInt32Ty(MC), Type::getInt32PtrTy(MC));

  Function *stub = dyn_cast<Function>(stub_callee.getCallee());

  IRBuilder<> IRB(stub->getContext());
  BasicBlock *bb = BasicBlock::Create(IRB.getContext(), "entry", stub);
  IRB.SetInsertPoint(bb);

  Value *loaded = IRB.CreateLoad(IRB.getInt32Ty(), stub->getArg(0));
  IRB.CreateRet(loaded);
}

static void gen_stub_strex(Module &M) {
  LLVMContext &MC = M.getContext();
  // i32 strex(i32*, i32)
  FunctionCallee stub_callee = M.getOrInsertFunction(INSTR_FN_FREFIX(strex),
        Type::getInt32Ty(MC), Type::getInt32PtrTy(MC), Type::getInt32Ty(MC));

  Function *stub = dyn_cast<Function>(stub_callee.getCallee());

  IRBuilder<> IRB(stub->getContext());
  BasicBlock *bb = BasicBlock::Create(IRB.getContext(), "entry", stub);
  IRB.SetInsertPoint(bb);

  IRB.CreateStore(stub->getArg(1), stub->getArg(0));
  IRB.CreateRet(IRB.getInt32(0));
}

#define ASM_HANDLE_LIST() \
  { \
    ASM_HANDLE_ENTRY(ldrex),  \
    ASM_HANDLE_ENTRY(strex),  \
  }

RaiseArmAsmPass::HandlerMapTy RaiseArmAsmPass::InitHandlerMap() {
  RaiseArmAsmPass::HandlerMapTy ret = ASM_HANDLE_LIST();
  return ret;
}

RaiseArmAsmPass::IgnoreSetTy RaiseArmAsmPass::InitIgnoreSet() {
  IgnoreSetTy ret = {
    "MRS", "MSR", "NOP", "nop", "wfi", "wfe", "dsb", "isb", "dmb", "sev"
  };
  return ret;
}

static void replace_asm(Module &M, CallInst *CI, std::string &op) {
  std::string inlined_handler_name = INSTR_FN_FREFIX() + op;
  Function *F = M.getFunction(inlined_handler_name);
  if (!F) {
    klee_error(
      "%s is not presented, should not happen", inlined_handler_name.c_str()
    );
  }

  FunctionType *FT = F->getFunctionType();
  std::vector<Value*> origArgs;
  for (auto &arg : CI->args()) {
    origArgs.push_back(arg.get());
  }
  CallInst *newCall = CallInst::Create(FT, F, origArgs);
  ReplaceInstWithInst(CI, newCall);
}

void RaiseArmAsmPass::handleAsmInsn(Module &M, Instruction &I,
      std::map<std::string, std::set<CallInst*>> &save,
      std::set<CallInst*> &ignore)
{
  CallInst *CI = dyn_cast<CallInst>(&I);
  if (!CI) {
    return;
  }

  InlineAsm *IA = dyn_cast<InlineAsm>(CI->getCalledOperand());
  if (!IA) {
    return;
  }

  // now it's an inlined asm for sure
  std::string AS = IA->getAsmString();
  std::string insn = AS.substr(0, AS.find_first_of(' '));

  if (ignoreSet.find(insn) != ignoreSet.end()) {
    ignore.insert(CI);
    return;
  }
  
  if (handlerMap.find(insn) == handlerMap.end()) {
    klee_warning("Missing lift handler for ARM instruction %s", insn.c_str());
    return;
  }

  save[insn].insert(CI);
}

bool RaiseArmAsmPass::runOnModule(Module &M) {
  Triple TargetTriple(M.getTargetTriple());
  Triple::ArchType arch = TargetTriple.getArch();

  // make sure it's an ARM module
  if (arch != Triple::ArchType::arm && arch != Triple::ArchType::thumb) {
    return false;
  }

  // setup handler functions in IR
  for (auto entry : handlerMap) {
    if (M.getFunction(entry.second.InstrFnName)) {
      continue; 
    } else {
      entry.second.InstrFn(M);
    }
  }

  std::map<std::string, std::set<CallInst*>> savedInsn;
  std::set<CallInst*> ignoredInsn;

  // don't modify instructions inside the iteration
  for (auto &F : M) {
    for (auto &B : F) {
      for (auto &I : B) {
        handleAsmInsn(M, I, savedInsn, ignoredInsn);
      }
    }
  }

  for (auto entry : savedInsn) {
    std::string insn_op = entry.first;
    for (auto CI : entry.second) {
      replace_asm(M, CI, insn_op);
    }
  }

  for (auto ins : ignoredInsn) {
    ins->eraseFromParent();
  }

  if (savedInsn.empty() && ignoredInsn.empty()) {
    return false; 
  } else {
    return true;
  }
}