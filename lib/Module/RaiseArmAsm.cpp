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

static void gen_stub_msr(Module &M) {
  // void msr(i32)
  LLVMContext &MC = M.getContext();
  FunctionCallee stub_callee = M.getOrInsertFunction(INSTR_FN_FREFIX(msr),
        Type::getVoidTy(MC), Type::getInt32Ty(MC));

  Function *stub = dyn_cast<Function>(stub_callee.getCallee());

  IRBuilder<> IRB(stub->getContext());
  IRBuilder<> IRBM(MC);
  BasicBlock *bb = BasicBlock::Create(IRB.getContext(), "entry", stub);
  IRB.SetInsertPoint(bb);
  
  auto PRIMASK = M.getNamedGlobal("PRIMASK");
  if (!PRIMASK) {
    M.getOrInsertGlobal("PRIMASK", IRBM.getInt32Ty());
    PRIMASK = M.getNamedGlobal("PRIMASK");
    PRIMASK->setLinkage(GlobalValue::CommonLinkage);
    PRIMASK->setInitializer(ConstantInt::get(IRBM.getInt32Ty(), 0));
  }
  IRB.CreateStore(stub->getArg(0), PRIMASK);
  IRB.CreateRetVoid();
}

static void gen_stub_mrs(Module &M) {
  // i32 mrs()
  LLVMContext &MC = M.getContext();
  FunctionCallee stub_callee = M.getOrInsertFunction(INSTR_FN_FREFIX(mrs),
        Type::getInt32Ty(MC));

  Function *stub = dyn_cast<Function>(stub_callee.getCallee());

  IRBuilder<> IRB(stub->getContext());
  IRBuilder<> IRBM(MC);
  BasicBlock *bb = BasicBlock::Create(IRB.getContext(), "entry", stub);
  IRB.SetInsertPoint(bb);

  auto PRIMASK = M.getNamedGlobal("PRIMASK");
  if (!PRIMASK) {
    M.getOrInsertGlobal("PRIMASK", IRBM.getInt32Ty());
    PRIMASK = M.getNamedGlobal("PRIMASK");
    PRIMASK->setLinkage(GlobalValue::CommonLinkage);
    PRIMASK->setInitializer(ConstantInt::get(IRBM.getInt32Ty(), 0));
  }
  auto ret = IRB.CreateLoad(IRB.getInt32Ty(), PRIMASK);
  IRB.CreateRet(ret);
}

static void gen_stub_rbit(Module &M) {
  // i32 rbit(i32)
  LLVMContext &MC = M.getContext();
  IntegerType *i32Ty = Type::getInt32Ty(MC);
  FunctionCallee stub_callee = M.getOrInsertFunction(INSTR_FN_FREFIX(rbit),
        i32Ty, i32Ty);

  Function *stub = dyn_cast<Function>(stub_callee.getCallee());

  IRBuilder<> IRB(stub->getContext());
  IRBuilder<> IRBM(MC);
  BasicBlock *bb = BasicBlock::Create(IRB.getContext(), "entry", stub);
  IRB.SetInsertPoint(bb);

  auto var0 = stub->getArg(0);
  auto One = ConstantInt::get(i32Ty, 1);
  auto Two = ConstantInt::get(i32Ty, 2);
  auto Four = ConstantInt::get(i32Ty, 4);
  auto Eight = ConstantInt::get(i32Ty, 8);
  auto Sixteen = ConstantInt::get(i32Ty, 16);

  // %2 = lshr i32 %0, 1
  auto var2 = IRB.CreateLShr(var0, One);
  // %3 = and i32 %2, 1431655765
  auto var3 = IRB.CreateAnd({var2, ConstantInt::get(i32Ty, 1431655765)});
  // %4 = shl i32 %0, 1
  auto var4 = IRB.CreateShl(var0, One);
  // %5 = and i32 %4, -1431655766
  auto var5 = IRB.CreateAnd({var4, ConstantInt::get(i32Ty, -1431655766)});
  // %6 = or i32 %3, %5
  auto var6 = IRB.CreateOr({var3, var5});
  // %7 = lshr i32 %6, 2
  auto var7 = IRB.CreateLShr(var6, Two);
  // %8 = and i32 %7, 858993459
  auto var8 = IRB.CreateAnd({var7, ConstantInt::get(i32Ty, 858993459)});
  // %9 = shl i32 %6, 2
  auto var9 = IRB.CreateShl(var6, Two);
  // %10 = and i32 %9, -858993460
  auto var10 = IRB.CreateAnd({var9, ConstantInt::get(i32Ty, -858993460)});
  // %11 = or i32 %8, %10
  auto var11 = IRB.CreateOr({var8, var10});
  // %12 = lshr i32 %11, 4
  auto var12 = IRB.CreateLShr(var11, Four);
  // %13 = and i32 %12, 252645135
  auto var13 = IRB.CreateAnd({var12, ConstantInt::get(i32Ty, 252645135)});
  // %14 = shl i32 %11, 4
  auto var14 = IRB.CreateShl(var11, Four);
  // %15 = and i32 %14, -252645136
  auto var15 = IRB.CreateAnd({var14, ConstantInt::get(i32Ty, -252645136)});
  // %16 = or i32 %13, %15
  auto var16 = IRB.CreateOr({var13, var15});
  // %17 = lshr i32 %16, 8
  auto var17 = IRB.CreateLShr(var16, Eight);
  // %18 = and i32 %17, 16711935
  auto var18 = IRB.CreateAnd({var17, ConstantInt::get(i32Ty, 16711935)});
  // %19 = shl i32 %16, 8
  auto var19 = IRB.CreateShl(var16, Eight);
  // %20 = and i32 %19, -16711936
  auto var20 = IRB.CreateAnd({var19, ConstantInt::get(i32Ty, -16711936)});
  // %21 = or i32 %18, %20
  auto var21 = IRB.CreateOr({var18, var20});
  // %22 = lshr i32 %21, 16
  auto var22 = IRB.CreateLShr(var21, Sixteen);
  // %23 = shl i32 %21, 16
  auto var23 = IRB.CreateShl(var21, Sixteen);
  // %24 = or i32 %22, %23
  auto var24 = IRB.CreateOr({var22, var23});
  // ret i32 %24
  IRB.CreateRet(var24);
}

#define ASM_HANDLE_LIST() \
  { \
    ASM_HANDLE_ENTRY(ldrex),  \
    ASM_HANDLE_ENTRY(strex),  \
    ASM_HANDLE_ENTRY(msr),    \
    ASM_HANDLE_ENTRY(mrs),    \
    ASM_HANDLE_ENTRY(rbit),   \
  }

RaiseArmAsmPass::HandlerMapTy RaiseArmAsmPass::InitHandlerMap() {
  RaiseArmAsmPass::HandlerMapTy ret = ASM_HANDLE_LIST();
  return ret;
}

RaiseArmAsmPass::IgnoreSetTy RaiseArmAsmPass::InitIgnoreSet() {
  IgnoreSetTy ret = {
    "nop", "wfi", "wfe", "dsb", "isb", "dmb", "sev", "cpsid", "bkpt", "cpsie"
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
  StringRef AS = IA->getAsmString();
  AS = AS.substr(AS.find_first_not_of(' '));
  std::string insn = AS.substr(0, AS.find_first_of(' ')).lower();

  if (insn.empty()) {
    std::string warn_msg;
    raw_string_ostream OS(warn_msg);
    OS << "Ignore empty inline asm: ";
    CI->print(OS);
    klee_warning("%s", warn_msg.c_str());
    ignore.insert(CI);
    return;
  }

  if (ignoreSet.find(insn) != ignoreSet.end()) {
    ignore.insert(CI);
    return;
  }
  
  if (handlerMap.find(insn) == handlerMap.end()) {
    klee_warning("Missing lift handler for ARM instruction %s", AS.str().c_str());
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
    if (ins->user_empty()) {
      // just remove this asm if no one uses the return value
      ins->eraseFromParent();
    } else {
      std::string err_msg;
      raw_string_ostream OS(err_msg);
      OS << "Cannot just remove instruction because it has users: ";
      ins->print(OS);
      klee_error("%s", err_msg.c_str());
    }
  }

  if (savedInsn.empty() && ignoredInsn.empty()) {
    return false; 
  } else {
    return true;
  }
}