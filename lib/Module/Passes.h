//===-- Passes.h ------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_PASSES_H
#define KLEE_PASSES_H

#include "klee/Config/Version.h"
#include "klee/Perry/Passes.h"

#include "llvm/ADT/Triple.h"
#include "llvm/CodeGen/IntrinsicLowering.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Analysis/CallGraph.h"

#include <set>
#include <map>
#include <vector>

namespace llvm {
class Function;
class Instruction;
class Module;
class DataLayout;
class TargetLowering;
class Type;
} // namespace llvm

namespace klee {

/// RaiseAsmPass - This pass raises some common occurences of inline
/// asm which are used by glibc into normal LLVM IR.
class RaiseAsmPass : public llvm::ModulePass {
  static char ID;

  const llvm::TargetLowering *TLI;

  llvm::Triple triple;

  llvm::Function *getIntrinsic(llvm::Module &M, unsigned IID, llvm::Type **Tys,
                               unsigned NumTys);
  llvm::Function *getIntrinsic(llvm::Module &M, unsigned IID, llvm::Type *Ty0) {
    return getIntrinsic(M, IID, &Ty0, 1);
  }

  bool runOnInstruction(llvm::Module &M, llvm::Instruction *I);

public:
  RaiseAsmPass() : llvm::ModulePass(ID), TLI(0) {}

  bool runOnModule(llvm::Module &M) override;
};

// This is a module pass because it can add and delete module
// variables (via intrinsic lowering).
class IntrinsicCleanerPass : public llvm::ModulePass {
  static char ID;
  const llvm::DataLayout &DataLayout;
  llvm::IntrinsicLowering *IL;

  bool runOnBasicBlock(llvm::BasicBlock &b, llvm::Module &M);

public:
  IntrinsicCleanerPass(const llvm::DataLayout &TD)
      : llvm::ModulePass(ID), DataLayout(TD),
        IL(new llvm::IntrinsicLowering(TD)) {}
  ~IntrinsicCleanerPass() { delete IL; }

  bool runOnModule(llvm::Module &M) override;
};

// performs two transformations which make interpretation
// easier and faster.
//
// 1) Ensure that all the PHI nodes in a basic block have
//    the incoming block list in the same order. Thus the
//    incoming block index only needs to be computed once
//    for each transfer.
//
// 2) Ensure that no PHI node result is used as an argument to
//    a subsequent PHI node in the same basic block. This allows
//    the transfer to execute the instructions in order instead
//    of in two passes.
class PhiCleanerPass : public llvm::FunctionPass {
  static char ID;

public:
  PhiCleanerPass() : llvm::FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &f) override;
};

class DivCheckPass : public llvm::ModulePass {
  static char ID;

public:
  DivCheckPass() : ModulePass(ID) {}
  bool runOnModule(llvm::Module &M) override;
};

/// This pass injects checks to check for overshifting.
///
/// Overshifting is where a Shl, LShr or AShr is performed
/// where the shift amount is greater than width of the bitvector
/// being shifted.
/// In LLVM (and in C/C++) this undefined behaviour!
///
/// Example:
/// \code
///     unsigned char x=15;
///     x << 4 ; // Defined behaviour
///     x << 8 ; // Undefined behaviour
///     x << 255 ; // Undefined behaviour
/// \endcode
class OvershiftCheckPass : public llvm::ModulePass {
  static char ID;

public:
  OvershiftCheckPass() : ModulePass(ID) {}
  bool runOnModule(llvm::Module &M) override;
};

/// LowerSwitchPass - Replace all SwitchInst instructions with chained branch
/// instructions.  Note that this cannot be a BasicBlock pass because it
/// modifies the CFG!
class LowerSwitchPass : public llvm::FunctionPass {
public:
  static char ID; // Pass identification, replacement for typeid
  LowerSwitchPass() : FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &F) override;

  struct SwitchCase {
    llvm ::Constant *value;
    llvm::BasicBlock *block;

    SwitchCase() : value(0), block(0) {}
    SwitchCase(llvm::Constant *v, llvm::BasicBlock *b) : value(v), block(b) {}
  };

  typedef std::vector<SwitchCase> CaseVector;
  typedef std::vector<SwitchCase>::iterator CaseItr;

private:
  void processSwitchInst(llvm::SwitchInst *SI);
  void switchConvert(CaseItr begin, CaseItr end, llvm::Value *value,
                     llvm::BasicBlock *origBlock,
                     llvm::BasicBlock *defaultBlock);
};

/// InstructionOperandTypeCheckPass - Type checks the types of instruction
/// operands to check that they conform to invariants expected by the Executor.
///
/// This is a ModulePass because other pass types are not meant to maintain
/// state between calls.
class InstructionOperandTypeCheckPass : public llvm::ModulePass {
private:
  bool instructionOperandsConform;

public:
  static char ID;
  InstructionOperandTypeCheckPass()
      : llvm::ModulePass(ID), instructionOperandsConform(true) {}
  bool runOnModule(llvm::Module &M) override;
  bool checkPassed() const { return instructionOperandsConform; }
};

/// FunctionAliasPass - Enables a user of KLEE to specify aliases to functions
/// using -function-alias=<name|pattern>:<replacement> which are injected as
/// GlobalAliases into the module. The replaced function is removed.
class FunctionAliasPass : public llvm::ModulePass {

public:
  static char ID;
  FunctionAliasPass() : llvm::ModulePass(ID) {}
  bool runOnModule(llvm::Module &M) override;

private:
  static const llvm::FunctionType *getFunctionType(const llvm::GlobalValue *gv);
  static bool checkType(const llvm::GlobalValue *match, const llvm::GlobalValue *replacement);
  static bool tryToReplace(llvm::GlobalValue *match, llvm::GlobalValue *replacement);
  static bool isFunctionOrGlobalFunctionAlias(const llvm::GlobalValue *gv);

};

/// Instruments every function that contains a KLEE function call as nonopt
class OptNonePass : public llvm::ModulePass {
public:
  static char ID;
  OptNonePass() : llvm::ModulePass(ID) {}
  bool runOnModule(llvm::Module &M) override;
};

/// Raise ARM instructions
class RaiseArmAsmPass : public llvm::ModulePass {

public:
  // replace handler
  using InsnRepHandlerFnTy = void(*)(llvm::Module&, llvm::CallInst*);
  // instrument handler
  using InsnInstrHandlerFnTy = void(*)(llvm::Module&);
  // map
  struct HandlerInfo {
    InsnInstrHandlerFnTy InstrFn;
    std::string InstrFnName;
  };
  using HandlerMapTy = std::map<std::string, HandlerInfo>;
  using IgnoreSetTy = std::set<std::string>;

  static char ID;
  RaiseArmAsmPass() : llvm::ModulePass(ID) {}
  bool runOnModule(llvm::Module &M) override;

private:
  void handleAsmInsn(llvm::Module &M, llvm::Instruction &I,
                      std::map<std::string, std::set<llvm::CallInst*>> &save,
                      std::set<llvm::CallInst*> &ignore);

  static HandlerMapTy handlerMap;
  static IgnoreSetTy ignoreSet;
  static HandlerMapTy InitHandlerMap();
  static IgnoreSetTy InitIgnoreSet();
};

/// Instrument calls to target function, and symbolize every parameters
class FuncSymbolizePass : public llvm::ModulePass {
public:
  static char ID;
  FuncSymbolizePass(const std::set<std::string> &_TopLevelFunctions,
                    std::map<std::string, std::string> *_FunctionToSymbolName,
            const std::map<StructOffset, std::set<std::string>> &_PtrFunction,
            const std::map<std::string, std::unordered_set<uint64_t>> &_OkValuesMap) :
    llvm::ModulePass(ID), TopLevelFunctions(_TopLevelFunctions),
    FunctionToSymbolName(_FunctionToSymbolName), PtrFunction(_PtrFunction),
    OkValuesMap(_OkValuesMap) {}
  ~FuncSymbolizePass();
  bool runOnModule(llvm::Module &M) override;
  struct Field {
    int offset;
    int num_bits;
    int start_bit;

    bool operator==(const Field &rhs) {
      return this->offset     == rhs.offset &&
             this->num_bits   == rhs.num_bits &&
             this->start_bit  == rhs.start_bit;
    }

    friend llvm::raw_ostream &operator<<(llvm::raw_ostream &os,
                                         const Field &F) {
      os << "offset=" << F.offset
         << ", num_bits=" << F.num_bits
         << ", start_bit=" << F.start_bit << "\n";
      return os;
    }
  };

private:
  // A tree-like data structure to hold the real value of each formal param
  struct ParamCell {
    ParamCell *parent = nullptr;
    std::vector<ParamCell*> child;
    llvm::Value *val = nullptr;
    llvm::Type *ParamType = nullptr;
    int depth = 0;
    int idx = -1;
    bool isBuffer = false;
    ~ParamCell();
    bool allocated() const;
  };
  const std::set<std::string> &TopLevelFunctions;
  std::map<std::string, std::string> *FunctionToSymbolName;
  const std::map<StructOffset, std::set<std::string>> &PtrFunction;
  const std::map<std::string, std::unordered_set<uint64_t>> &OkValuesMap;
  std::string PeripheralPlaceholder;
  const llvm::DataLayout *DL;
  llvm::LLVMContext *ctx;
  llvm::FunctionCallee MakeSymbolicFC;
  llvm::FunctionCallee SetTaintFC;
  llvm::FunctionCallee SetPersistTaintFC;
  llvm::FunctionCallee GetTaintFC;
  llvm::FunctionCallee GetRetValFC;
  llvm::FunctionCallee AllocFixFC;
  llvm::FunctionCallee AssertFC;
  llvm::FunctionCallee GeneralHookFC;
  llvm::FunctionCallee GeneralHookWrapperFC;
  std::vector<std::pair<llvm::Value*, int>> GuessedBuffers;
  std::pair<llvm::Value*, int> fRetVal;
  llvm::CallGraph *CG = nullptr;
  bool TargetIsETH = false;
  Field TxBufLen;
  Field RxFrameLen;
  Field RxBufLen;
  Field DescBuf;
  llvm::BasicBlock *rx_set_length_block = nullptr;
  bool TargetIsTimer = false;
  unsigned TargetPeriphStructSize = 0;
  bool TargetIsDMA = false;
  llvm::Function *ParamF = nullptr;
  llvm::FunctionCallee DMAInitFC;
  std::unordered_set<llvm::Function *> GlovalVoidPtrArrayUserFn;
  std::unordered_set<llvm::Function *> InstrumentedCallbacks;

  void handleCallbacks(llvm::Module &M);
  llvm::Value *createDefaultFptr(llvm::IRBuilder<> &IRB,
                                 llvm::PointerType *fptr_ty);
  void handleGlobalVoidPtrArray(llvm::IRBuilder<> &IRB,
                                llvm::GlobalVariable &G,
                                std::vector<llvm::Type *> &ty);
  bool isEthernetPeriph(llvm::StringRef name);
  bool isDMAPeriph(llvm::StringRef name);
  void analyzeDescRegs(llvm::Module &M);
  void analyzeDescTxBufferLen(llvm::Module &M);
  void analyzeDescRxBufferLen(llvm::Module &M);
  void analyzeDescRxFrameLen(llvm::Module &M);
  void analyzeDescBuffer(llvm::Module &M);
  void analyzeDescMemLayout(llvm::Module &M);
  void analyzeDescConstraints(llvm::Module &M);
  bool isTimerPeriph(llvm::StringRef name);
  void analyzeTimerCounterReg(llvm::Module &M);
  void analyzeTimerPeriodReg(llvm::Module &M);
  void symbolizeGlobals(llvm::IRBuilder<> &IRB, llvm::Module &M);
  void createPeriph(llvm::IRBuilder<> &IRB, llvm::Module &M);
  void taintPeriph(llvm::IRBuilder<> &IRB, llvm::Module &M, llvm::DIType *ty,
                   int &taint, unsigned &offset);
  void createParamsFor(llvm::Function *TargetF, llvm::IRBuilder<> &IRB,
                       std::vector<ParamCell*> &results);
  void symbolizeParams(llvm::IRBuilder<> &IRB, std::vector<ParamCell*> &results);
  void prepFunctionPtr(llvm::Module &M, llvm::Function *TargetF,
                       llvm::IRBuilder<> &IRB, std::vector<ParamCell*> &results);
  void setTaint(llvm::IRBuilder<> &IRB, std::vector<ParamCell*> &results);
  void callTarget(llvm::Function *TargetF, llvm::IRBuilder<> &IRB,
                  std::vector<ParamCell*> &results);
  void fillParamas(llvm::IRBuilder<> &IRB, std::vector<ParamCell*> &results);
  void collectTaint(llvm::IRBuilder<> &IRB);
  void collectRetVal(llvm::IRBuilder<> &IRB, const std::string &FName);
  void symbolizeValue(llvm::IRBuilder<> &IRB, llvm::Value *Var,
                      const std::string &Name, uint32_t Size);
  bool createCellsFrom(llvm::IRBuilder<> &IRB, ParamCell *root);
  void symbolizeFrom(llvm::IRBuilder<> &IRB, ParamCell *root);
  void fillCellInner(llvm::IRBuilder<> &IRB, ParamCell *root);
  void applyDataHeuristic(llvm::IRBuilder<> &IRB,
                          std::vector<ParamCell*> &results,
                          llvm::Function *TargetF);
  llvm::Value* createDMAChannel(llvm::IRBuilder<> &IRB, ParamCell *PC,
                                const void * Cdef);
};

} // namespace klee

#endif /* KLEE_PASSES_H */
