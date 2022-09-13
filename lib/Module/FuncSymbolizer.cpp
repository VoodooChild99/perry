#include "Passes.h"
#include "klee/Support/ErrorHandling.h"
#include "klee/Support/OptionCategories.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DebugInfo.h"

#include <stack>

using namespace llvm;
using namespace klee;

#define HEURISTIC_BUFFER_LENGTH   8

char FuncSymbolizePass::ID = 0;

/// Things we need to do in this pass:
/// 1. create proxies calling top level functions
/// 2. taint registers
/// 3. symbolize all parameters && non-constant global variables
/// 4. infer buffer, buffer are allocated with more space

namespace {
  cl::opt<std::string> TargetStruct(
    "target-periph-struct",
    cl::desc("The structure that holds the peripheral"),
    cl::init(""),
    cl::cat(MiscCat)
  );
  cl::opt<unsigned long long> TargetStructLoc(
    "target-periph-address",
    cl::desc("Physical address of the target peripheral"),
    cl::init(0),
    cl::cat(MiscCat)
  );
  cl::opt<unsigned long long> TargetStructSize(
    "target-periph-size",
    cl::desc("Size of the target peripheral"),
    cl::init(0),
    cl::cat(MiscCat)
  );
  cl::list<unsigned long long> PeriphAddrList(
    "periph-address",
    cl::desc("A list of physical addresses of other peripherals"),
    cl::cat(MiscCat)
  );
  cl::list<unsigned> PeriphSizeList(
    "periph-size",
    cl::desc("A list of sizes of other peripherals"),
    cl::cat(MiscCat)
  );
}

FuncSymbolizePass::ParamCell::~ParamCell() {
  std::vector<ParamCell*> childCopy = child;
  for (auto PC : childCopy) {
    if (PC) {
      delete PC;
    }
  }

  if (parent) {
    int index = -1;
    int cnt = 0;
    for (auto ChildPC : parent->child) {
      if (ChildPC == this) {
        index = cnt;
        break;
      }
      ++cnt;
    }
    if (index >= 0) {
      parent->child.erase(parent->child.begin() + index);
    }
    parent = nullptr;
  }
}

void FuncSymbolizePass::
symbolizeGlobals(llvm::IRBuilder<> &IRB, llvm::Module &M) {
  int gIdx = 0;
  for (auto &G : M.globals()) {
    if (G.isConstant()) {
      continue;
    }
    auto valueType = G.getValueType();
    if (valueType->isIntegerTy()) {
      // symbolize it
      std::string symbolName = "g" + std::to_string(gIdx);
      gIdx += 1;
      Value *addr = IRB.CreatePointerCast(&G, IRB.getInt8PtrTy());
      Value* varName 
        = ConstantDataArray::getString(IRB.getContext(), symbolName);
      Value *ptrVarName = IRB.CreateAlloca(varName->getType());
      IRB.CreateStore(varName, ptrVarName);
      ptrVarName = IRB.CreatePointerCast(ptrVarName, IRB.getInt8PtrTy());
      auto varSize = IRB.getInt32(DL->getTypeAllocSize(valueType));
      IRB.CreateCall(MakeSymbolicFC, {addr, varSize, ptrVarName});
    } else {
      std::string err_msg;
      raw_string_ostream OS(err_msg);
      OS << "Unsupported value type when symbolizing globals: ";
      valueType->print(OS);
      klee_error("%s", err_msg.c_str());
    }
  }
}


void FuncSymbolizePass::createPeriph(IRBuilder<> &IRB, Module &M) {
  unsigned num = PeriphAddrList.size();
  if (num != PeriphSizeList.size()) {
    klee_error("Number of addresses must be the same as the number of sizes");
  }

  int pIdx = 0;
  // create all peripherals
  bool target_periph_created = false;
  for (unsigned i = 0; i < num; ++i) {
    bool is_target = false;
    if (TargetStructLoc != 0) {
      if (PeriphAddrList[i] == TargetStructLoc) {
        target_periph_created = true;
        is_target = true;
      }
    }
    Value *pAddr = IRB.getInt32(PeriphAddrList[i]);
    Value *pSize = IRB.getInt32(PeriphSizeList[i]);
    IRB.CreateCall(AllocFixFC, {pAddr, pSize});
    std::string SymbolName;
    if (is_target) {
      SymbolName = "s0";
    } else {
      SymbolName = "p" + std::to_string(pIdx);
      ++pIdx;
    }
    Value *addr = IRB.CreateIntToPtr(pAddr, IRB.getInt8PtrTy());
    Value* varName 
      = ConstantDataArray::getString(IRB.getContext(), SymbolName);
    Value *ptrVarName = IRB.CreateAlloca(varName->getType());
    IRB.CreateStore(varName, ptrVarName);
    ptrVarName = IRB.CreatePointerCast(ptrVarName, IRB.getInt8PtrTy());
    IRB.CreateCall(MakeSymbolicFC, {addr, pSize, ptrVarName});
  }
    
  // create the target peripheral
  if (TargetStructLoc != 0) {
    DebugInfoFinder DIF;
    DIF.processModule(M);
    DICompositeType *DICT = nullptr;
    for (auto DIT : DIF.types()) {
      if (DIT->getMetadataID() == Metadata::DIDerivedTypeKind) {
        auto DT = cast<DIDerivedType>(DIT);
        auto BT = DT->getBaseType();
        if (!BT) {
          continue;
        }
        if (BT->getMetadataID() == Metadata::DICompositeTypeKind) {
          if (DT->getName() == TargetStruct) {
            DICT = cast<DICompositeType>(BT);
          }
        }
      } else if (DIT->getMetadataID() == Metadata::DICompositeTypeKind) {
        if (DIT->getName() == TargetStruct) {
          DICT = cast<DICompositeType>(DIT);
        }
      }
      if (DICT) {
        break;
      }
    }
    if (!DICT) {
      klee_error("Cannot locate struct");
    }

    if (!target_periph_created) {
      Value *pLoc = IRB.getInt32(TargetStructLoc);
      unsigned target_size = TargetStructSize;
      // allocate it
      if (target_size == 0) {
        target_size = DICT->getSizeInBits() / 8;
      }
      IRB.CreateCall(AllocFixFC, {pLoc, IRB.getInt32(target_size)});
      // symbolize it
      Value *addr = IRB.CreateIntToPtr(pLoc, IRB.getInt8PtrTy());
      Value* varName 
        = ConstantDataArray::getString(IRB.getContext(), "s0");
      Value *ptrVarName = IRB.CreateAlloca(varName->getType());
      IRB.CreateStore(varName, ptrVarName);
      ptrVarName = IRB.CreatePointerCast(ptrVarName, IRB.getInt8PtrTy());
      Value *valSize = IRB.getInt32(target_size);
      IRB.CreateCall(MakeSymbolicFC, {addr, valSize, ptrVarName});
    }
    // taint it
    int Taint = 0;
    for (auto EI : DICT->getElements()) {
      auto EDIT = dyn_cast<DIType>(EI);
      assert(EDIT != nullptr);
      uint64_t bits = EDIT->getSizeInBits();
      Type *CT;
      if (bits == 32) {
        CT = IRB.getInt32Ty();
      } else if (bits == 64) {
        CT = IRB.getInt64Ty();
      } else if (bits == 16) {
        CT = IRB.getInt16Ty();
      } else if (bits == 8) {
        CT = IRB.getInt8Ty();
      } else {
        klee_error("unsupported type");
      }
      Value *TT = IRB.getInt32(Taint * 0x01000000);
      ++Taint;
      if (Taint > 0xff) {
        klee_error("Register persistent taint too big");
      }
      Value *Size = IRB.getInt32(DL->getTypeAllocSize(CT));
      Value *Offset = IRB.CreateIntToPtr(
        IRB.getInt32(TargetStructLoc + EDIT->getOffsetInBits() / 8),
        IRB.getInt8PtrTy());
      IRB.CreateCall(SetPersistTaintFC, {TT, Offset, Size});
      IRB.CreateCall(SetTaintFC, {TT, Offset, Size});
    }
  }
}

void FuncSymbolizePass::createParamsFor(Function *TargetF, IRBuilder<> &IRB,
                                        std::vector<ParamCell*> &results)
{
  results.clear();
  size_t NumArgs = TargetF->arg_size();
  for (size_t i = 0; i < NumArgs; ++i) {
    ParamCell *PC = new ParamCell();
    PC->ParamType = TargetF->getArg(i)->getType();
    results.push_back(PC);
  }

  std::stack<ParamCell*> WorkStack;
  for (size_t i = NumArgs; i > 0; --i) {
    WorkStack.push(results[i - 1]);
  }

  while (!WorkStack.empty()) {
    ParamCell *PC = WorkStack.top();
    WorkStack.pop();

    switch (PC->ParamType->getTypeID()) {
      case Type::TypeID::StructTyID: {
        if (!(PC->parent && PC->depth == 0)) {
          if (!PC->ParamType->getStructName().equals(PeripheralPlaceholder)) {
            PC->val = IRB.CreateAlloca(PC->ParamType);
          } else {
            PC->val = IRB.CreateIntToPtr(IRB.getInt32(TargetStructLoc),
                                         PC->ParamType->getPointerTo());
          }
        }
        unsigned int NumElements = PC->ParamType->getStructNumElements();
        for (unsigned int i = 0; i < NumElements; ++i) {
          ParamCell *NPC = new ParamCell();
          PC->child.push_back(NPC);
          NPC->parent = PC;
          NPC->ParamType = PC->ParamType->getStructElementType(i);
          NPC->idx = i;
        }
        for (unsigned int i = NumElements; i > 0; --i) {
          WorkStack.push(PC->child[i - 1]);
        }
        break;
      }
      case Type::TypeID::IntegerTyID: {
        if (!(PC->parent && PC->depth == 0)) {
          // For now, we intuitively treat integer pointers as buffers.
          // Maybe we can do beter based on both names and types?
          if (PC->depth == 1) {
            PC->val
              = IRB.CreateAlloca(PC->ParamType,
                                 ConstantInt::get(IRB.getInt32Ty(),
                                                  HEURISTIC_BUFFER_LENGTH));
            PC->isBuffer = true;
          } else {
            PC->val = IRB.CreateAlloca(PC->ParamType);
            if (PC->depth > 1) {
              std::string TypeName;
              raw_string_ostream OS(TypeName);
              PC->ParamType->print(OS);
              klee_warning(
                "A pointer parameter of depth %d to type \'%s\' "
                "could be problematic", PC->depth, TypeName.c_str());
            }
          }
        }
        break;
      }
      case Type::TypeID::PointerTyID: {
        PC->depth += 1;
        PC->ParamType = PC->ParamType->getPointerElementType();
        WorkStack.push(PC);
        break;
      }
      default: {
        std::string ErrorMsg;
        raw_string_ostream OS(ErrorMsg);
        OS << "Unhandled parameter type in function "
           << TargetF->getName() << ": ";
        PC->ParamType->print(OS);
        klee_warning_once(TargetF, "%s", ErrorMsg.c_str());
        delete PC;
        break;
      }
    }
  }
}

static int symidx = 1;
// static std::string PeriphSymbolName = "";

void FuncSymbolizePass::makeSymbolic(IRBuilder<> &IRB,
                                     std::vector<ParamCell*> &results)
{
  std::stack<ParamCell*> WorkStack;
  for (auto root : results) {
    WorkStack.push(root);
    while (!WorkStack.empty()) {
      ParamCell *PC = WorkStack.top();
      WorkStack.pop();
      if (!PC) {
        continue;
      }
      if (PC->val) {
        if (PC->ParamType->isStructTy() &&
            PC->ParamType->getStructName().equals(PeripheralPlaceholder))
        {
          continue;
        }
        std::string SymbolName = "s" + std::to_string(symidx);
        ++symidx;
        Value *addr = IRB.CreatePointerCast(PC->val, IRB.getInt8PtrTy());
        Value* varName 
          = ConstantDataArray::getString(IRB.getContext(), SymbolName);
        Value *ptrVarName = IRB.CreateAlloca(varName->getType());
        IRB.CreateStore(varName, ptrVarName);
        ptrVarName = IRB.CreatePointerCast(ptrVarName, IRB.getInt8PtrTy());
        int allocSize = DL->getTypeAllocSize(PC->ParamType);
        if (PC->isBuffer) {
          allocSize *= HEURISTIC_BUFFER_LENGTH;
          GuessedBuffers.push_back(std::make_pair(addr, allocSize));
        }
        Value *valSize = IRB.getInt32(allocSize);
        IRB.CreateCall(MakeSymbolicFC, {addr, valSize, ptrVarName});
      }
      std::size_t NumChild = PC->child.size();
      for (std::size_t i = NumChild; i > 0; --i) {
        WorkStack.push(PC->child[i - 1]);
      }
    }
  }
}

void FuncSymbolizePass::prepFunctionPtr(Module &M, Function *TargetF, 
                                        IRBuilder<> &IRB,
                                        std::vector<ParamCell*> &results)
{
  int selector_idx = 0;
  std::vector<std::pair<BasicBlock*, std::set<StructOffset>>> FptrUses;
  Value *Zero = IRB.getInt32(0);
  for (auto &B : *TargetF) {
    for (auto &I : B) {
      if (!isa<CallInst>(&I)) {
        continue;
      }
      auto CI = cast<CallInst>(&I);
      auto CO = CI->getCalledOperand();
      if (isa<Function>(CO)) {
        continue;
      }
      auto PI = CI->getPrevNonDebugInstruction();
      std::set<StructOffset> PrevSet;
      while (PI) {
        if (!isa<StoreInst>(PI)) {
          PI = PI->getPrevNonDebugInstruction();
          continue;
        }
        auto SI = cast<StoreInst>(PI);
        Value *VO = SI->getValueOperand();
        Type *VOT = VO->getType();
        if (!VOT->isPointerTy() ||
            !VOT->getPointerElementType()->isFunctionTy())
        {
          PI = PI->getPrevNonDebugInstruction();
          continue;
        }
        trackFunctionPtrPlaceholder(SI->getPointerOperand(), PrevSet);
        PI = PI->getPrevNonDebugInstruction();
      }
      std::set<StructOffset> NowSet;
      trackFunctionPtrPlaceholder(CO, NowSet);
      // remove those having been set before
      if (!PrevSet.empty()) {
        for (auto it = NowSet.begin(); it != NowSet.end(); ) {
          if (PrevSet.find(*it) != PrevSet.end()) {
            it = NowSet.erase(it);
          } else {
            ++it;
          }
        }
      }
      FptrUses.push_back(std::make_pair(&B, std::move(NowSet)));
    }
  }
  std::set<StructOffset> SetOffsetsAll;
  std::deque<BasicBlock*> WL;
  for (auto &US : FptrUses) {
    if (US.second.empty()) {
      continue;
    }
    WL.push_back(US.first);
    while (!WL.empty()) {
      auto BB =  WL.front();
      WL.pop_front();
      for (auto itb = BB->rbegin(); itb != BB->rend(); ++itb) {
        auto &I = *itb;
        if (!isa<StoreInst>(&I)) {
          continue;
        }
        StoreInst *SI = cast<StoreInst>(&I);
        Value *VO = SI->getValueOperand();
        Type *VOT = VO->getType();
        if (!VOT->isPointerTy() ||
            !VOT->getPointerElementType()->isFunctionTy())
        {
          continue;
        }
        std::set<StructOffset> LocalPrev;
        trackFunctionPtrPlaceholder(SI->getPointerOperand(), LocalPrev);
        if (!LocalPrev.empty()) {
          for (auto its = US.second.begin(); its != US.second.end(); ) {
            if (LocalPrev.find(*its) != LocalPrev.end()) {
              its = US.second.erase(its);
            } else {
              ++its;
            }
          }
        }
        if (US.second.empty()) {
          break;
        }
      }
      if (US.second.empty()) {
        WL.clear();
        break;
      } else {
        for (auto PB : predecessors(BB)) {
          WL.push_back(PB);
        }
      }
    }
    for (auto &SO : US.second) {
      SetOffsetsAll.insert(SO);
    }
  }

  for (auto &SO : SetOffsetsAll) {
    std::vector<Constant*> possibleFuncs;
    if (PtrFunction.find(SO) == PtrFunction.end()) {
      continue;
    }
    for (auto &FS : PtrFunction.at(SO)) {
      auto f = M.getFunction(FS);
      if (f) {
        possibleFuncs.push_back(f);
      }
    }
    if (possibleFuncs.size() == 0) {
      continue;
    }
    Value *Selector = IRB.CreateAlloca(IRB.getInt32Ty());
    // symbolize it
    std::string SymbolName = "f" + std::to_string(selector_idx);
    ++selector_idx;
    Value *addr = IRB.CreatePointerCast(Selector, IRB.getInt8PtrTy());
    Value* varName 
      = ConstantDataArray::getString(IRB.getContext(), SymbolName);
    Value *ptrVarName = IRB.CreateAlloca(varName->getType());
    IRB.CreateStore(varName, ptrVarName);
    ptrVarName = IRB.CreatePointerCast(ptrVarName, IRB.getInt8PtrTy());
    int allocSize = DL->getTypeAllocSize(IRB.getInt32Ty());
    Value *valSize = IRB.getInt32(allocSize);
    IRB.CreateCall(MakeSymbolicFC, {addr, valSize, ptrVarName});
    // choose a value
    Selector = IRB.CreateLoad(IRB.getInt32Ty(), Selector);
    Selector = IRB.CreateURem(Selector, IRB.getInt32(possibleFuncs.size()));
    // store different values
    bool okFlag = false;
    std::stack<ParamCell*> WorkStack;
    for (auto root : results) {
      WorkStack.push(root);
      while (!WorkStack.empty()) {
        ParamCell *PC = WorkStack.top();
        WorkStack.pop();
        if (!PC) {
          continue;
        }
        if (PC->ParamType->isStructTy() && 
            PC->ParamType->getStructName().equals(SO.TypeName))
        {
          Value *PH;
          if (PC->val) {
            PH = IRB.CreateGEP(PC->ParamType, PC->val,
                                      {Zero, IRB.getInt32(SO.Offset)});
          } else {
            std::stack<ParamCell*> parents;
            ParamCell *P = PC;
            while (P->parent && !P->parent->val) {
              P = P->parent;
              parents.push(P);
            }
            assert(P->parent && P->parent->val);
            ParamCell *Top = P->parent;
            std::vector<Value*> IdxVec;
            IdxVec.push_back(Zero);
            while (!parents.empty()) {
              P = parents.top();
              parents.pop();
              IdxVec.push_back(IRB.getInt32(P->idx));
            }
            IdxVec.push_back(IRB.getInt32(SO.Offset));
            PH = IRB.CreateGEP(Top->ParamType, Top->val, IdxVec);
          }
          auto DummyF = IRB.GetInsertBlock()->getParent();
          auto DefaultBB = BasicBlock::Create(IRB.getContext(),
                                              "default_branch", DummyF);
          auto CSI = IRB.CreateSwitch(Selector, DefaultBB, possibleFuncs.size());
          unsigned pf_idx = 0;
          for (auto PF: possibleFuncs) {
            std::string BranchName = "branch_" + std::to_string(pf_idx);
            auto BranchBB = BasicBlock::Create(IRB.getContext(), BranchName,
                                               DummyF, DefaultBB);
            CSI->addCase(IRB.getInt32(pf_idx), BranchBB);
            ++pf_idx;
            IRB.SetInsertPoint(BranchBB);
            IRB.CreateStore(PF, PH);
            IRB.CreateBr(DefaultBB);
          }
          IRB.SetInsertPoint(DefaultBB);
          okFlag = true;
          break;
        }
        std::size_t NumChild = PC->child.size();
        for (std::size_t i = NumChild; i > 0; --i) {
          WorkStack.push(PC->child[i - 1]);
        }
      }
      if (okFlag) {
        break;
      }
    }
    if (!okFlag) {
      klee_warning_once(0, "Failed to initialize function pointer");
    }
  }
}

void FuncSymbolizePass::setTaint(IRBuilder<> &IRB,
                                 std::vector<ParamCell*> &results)
{
  std::stack<ParamCell*> WorkStack;
  int Taint = 0;
  // peripheral is persistently tainted
  // for (auto root : results) {
  //   WorkStack.push(root);
  //   while (!WorkStack.empty()) {
  //     ParamCell *PC = WorkStack.top();
  //     WorkStack.pop();
  //     if (!PC) {
  //       continue;
  //     }
  //     if (PC->ParamType->isStructTy() &&
  //         PC->ParamType->getStructName().equals(PeripheralPlaceholder))
  //     {
  //       for (auto Child : PC->child) {
  //         Value *TT = IRB.getInt32(Taint * 0x01000000);
  //         ++Taint;
  //         if (Taint > 0xff) {
  //           klee_error("Register persistent taint too big");
  //         }
  //         Value *Size
  //           = IRB.getInt32(DL->getTypeAllocSize(Child->ParamType));
  //         Value *Offset;
  //         if (PC->val) {
  //           Offset = IRB.CreateGEP(PC->ParamType, PC->val,
  //                                 {Zero, IRB.getInt32(Child->idx)});
  //         } else {
  //           std::stack<ParamCell*> parents;
  //           ParamCell *P = PC;
  //           while (P->parent && !P->parent->val) {
  //             P = P->parent;
  //             parents.push(P);
  //           }
  //           assert(P->parent && P->parent->val);
  //           ParamCell *Top = P->parent;
  //           std::vector<Value*> IdxVec;
  //           IdxVec.push_back(Zero);
  //           while (!parents.empty()) {
  //             P = parents.top();
  //             parents.pop();
  //             IdxVec.push_back(IRB.getInt32(P->idx));
  //           }
  //           Offset = IRB.CreateGEP(Top->ParamType, Top->val, IdxVec);
  //         }
  //         Value *Addr = IRB.CreatePointerCast(Offset, IRB.getInt8PtrTy());
  //         IRB.CreateCall(SetPersistTaintFC, {TT, Addr, Size});
  //         IRB.CreateCall(SetTaintFC, {TT, Addr, Size});
  //       }
  //     }
  //     std::size_t NumChild = PC->child.size();
  //     for (std::size_t i = NumChild; i > 0; --i) {
  //       WorkStack.push(PC->child[i - 1]);
  //     }
  //   }
  // }
  // buffers are temporarily tainted
  Taint = 1;
  for (auto &BF : GuessedBuffers) {
    Value *TT = IRB.getInt32(Taint * 0x00010000);
    Taint += 1;
    if (Taint > 0xff) {
      klee_error("Buffer taint too big");
    }
    IRB.CreateCall(SetTaintFC, {TT, BF.first, IRB.getInt32(BF.second)});
  }
}

void FuncSymbolizePass::issueCallToTarget(Function *TargetF, IRBuilder<> &IRB,
                                          std::vector<ParamCell*> &results)
{
  // first prepare inner states
  std::stack<ParamCell*> WorkStack;
  Constant *Zero = IRB.getInt32(0);
  for (auto root : results) {
    WorkStack.push(root);
    while (!WorkStack.empty()) {
      ParamCell *PC = WorkStack.top();
      WorkStack.pop();
      for (auto Child : PC->child) {
        WorkStack.push(Child);
        if (Child->val) {
          assert(Child->depth > 0);
          int tmp = Child->depth - 1;
          Value *FinalValue = Child->val;
          while (tmp > 0) {
            Value *PtrToValue = IRB.CreateAlloca(FinalValue->getType());
            IRB.CreateStore(FinalValue, PtrToValue);
            FinalValue = PtrToValue;
            --tmp;
          }
          Value *FinalValuePlaceholder
            = IRB.CreateGEP(PC->ParamType, PC->val,
                            {Zero, IRB.getInt32(Child->idx)});
          IRB.CreateStore(FinalValue, FinalValuePlaceholder);
        }
      }
    }
  }
  // then outter states
  std::vector<Value*> RealParams;
  for (auto root : results) {
    assert(root->val);
    if (root->depth == 0) {
      RealParams.push_back(IRB.CreateLoad(root->ParamType, root->val));
    } else {
      int tmp = root->depth - 1;
      Value *FinalValue = root->val;
      while (tmp > 0) {
        Value *PtrToValue = IRB.CreateAlloca(FinalValue->getType());
        IRB.CreateStore(FinalValue, PtrToValue);
        FinalValue = PtrToValue;
        --tmp;
      }
      RealParams.push_back(FinalValue);
    }
  }
  // handle return value
  Value *retVal = IRB.CreateCall(TargetF->getFunctionType(),
                                 TargetF, RealParams);
  switch (retVal->getType()->getTypeID()) {
    case Type::TypeID::VoidTyID: {
      break;
    }
    case Type::TypeID::IntegerTyID: {
      Value *ptrRetVal = IRB.CreateAlloca(retVal->getType());
      IRB.CreateStore(retVal, ptrRetVal);
      fRetVal
        = std::make_pair(IRB.CreatePointerCast(ptrRetVal, IRB.getInt8PtrTy()),
                         DL->getTypeAllocSize(retVal->getType()));
      // GuessedBuffers.push_back(
      //   std::make_pair(IRB.CreatePointerCast(ptrRetVal, IRB.getInt8PtrTy()),
      //                  DL->getTypeAllocSize(retVal->getType())));
      break;
    }
    default: {
      std::string ErrorMsg;
      raw_string_ostream OS(ErrorMsg);
      OS << "Unhandled return type: ";
      retVal->getType()->print(OS);
      klee_warning("%s", ErrorMsg.c_str());
      break;
    }
  }
}

void FuncSymbolizePass::collectTaint(IRBuilder<> &IRB,
                                     std::vector<ParamCell*> &results,
                                     const std::string &FName)
{
  for (auto P : GuessedBuffers) {
    IRB.CreateCall(GetTaintFC, {P.first, IRB.getInt32(P.second)});
  }
  // collect return value when we should
  if (OkValuesMap.find(FName) != OkValuesMap.end()) {
    auto Ptr = fRetVal.first;
    auto RetType = IRB.getInt32Ty();
    IRB.CreateCall(GetRetValFC, {IRB.CreateLoad(RetType, Ptr)});
  }
  GuessedBuffers.clear();
}

bool FuncSymbolizePass::runOnModule(Module &M) {
  if (TargetStruct.empty()) {
    klee_warning("Peripheral placeholder is absent.");
  }

  if (TargetStructLoc == 0) {
    klee_error("Must specify target peripheral address");
  }

  PeripheralPlaceholder = "struct." + TargetStruct;

  if (TopLevelFunctions.empty()) {
    klee_warning("No top-level functions, skip instrumentation");
    return false;
  }

  DL = &M.getDataLayout();
  ctx = &M.getContext();

  IRBuilder<> IRBM(*ctx);

  MakeSymbolicFC = M.getOrInsertFunction("klee_make_symbolic",
                                         IRBM.getVoidTy(),
                                         IRBM.getInt8PtrTy(),
                                         IRBM.getInt32Ty(),
                                         IRBM.getInt8PtrTy());
  SetTaintFC = M.getOrInsertFunction("klee_set_taint",
                                     IRBM.getVoidTy(),
                                     IRBM.getInt32Ty(),
                                     IRBM.getInt8PtrTy(),
                                     IRBM.getInt32Ty());
  SetPersistTaintFC = M.getOrInsertFunction("klee_set_persist_taint",
                                            IRBM.getVoidTy(),
                                            IRBM.getInt32Ty(),
                                            IRBM.getInt8PtrTy(),
                                            IRBM.getInt32Ty());
  GetTaintFC = M.getOrInsertFunction("klee_get_taint_internal",
                                     IRBM.getVoidTy(),
                                     IRBM.getInt8PtrTy(),
                                     IRBM.getInt32Ty());
  GetRetValFC = M.getOrInsertFunction("klee_get_return_value",
                                      IRBM.getVoidTy(),
                                      IRBM.getInt32Ty());
  AllocFixFC = M.getOrInsertFunction("klee_define_fixed_object",
                                     IRBM.getVoidTy(),
                                     IRBM.getInt32Ty(),
                                     IRBM.getInt32Ty());

  bool changed = false;
  for (auto TFName : TopLevelFunctions) {
    std::string DummyTFName = "__perry_dummy_" + TFName;
    if (M.getFunction(DummyTFName)) {
      continue;
    }
    if (!M.getFunction(TFName)) {
      klee_warning(
        "Failed to locate function \'%s\' when instrumenting, ignore",
        TFName.c_str());
      continue;
    }
    FunctionCallee DummyFC = M.getOrInsertFunction(DummyTFName,
                                                   IRBM.getVoidTy());
    Function *DummyF = dyn_cast<Function>(DummyFC.getCallee());
    IRBuilder<> IRBF(DummyF->getContext());
    BasicBlock *bb = BasicBlock::Create(IRBF.getContext(), "entry", DummyF);
    IRBF.SetInsertPoint(bb);
    Function *TargetF = M.getFunction(TFName);
    // generate
    // symbolize all global variables
    symbolizeGlobals(IRBF, M);
    // prepare other peripherals used
    createPeriph(IRBF, M);
    // create params for
    std::vector<ParamCell*> results;
    createParamsFor(TargetF, IRBF, results);
    // process results
    symidx = 1;
    // PeriphSymbolName.clear();
    // 1. make all allocated memory region symbolic
    makeSymbolic(IRBF, results);
    FunctionToSymbolName->insert(std::make_pair(TFName, "s0"));
    // klee_message("%s: Symbol Name of Registers is \'%s\'",
    //              TFName.c_str(), PeriphSymbolName.c_str());
    // 2. prepare function pointers if used
    prepFunctionPtr(M, TargetF, IRBF, results);
    // 3. (persistently) taint register regions
    setTaint(IRBF, results);
    // 4. call the target function
    issueCallToTarget(TargetF, IRBF, results);
    // 5. collect taint after symbolic execution
    collectTaint(IRBF, results, TFName);
    // then return
    IRBF.CreateRetVoid();
    for (auto root : results) {
      delete root;
    }
    changed = true;
  }

  return changed;
}