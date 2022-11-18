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
symbolizeValue(IRBuilder<> &IRB, Value *Var, const std::string &Name,
               uint32_t Size) {
  Value *addr;
  Type *varType = Var->getType();
  if (varType->isIntegerTy()) {
    addr = IRB.CreateIntToPtr(Var, IRB.getInt8PtrTy());
  } else {
    assert(varType->isPointerTy());
    addr = IRB.CreatePointerCast(Var, IRB.getInt8PtrTy());
  }
  Value *varName = ConstantDataArray::getString(IRB.getContext(), Name);
  Value *ptrVarName = IRB.CreateAlloca(varName->getType());
  IRB.CreateStore(varName, ptrVarName);
  ptrVarName = IRB.CreatePointerCast(ptrVarName, IRB.getInt8PtrTy());
  auto varSize = IRB.getInt32(Size);
  IRB.CreateCall(MakeSymbolicFC, {addr, varSize, ptrVarName});
}

void FuncSymbolizePass::
symbolizeGlobals(llvm::IRBuilder<> &IRB, llvm::Module &M) {
  int gIdx = 0;
  for (auto &G : M.globals()) {
    if (G.isConstant()) {
      continue;
    }
    auto valueType = G.getValueType();
    switch (valueType->getTypeID()) {
      case Type::TypeID::IntegerTyID: {
        // symbolize it
        std::string symbolName = "g" + std::to_string(gIdx);
        gIdx += 1;
        symbolizeValue(IRB, &G, symbolName, DL->getTypeAllocSize(valueType));
        break;
      }
      case Type::TypeID::StructTyID: {
        // symbolize it first
        std::string symbolName = "g" + std::to_string(gIdx);
        gIdx += 1;
        symbolizeValue(IRB, &G, symbolName, DL->getTypeAllocSize(valueType));
        // deal with members
        ParamCell ParentCell;
        ParentCell.ParamType = valueType;
        ParentCell.depth = 1;
        ParentCell.val = &G;
        unsigned num_elements = valueType->getStructNumElements();
        for (unsigned i = 0; i < num_elements; ++i) {
          Type *member_type = valueType->getStructElementType(i);
          ParamCell *PC = new ParamCell();
          PC->ParamType = member_type;
          PC->idx = i;
          PC->parent = &ParentCell;
          if (createCellsFrom(IRB, PC)) {
            ParentCell.child.push_back(PC);
            // try symbolize it
            symbolizeFrom(IRB, PC);
          } else {
            delete PC;
          }
        }
        fillCellInner(IRB, &ParentCell);
        break;
      }
      default: {
        std::string err_msg;
        raw_string_ostream OS(err_msg);
        OS << "Unsupported value type when symbolizing globals: ";
        valueType->print(OS);
        OS << ", ignore";
        klee_warning("%s", err_msg.c_str());
        break;
      }
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
    symbolizeValue(IRB, pAddr, SymbolName, PeriphSizeList[i]);
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
      symbolizeValue(IRB, pLoc, "s0", target_size);
    }
    // taint it
    int Taint = 0;
    for (auto EI : DICT->getElements()) {
      auto EDIT = dyn_cast<DIType>(EI);
      assert(EDIT != nullptr);
      uint64_t bits = EDIT->getSizeInBits();
      Type *CT = nullptr;
      if (bits == 32) {
        CT = IRB.getInt32Ty();
      } else if (bits == 64) {
        CT = IRB.getInt64Ty();
      } else if (bits == 16) {
        CT = IRB.getInt16Ty();
      } else if (bits == 8) {
        CT = IRB.getInt8Ty();
      } else {
        if (EDIT->getName().contains_insensitive("reserved")) {
          continue;
        }
        // array?
        if (isa<DIDerivedType>(EDIT)) {
          DIDerivedType *DIDT = cast<DIDerivedType>(EDIT);
          if (DIDT->getBaseType()) {
            if (isa<DICompositeType>(DIDT->getBaseType())) {
              auto MayBeArrayTy = cast<DICompositeType>(DIDT->getBaseType());
              if (MayBeArrayTy->getTag() == dwarf::DW_TAG_array_type) {
                if (MayBeArrayTy->getElements().size() == 1 &&
                    MayBeArrayTy->getElements()[0]->getTag() == dwarf::DW_TAG_subrange_type) {
                  DISubrange *DIS = cast<DISubrange>(MayBeArrayTy->getElements()[0]);
                  auto CB = DIS->getRawCountNode();
                  if (CB && isa<ConstantAsMetadata>(CB)) {
                    auto *MD = cast<ConstantAsMetadata>(CB);
                    auto *CI = dyn_cast<ConstantInt>(MD->getValue());
                    unsigned num_elem = CI->getZExtValue();
                    unsigned array_size = MayBeArrayTy->getSizeInBits();
                    unsigned elem_size = array_size / num_elem;
                    if (elem_size == 32) {
                      CT = IRB.getInt32Ty();
                    } else if (elem_size == 16) {
                      CT = IRB.getInt16Ty();
                    } else if (elem_size == 8) {
                      CT = IRB.getInt8Ty();
                    } else if (elem_size == 64) {
                      CT = IRB.getInt64Ty();
                    }
                    if (CT) {
                      CT = ArrayType::get(CT, num_elem);
                    }
                  }
                }
              }
            }
          }
        }
        if (!CT) {
          std::string err_msg;
          raw_string_ostream OS(err_msg);
          EDIT->print(OS);
          klee_error("unsupported type: %s", err_msg.c_str());
        }
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

bool FuncSymbolizePass::
createCellsFrom(IRBuilder<> &IRB, ParamCell *root) {
  std::stack<ParamCell*> WorkStack;
  WorkStack.push(root);
  bool ret = true;

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
      case Type::TypeID::ArrayTyID: {
        if (!(PC->parent && PC->depth == 0)) {
          klee_error("Symbolizing standalone arrays is not supported");
        }
        break;
      }
      case Type::TypeID::FunctionTyID: {
        std::string err_msg;
        raw_string_ostream OS(err_msg);
        OS << "Function pointer will be null: ";
        PC->ParamType->print(OS);
        klee_warning("%s", err_msg.c_str());
        break;
      }
      default: {
        std::string ErrorMsg;
        raw_string_ostream OS(ErrorMsg);
        OS << "Unhandled type when creating cells: ";
        PC->ParamType->print(OS);
        klee_warning_once(ErrorMsg.c_str(), "%s", ErrorMsg.c_str());
        // do not delete PC when it's root
        if (PC == root) {
          ret = false;
        } else {
          delete PC;
        }
        break;
      }
    }
  }

  return ret;
}

void FuncSymbolizePass::createParamsFor(Function *TargetF, IRBuilder<> &IRB,
                                        std::vector<ParamCell*> &results)
{
  results.clear();
  size_t NumArgs = TargetF->arg_size();
  for (size_t i = 0; i < NumArgs; ++i) {
    ParamCell *PC = new ParamCell();
    PC->ParamType = TargetF->getArg(i)->getType();
    PC->idx = i;
    if (createCellsFrom(IRB, PC)) {
      results.push_back(PC);
    } else {
      delete PC;
      results.push_back(nullptr);
    }
  }
}

static int symidx = 1;
// static std::string PeriphSymbolName = "";

void FuncSymbolizePass::symbolizeFrom(IRBuilder<> &IRB, ParamCell *root) {
  if (!root) {
    return;
  }
  std::stack<ParamCell*> WorkStack;
  WorkStack.push(root);
  while (!WorkStack.empty()) {
    ParamCell *PC = WorkStack.top();
    WorkStack.pop();
    if (!PC) {
      continue;
    }
    if (PC->val) {
      if (PC->ParamType->isStructTy() &&
          PC->ParamType->getStructName().equals(PeripheralPlaceholder)) {
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

void FuncSymbolizePass::symbolizeParams(IRBuilder<> &IRB,
                                        std::vector<ParamCell*> &results)
{
  std::stack<ParamCell*> WorkStack;
  for (auto root : results) {
    if (!root->val) {
      continue;
    }
    symbolizeFrom(IRB, root);
  }
}

void FuncSymbolizePass::prepFunctionPtr(Module &M, Function *TargetF, 
                                        IRBuilder<> &IRB,
                                        std::vector<ParamCell*> &results)
{
  int selector_idx = 0;
  std::vector<std::pair<BasicBlock*, std::set<StructOffset>>> FptrUses;
  Value *Zero = IRB.getInt32(0);
  // collect used function ptrs on all called functions
  CallGraph &MCG = *CG;
  std::set<Function*> calledFuncs;
  std::vector<Function*> FWL;
  FWL.push_back(TargetF);
  while (!FWL.empty()) {
    Function *cur_func = FWL.back();
    FWL.pop_back();
    if (cur_func->isDeclaration()) {
      continue;
    }
    if (calledFuncs.find(cur_func) != calledFuncs.end()) {
      continue;
    }
    calledFuncs.insert(cur_func);
    CallGraphNode *CGN = MCG[cur_func];
    for (auto &SF : *CGN) {
      Function *next_func = SF.second->getFunction();
      if (next_func) {
        FWL.push_back(next_func);
      }
    }
  }
  for (auto TF : calledFuncs) {
    for (auto &B : *TF) {
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
  }

  std::set<StructOffset> SetOffsetsAll;
  std::deque<BasicBlock*> WL;
  for (auto &US : FptrUses) {
    if (US.second.empty()) {
      continue;
    }
    WL.push_back(US.first);
    std::set<BasicBlock*> visited;
    while (!WL.empty()) {
      auto BB =  WL.front();
      WL.pop_front();
      if (visited.find(BB) != visited.end()) {
        continue;
      }
      visited.insert(BB);
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
    bool isGlobal = (SO.TypeName.find("_perry_global_") != std::string::npos);
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
    symbolizeValue(IRB, Selector, SymbolName,
                   DL->getTypeAllocSize(IRB.getInt32Ty()));
    // choose a value
    Selector = IRB.CreateLoad(IRB.getInt32Ty(), Selector);
    Selector = IRB.CreateURem(Selector, IRB.getInt32(possibleFuncs.size()));
    // store different values
    if (isGlobal) {
      Value *PH = M.getNamedGlobal(SO.TypeName.substr(14));
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
    } else {
      bool okFlag = false;
      std::stack<ParamCell*> WorkStack;
      for (auto root : results) {
        if (!root->val) {
          continue;
        }
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
              IdxVec.push_back(IRB.getInt32(PC->idx));
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
}

void FuncSymbolizePass::setTaint(IRBuilder<> &IRB,
                                 std::vector<ParamCell*> &results)
{
  std::stack<ParamCell*> WorkStack;
  int Taint = 1;

  for (auto &BF : GuessedBuffers) {
    Value *TT = IRB.getInt32(Taint * 0x00010000);
    Taint += 1;
    if (Taint > 0xff) {
      klee_error("Buffer taint too big");
    }
    IRB.CreateCall(SetTaintFC, {TT, BF.first, IRB.getInt32(BF.second)});
  }
}

void FuncSymbolizePass::
fillCellInner(llvm::IRBuilder<> &IRB, ParamCell *root) {
  if (!root->val) {
    return;
  }
  std::stack<ParamCell*> WorkStack;
  Constant *Zero = IRB.getInt32(0);
  WorkStack.push(root);
  while (!WorkStack.empty()) {
    ParamCell *PC = WorkStack.top();
    WorkStack.pop();
    for (auto Child : PC->child) {
      WorkStack.push(Child);
      Value *FinalValue = nullptr;
      if (Child->val) {
        assert(Child->depth > 0);
        int tmp = Child->depth - 1;
        FinalValue = Child->val;
        while (tmp > 0) {
          Value *PtrToValue = IRB.CreateAlloca(FinalValue->getType());
          IRB.CreateStore(FinalValue, PtrToValue);
          FinalValue = PtrToValue;
          --tmp;
        }
      } else {
        if (Child->ParamType->isFunctionTy()) {
          assert(Child->depth == 1);
          FinalValue 
            = ConstantPointerNull::get(Child->ParamType->getPointerTo());
        }
      }
      if (!FinalValue) {
        continue;
      }
      Value *FinalValuePlaceholder;
      if (PC->val) {
        FinalValuePlaceholder 
          = IRB.CreateGEP(PC->ParamType, PC->val,
                          {Zero, IRB.getInt32(Child->idx)});
      } else {
        // track backward
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
        IdxVec.push_back(IRB.getInt32(PC->idx));
        IdxVec.push_back(IRB.getInt32(Child->idx));
        FinalValuePlaceholder = IRB.CreateGEP(Top->ParamType, Top->val,
                                              IdxVec);
      }
      IRB.CreateStore(FinalValue, FinalValuePlaceholder);
    }
  }
}

void FuncSymbolizePass::
fillParamas(IRBuilder<> &IRB, std::vector<ParamCell*> &results) {
  // first prepare inner states
  std::stack<ParamCell*> WorkStack;
  // Constant *Zero = IRB.getInt32(0);
  for (auto root : results) {
    if (!root->val) {
      continue;
    }
    fillCellInner(IRB, root);
  }
}

void FuncSymbolizePass::callTarget(Function *TargetF, IRBuilder<> &IRB,
                                   std::vector<ParamCell*> &results)
{
  // then outter states
  std::vector<Value*> RealParams;
  for (auto root : results) {
    if (!root->val) {
      assert(root->ParamType->isFunctionTy() && root->depth == 1);
      RealParams.push_back(
        ConstantPointerNull::get(root->ParamType->getPointerTo()));
      continue;
    }
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
}

void FuncSymbolizePass::
applyDataHeuristic(IRBuilder<> &IRB, std::vector<ParamCell*> &results,
                   Function *TargetF) {
  for (auto root : results) {
    if (!root) {
      continue;
    }
    if (root->ParamType->isIntegerTy() && root->depth == 0) {
      auto SP = TargetF->getSubprogram();
      if (SP->getNumOperands() >= 8) {
        auto RN = SP->getRetainedNodes();
        unsigned num_nodes = RN.size();
        if (num_nodes != 0) {
          if (root->idx < (int)num_nodes) {
            auto Node = RN[root->idx];
            auto LV = dyn_cast<DILocalVariable>(Node);
            if (LV) {
              if (LV->getName().contains_insensitive("data")) {
                // taint it!
                Value *addr = IRB.CreatePointerCast(root->val, IRB.getInt8PtrTy());
                int allocSize = DL->getTypeAllocSize(root->ParamType);
                GuessedBuffers.push_back(std::make_pair(addr, allocSize));
                continue;
              }
            }
          }
        }
      }
      for (auto &B : *TargetF) {
        for (auto &I : B) {
          DbgDeclareInst *DI = dyn_cast<DbgDeclareInst>(&I);
          if (!DI) {
            continue;
          }
          auto LV = DI->getVariable();
          if (!LV->isParameter()) {
            continue;
          }
          if ((int)LV->getArg() == root->idx + 1) {
            if (LV->getName().contains_insensitive("data")) {
              // taint it!
              Value *addr = IRB.CreatePointerCast(root->val, IRB.getInt8PtrTy());
              int allocSize = DL->getTypeAllocSize(root->ParamType);
              GuessedBuffers.push_back(std::make_pair(addr, allocSize));
              continue;
            }
          }
        }
      }
    }
  }
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
  if (CG) {
    delete CG;
  }
  CG = new CallGraph(M);

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
    // let's go
    symidx = 1;
    // symbolize all global variables
    symbolizeGlobals(IRBF, M);
    // prepare other peripherals used
    createPeriph(IRBF, M);
    // create params for
    std::vector<ParamCell*> results;
    createParamsFor(TargetF, IRBF, results);
    // fail early
    bool fail_early = false;
    for (auto root : results) {
      if (!root) {
        fail_early = true;
        break;
      }
    }
    if (fail_early) {
      klee_warning("Failed to invoke %s", TFName.c_str());
      IRBF.CreateRetVoid();
      // DummyF->eraseFromParent();
      // IRBF.ClearInsertionPoint();
      for (auto root : results) {
        if (root) {
          delete root;
        }
      }
      continue;
    }
    // process results
    // PeriphSymbolName.clear();
    // make all allocated memory region in params symbolic
    symbolizeParams(IRBF, results);
    FunctionToSymbolName->insert(std::make_pair(TFName, "s0"));
    applyDataHeuristic(IRBF, results, TargetF);
    // taint buffers
    setTaint(IRBF, results);
    // fill in params
    fillParamas(IRBF, results);
    // prepare function pointers if used
    prepFunctionPtr(M, TargetF, IRBF, results);
    // call the target function & process the return value
    callTarget(TargetF, IRBF, results);
    // collect taint after symbolic execution
    collectTaint(IRBF, results, TFName);
    GuessedBuffers.clear();
    // then return
    IRBF.CreateRetVoid();
    for (auto root : results) {
      delete root;
    }
    changed = true;
  }

  return changed;
}

FuncSymbolizePass::~FuncSymbolizePass() {
  if (CG) {
    delete CG;
    CG = nullptr;
  }
}