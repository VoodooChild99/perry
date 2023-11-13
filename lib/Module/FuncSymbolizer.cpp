#include "Passes.h"
#include "klee/Support/ErrorHandling.h"
#include "klee/Support/OptionCategories.h"
#include "klee/Perry/PerryExpr.h"
#include "klee/Perry/PerryEthInfo.h"
#include "klee/Perry/PerryTimerInfo.h"
#include "klee/Perry/PerryDMAInfo.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/CFG.h"

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

static std::vector<std::string> null_ptr_structs = {
  "edma_tcd"
};

static inline bool shouldStructPtrBeNull(llvm::StringRef name) {
  for (auto &n : null_ptr_structs) {
    if (name.contains(n)) {
      return true;
    }
  }
  return false;
}

enum DataType {
  PARAMETER,
  STRUCT,
};

static const std::set<std::string> dma_keywords = {
  "DMA",
};

bool FuncSymbolizePass::isDMAPeriph(llvm::StringRef name) {
  for (auto &k : dma_keywords) {
    if (name.startswith_insensitive(k)) {
      return true;
    }
  }
  return false;
}

struct DMADataDesc {
  DataType ty;
  std::string sname;
  int data_idx;
};

static const std::vector<DMADataDesc> dma_config_src_data = {
  DMADataDesc {
    .ty = STRUCT,
    .sname = "edma_transfer_config",
    .data_idx = 0,
  },
  DMADataDesc {
    .ty = PARAMETER,
    .sname = "HAL_DMA_Start",
    .data_idx = 1,
  },
};

static const std::vector<DMADataDesc> dma_config_dst_data = {
  DMADataDesc {
    .ty = STRUCT,
    .sname = "edma_transfer_config",
    .data_idx = 1,
  },
  DMADataDesc {
    .ty = PARAMETER,
    .sname = "HAL_DMA_Start",
    .data_idx = 2,
  },
};

static const std::vector<DMADataDesc> dma_config_count_data = {
  DMADataDesc {
    .ty = STRUCT,
    .sname = "edma_transfer_config",
    .data_idx = 7,
  },
  DMADataDesc {
    .ty = PARAMETER,
    .sname = "HAL_DMA_Start",
    .data_idx = 3,
  },
};

static const std::vector<std::string> dma_init_func = {
  "EDMA_Init",
  "HAL_DMA_Init",
};

struct DMAChannelDef {
  std::string sname;
  int start_padding;
  int end_padding;
};

static const std::vector<DMAChannelDef> dma_channel_struct = {
  DMAChannelDef {
    .sname = "DMA_Channel_TypeDef",
    .start_padding = 0,
    .end_padding = 4,
  },
};

static inline const DMAChannelDef* isDMAChannelTy(llvm::StringRef name) {
  for (auto &CS : dma_channel_struct) {
    if (name.contains(CS.sname)) {
      return &CS;
    }
  }
  return nullptr;
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
  // filter out UBSAN globals
  std::set<GlobalVariable*> UBSanGlobals;
  unsigned num_ubsan_globals = 0;
  while (true) {
    for (auto &G : M.globals()) {
      if (G.isConstant()) {
        continue;
      }
      for (auto U : G.users()) {
        // 1) the user is also a global, and the user is used by a UBSAN global
        if (isa<GlobalVariable>(U) &&
            (UBSanGlobals.find(&G) != UBSanGlobals.end())) {
          UBSanGlobals.insert(cast<GlobalVariable>(U));
        }
        // 2) the user is a CallInst, and the called function is a UBSAN handler
        if (llvm::ConstantExpr *CE = dyn_cast<llvm::ConstantExpr>(U)) {
          if (!CE->isCast()) {
            continue;
          }
          auto destTy = CE->getType();
          if (destTy->isPointerTy() &&
              destTy->getPointerElementType()->isIntegerTy(8)) {
            if (CE->hasOneUser()) {
              auto CEU = *(CE->user_begin());
              if (CallInst *CI = dyn_cast<CallInst>(CEU)) {
                if (CI->getCalledFunction()
                    ->getName().startswith("__ubsan_handle_")) {
                  UBSanGlobals.insert(&G);
                }
              }
            }
          }
        }
      }
    }
    if (num_ubsan_globals != UBSanGlobals.size()) {
      num_ubsan_globals = UBSanGlobals.size();
    } else {
      break;
    }
  }
  int gIdx = 0;
  for (auto &G : M.globals()) {
    if (G.isConstant()) {
      continue;
    }
    if (UBSanGlobals.find(&G) != UBSanGlobals.end()) {
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

void FuncSymbolizePass::taintPeriph(IRBuilder<> &IRB, Module &M, DIType *ty,
                                    int &taint, unsigned &offset) {
  //
  if (ty->getName().contains_insensitive("reserved")) {
    return;
  }
  switch (ty->getMetadataID()) {
    case Metadata::DICompositeTypeKind: {
      DICompositeType *CT = cast<DICompositeType>(ty);
      switch (CT->getTag()) {
        case dwarf::DW_TAG_structure_type: {
          for (auto elm : CT->getElements()) {
            auto ElmTy = dyn_cast<DIType>(elm);
            assert(ElmTy != nullptr);
            taintPeriph(IRB, M, ElmTy, taint, offset);
          }
          break;
        }
        case dwarf::DW_TAG_union_type: {
          // select the largest member
          auto elms = CT->getElements();
          if (elms.size() == 1) {
            taintPeriph(IRB, M, dyn_cast<DIType>(elms[0]), taint, offset);
          } else {
            unsigned max_index = 0;
            unsigned index = 0;
            unsigned max_size = dyn_cast<DIType>(elms[0])->getSizeInBits();
            for (auto elm : elms) {
              if (dyn_cast<DIType>(elm)->getSizeInBits() > max_size) {
                max_size = dyn_cast<DIType>(elm)->getSizeInBits();
                max_index = index;
              }
              ++index;
            }
            taintPeriph(IRB, M, dyn_cast<DIType>(elms[max_index]), taint, offset);
          }
          break;
        }
        case dwarf::DW_TAG_array_type: {
          if (CT->getElements().size() != 1) {
            break;
          }
          DISubrange *sub_range = dyn_cast<DISubrange>(CT->getElements()[0]);
          if (!sub_range) {
            break;
          }
          auto count = dyn_cast_or_null<ConstantAsMetadata>(sub_range->getRawCountNode());
          if (!count) {
            break;
          }
          unsigned num_elem = dyn_cast<ConstantInt>(count->getValue())->getZExtValue();
          auto ElmTy = CT->getBaseType();
          unsigned array_size = (CT->getSizeInBits() >> 3);
          unsigned elm_size = array_size / num_elem;
          unsigned tmp_offset = offset;
          for (unsigned i = 0; i < num_elem; ++i) {
            taintPeriph(IRB, M, ElmTy, taint, tmp_offset);
            tmp_offset += elm_size;
          }
          break;
        }
        default: {
          std::string err_msg;
          raw_string_ostream OS(err_msg);
          CT->print(OS);
          klee_error("unhandled tag: %s", err_msg.c_str());
        }
      }
      break;
    }
    case Metadata::DIDerivedTypeKind: {
      DIDerivedType *DT = cast<DIDerivedType>(ty);
      switch (DT->getTag()) {
        case dwarf::DW_TAG_member: {
          unsigned tmp_offset = offset;
          tmp_offset += (DT->getOffsetInBits()  >> 3);
          taintPeriph(IRB, M, DT->getBaseType(), taint, tmp_offset);
          break;
        }
        case dwarf::DW_TAG_const_type:
        case dwarf::DW_TAG_volatile_type:
        case dwarf::DW_TAG_typedef: {
          taintPeriph(IRB, M, DT->getBaseType(), taint, offset);
          break;
        }
        default: {
          std::string err_msg;
          raw_string_ostream OS(err_msg);
          DT->print(OS);
          klee_error("unhandled tag: %s", err_msg.c_str());
        }
      }
      break;
    }
    case Metadata::DIBasicTypeKind: {
      DIBasicType *BT = cast<DIBasicType>(ty);
      unsigned elm_size = (BT->getSizeInBits() >> 3);
      if (elm_size == 1 || elm_size == 2 || elm_size == 4 || elm_size == 8) {
        Value *TT = IRB.getInt32(taint * 0x01000000);
        ++taint;
        if (taint > 0xff) {
          klee_error("Register persistent taint too big");
        }
        Value *Size = IRB.getInt32(elm_size);
        Value *Offset = IRB.CreateIntToPtr(
          IRB.getInt32(TargetStructLoc + offset),
          IRB.getInt8PtrTy());
        IRB.CreateCall(SetPersistTaintFC, {TT, Offset, Size});
        IRB.CreateCall(SetTaintFC, {TT, Offset, Size});
      }
      break;
    }
    default: {
      std::string err_msg;
      raw_string_ostream OS(err_msg);
      ty->print(OS);
      klee_error("unhandled metadata: %s", err_msg.c_str());
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
    TargetPeriphStructSize = DICT->getSizeInBits() / 8;

    if (!target_periph_created) {
      Value *pLoc = IRB.getInt32(TargetStructLoc);
      unsigned target_size = TargetStructSize;
      // allocate it
      unsigned s_size = DICT->getSizeInBits() / 8;
      target_size = std::max(target_size, s_size);
      IRB.CreateCall(AllocFixFC, {pLoc, IRB.getInt32(target_size)});
      // symbolize it
      symbolizeValue(IRB, pLoc, "s0", target_size);
    }
    // taint it
    int Taint = 0;
    unsigned offset = 0;
    taintPeriph(IRB, M, DICT, Taint, offset);
    if (TargetIsDMA) {
      // taint channels, if any
      unsigned sz = (DICT->getSizeInBits() >> 3);
      DICT = nullptr;
      const DMAChannelDef *DCD = nullptr;
      for (auto &CS : dma_channel_struct) {
        for (auto DIT : DIF.types()) {
          if (DIT->getMetadataID() == Metadata::DIDerivedTypeKind) {
            auto DT = cast<DIDerivedType>(DIT);
            auto BT = DT->getBaseType();
            if (!BT) {
              continue;
            }
            if (BT->getMetadataID() == Metadata::DICompositeTypeKind) {
              if (DT->getName().contains(CS.sname)) {
                DICT = cast<DICompositeType>(BT);
                DCD = &CS;
              }
            }
          } else if (DIT->getMetadataID() == Metadata::DICompositeTypeKind) {
            if (DIT->getName().contains(CS.sname)) {
              DICT = cast<DICompositeType>(DIT);
              DCD = &CS;
            }
          }
          if (DICT) {
            break;
          }
        }
        if (DICT) {
          break;
        }
      }
      if (DICT) {
        offset = sz;
        sz = (DICT->getSizeInBits() >> 3);
        while (1) {
          offset += DCD->start_padding;
          if (offset >= TargetStructSize) {
            break;
          }
          taintPeriph(IRB, M, DICT, Taint, offset);
          offset += sz;
          offset += DCD->end_padding;
        }
      }
    }
  }
}

Value* FuncSymbolizePass::
createDMAChannel(IRBuilder<> &IRB, ParamCell *PC, const void *Cdef) {
  if (!TargetIsDMA) {
    return ConstantPointerNull::get(PointerType::get(PC->ParamType, 0));
  }
  const DMAChannelDef *Channel = (const DMAChannelDef*)Cdef;
  std::vector<Value*> channel_bases;
  unsigned cur_size = TargetPeriphStructSize + Channel->start_padding;
  unsigned channel_size = DL->getTypeAllocSize(PC->ParamType);
  while (true) {
    cur_size += channel_size;
    if (cur_size <= TargetStructSize) {
      channel_bases.push_back(
        IRB.CreateIntToPtr(IRB.getInt32(TargetStructLoc + cur_size - channel_size),
                           PC->ParamType->getPointerTo()));
      cur_size += (Channel->end_padding + Channel->start_padding);
    } else {
      break;
    }
  }
  if (channel_bases.empty()) {
    return ConstantPointerNull::get(PointerType::get(PC->ParamType, 0));
  }
  if (channel_bases.size() == 1) {
    return channel_bases[0];
  }  
  // use a selector to select the channel
  Value *sel = IRB.CreateAlloca(IRB.getInt32Ty());
  std::string SymbolName = "sel";
  symbolizeValue(IRB, sel, SymbolName,
                 DL->getTypeAllocSize(IRB.getInt32Ty()));
  // choose a value
  sel = IRB.CreateLoad(IRB.getInt32Ty(), sel);
  sel = IRB.CreateURem(sel, IRB.getInt32(channel_bases.size()));
  auto DummyF = IRB.GetInsertBlock()->getParent();
  auto entryBB = IRB.GetInsertBlock();
  auto DefaultBB = BasicBlock::Create(IRB.getContext(),
                                      "default_channel_branch", DummyF);
  auto CSI = IRB.CreateSwitch(sel, DefaultBB, channel_bases.size());
  unsigned pf_idx = 0;
  std::vector<std::pair<Value*, BasicBlock *>> bb_values;
  for (auto cb: channel_bases) {
    std::string BranchName = "branch_channel_" + std::to_string(pf_idx);
    auto BranchBB = BasicBlock::Create(IRB.getContext(), BranchName,
                                       DummyF, DefaultBB);
    CSI->addCase(IRB.getInt32(pf_idx), BranchBB);
    ++pf_idx;
    IRB.SetInsertPoint(BranchBB);
    IRB.CreateBr(DefaultBB);
    bb_values.emplace_back(std::make_pair(cb, BranchBB));
  }
  IRB.SetInsertPoint(DefaultBB);
  PHINode *phi = IRB.CreatePHI(PC->ParamType->getPointerTo(), channel_bases.size());
  for (auto &bv : bb_values) {
    phi->addIncoming(bv.first, bv.second);
  }
  phi->addIncoming(
    ConstantPointerNull::get(PointerType::get(PC->ParamType, 0)), entryBB);
  return phi;
}

bool FuncSymbolizePass::
createCellsFrom(IRBuilder<> &IRB, ParamCell *root) {
  std::stack<ParamCell*> WorkStack;
  WorkStack.push(root);
  bool ret = true;
  const DMAChannelDef *Cdef = nullptr;

  while (!WorkStack.empty()) {
    ParamCell *PC = WorkStack.top();
    WorkStack.pop();

    switch (PC->ParamType->getTypeID()) {
      case Type::TypeID::StructTyID: {
        if (!(PC->parent && PC->depth == 0)) {
          if (!PC->ParamType->getStructName().equals(PeripheralPlaceholder)) {
            if (PC->depth == 1 &&
                shouldStructPtrBeNull(PC->ParamType->getStructName())) {
              PC->val = ConstantPointerNull::get(PointerType::get(PC->ParamType, 0));
              break;
            } else if (PC->depth == 1 &&
                       (Cdef = isDMAChannelTy(PC->ParamType->getStructName())))  {
              PC->val = createDMAChannel(IRB, PC, Cdef);
              break;
            } else {
              PC->val = IRB.CreateAlloca(PC->ParamType);
            }
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
          (PC->ParamType->getStructName().equals(PeripheralPlaceholder) ||
           shouldStructPtrBeNull(PC->ParamType->getStructName()) ||
           isDMAChannelTy(PC->ParamType->getStructName()))) {
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

      if (TargetIsDMA) {
        if (PC->depth == 0 && !PC->parent) {
          // param
          for (auto &conf : dma_config_src_data) {
            if (conf.ty == STRUCT) {
              continue;
            }
            if (conf.data_idx != PC->idx) {
              continue;
            }
            if (!ParamF->getName().equals(conf.sname)) {
              continue;
            }
            perry_dma_info->src_symbol.insert(
              std::make_pair(ParamF->getName().str(),
                            PerryDMAInfo::SymbolInfo(SymbolName, 0)));
          }

          for (auto &conf : dma_config_dst_data) {
            if (conf.ty == STRUCT) {
              continue;
            }
            if (conf.data_idx != PC->idx) {
              continue;
            }
            if (!ParamF->getName().equals(conf.sname)) {
              continue;
            }
            perry_dma_info->dst_symbol.insert(
              std::make_pair(ParamF->getName().str(),
                            PerryDMAInfo::SymbolInfo(SymbolName, 0)));
          }

          for (auto &conf : dma_config_count_data) {
            if (conf.ty == STRUCT) {
              continue;
            }
            if (conf.data_idx != PC->idx) {
              continue;
            }
            if (!ParamF->getName().equals(conf.sname)) {
              continue;
            }
            perry_dma_info->cnt_symbol.insert(
              std::make_pair(ParamF->getName().str(),
                            PerryDMAInfo::SymbolInfo(SymbolName, 0)));
          }
        }

        if (PC->ParamType->isStructTy()) {
          StringRef sname = PC->ParamType->getStructName();
          for (auto &conf : dma_config_src_data) {
            if (conf.ty == PARAMETER) {
              continue;
            }
            if (!sname.contains(conf.sname)) {
              continue;
            }
            auto Sty = cast<StructType>(PC->ParamType);
            auto mem_offset = DL->getStructLayout(Sty)->getElementOffset(conf.data_idx);
            perry_dma_info->src_symbol.insert(
              std::make_pair(ParamF->getName().str(),
                            PerryDMAInfo::SymbolInfo(SymbolName, mem_offset)));
          }

          for (auto &conf : dma_config_dst_data) {
            if (conf.ty == PARAMETER) {
              continue;
            }
            if (!sname.contains(conf.sname)) {
              continue;
            }
            auto Sty = cast<StructType>(PC->ParamType);
            auto mem_offset = DL->getStructLayout(Sty)->getElementOffset(conf.data_idx);
            perry_dma_info->dst_symbol.insert(
              std::make_pair(ParamF->getName().str(),
                            PerryDMAInfo::SymbolInfo(SymbolName, mem_offset)));
          }

          for (auto &conf : dma_config_count_data) {
            if (conf.ty == PARAMETER) {
              continue;
            }
            if (!sname.contains(conf.sname)) {
              continue;
            }
            auto Sty = cast<StructType>(PC->ParamType);
            auto mem_offset = DL->getStructLayout(Sty)->getElementOffset(conf.data_idx);
            perry_dma_info->cnt_symbol.insert(
              std::make_pair(ParamF->getName().str(),
                            PerryDMAInfo::SymbolInfo(SymbolName, mem_offset)));
          }
        }
      }
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
  // if the target is a DMA peripheral, call the initialization function first
  if (TargetIsDMA && DMAInitFC.getCallee() && TargetF != DMAInitFC.getCallee()) {
    // analyze the params first
    std::vector<Value *> dma_init_params;
    unsigned idx = 0;
    bool share_same_param = false;
    for (auto ty : DMAInitFC.getFunctionType()->params()) {
      for (unsigned pid = 0; pid < TargetF->getFunctionType()->getNumParams(); ++pid) {
        if (ty == TargetF->getFunctionType()->getParamType(pid)) {
          share_same_param = true;
          break;
        }
      }
      if (share_same_param) {
        break;
      }
    }
    if (share_same_param) {
      for (auto ty : DMAInitFC.getFunctionType()->params()) {
        bool found_same_type = false;
        for (unsigned pid = 0; pid < TargetF->getFunctionType()->getNumParams(); ++pid) {
          if (ty == TargetF->getFunctionType()->getParamType(pid)) {
            dma_init_params.push_back(RealParams[pid]);
            found_same_type = true;
            break;
          }
        }
        if (!found_same_type) {
          // we must create it now
          ParamCell *PC = new ParamCell();
          PC->ParamType = ty;
          PC->idx = idx;
          if (createCellsFrom(IRB, PC)) {
            ParamF = cast<Function>(DMAInitFC.getCallee());
            symbolizeFrom(IRB, PC);
            fillCellInner(IRB, PC);
            if (!PC->val) {
              assert(PC->ParamType->isFunctionTy() && PC->depth == 1);
              dma_init_params.push_back(
                ConstantPointerNull::get(PC->ParamType->getPointerTo()));
            } else if (PC->depth == 0) {
              dma_init_params.push_back(IRB.CreateLoad(PC->ParamType, PC->val));
            } else {
              int tmp = PC->depth - 1;
              Value *FinalValue = PC->val;
              while (tmp > 0) {
                Value *PtrToValue = IRB.CreateAlloca(FinalValue->getType());
                IRB.CreateStore(FinalValue, PtrToValue);
                FinalValue = PtrToValue;
                --tmp;
              }
              dma_init_params.push_back(FinalValue);
            }
          } else {
            assert(PC->ParamType->isFunctionTy() && PC->depth == 1);
            dma_init_params.push_back(
              ConstantPointerNull::get(PC->ParamType->getPointerTo()));
          }
        }
        ++idx;
      }
      IRB.CreateCall(DMAInitFC, dma_init_params);
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

void FuncSymbolizePass::collectTaint(IRBuilder<> &IRB)
{
  for (auto P : GuessedBuffers) {
    IRB.CreateCall(GetTaintFC, {P.first, IRB.getInt32(P.second)});
  }
}

void FuncSymbolizePass::collectRetVal(IRBuilder<> &IRB,
                                     const std::string &FName)
{
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

static const std::set<std::string> eth_keywords = {
  "enet", "eth"
};

static const std::set<std::string> function_sigs = {
  "ENET_", "HAL_ETH_"
};

static const std::set<std::string> desc_struct_names = {
  "ETH_DMADescTypeDef", "enet_rx_bd_struct", "enet_tx_bd_struct"
};

static const std::set<std::string> rx_desc_struct_names = {
  "ETH_DMADescTypeDef", "enet_rx_bd_struct"
};

static const std::set<std::string> tx_desc_struct_names = {
  "ETH_DMADescTypeDef", "enet_tx_bd_struct"
};

struct FrameTxFunc {
  std::string name;
  int len_param_idx;
};

struct FrameRxFunc {
  std::string name;
  std::string recv_buf_struct_name;
  std::string recv_len_struct_name;
  int buf_idx;
  int len_idx;
};

static const std::vector<FrameTxFunc> frame_tx_funcs = {
  FrameTxFunc {.name = "HAL_ETH_TransmitFrame", .len_param_idx = 1},
  FrameTxFunc {.name = "ENET_SendFrame", .len_param_idx = 3},
};

static const std::vector<FrameRxFunc> frame_rx_funcs = {
  FrameRxFunc {
    .name = "HAL_ETH_GetReceivedFrame",
    .recv_buf_struct_name = "ETH_DMARxFrameInfos",
    .recv_len_struct_name = "ETH_DMARxFrameInfos",
    .buf_idx = 4,
    .len_idx = 3,
  },
  FrameRxFunc {
    .name = "ENET_GetRxFrame",
    .recv_buf_struct_name = "enet_buffer_struct",
    .recv_len_struct_name = "enet_rx_frame_struct",
    .buf_idx = 0,
    .len_idx = 1,
  },
};

struct RxDescConfig {
  std::string struct_name;
  int rxbuf_size_idx;
};

static const std::vector<RxDescConfig> rx_desc_configs = {
  RxDescConfig {.struct_name = "enet_buffer_config", .rxbuf_size_idx = 2},
};

bool FuncSymbolizePass::isEthernetPeriph(StringRef name) {
  for (auto &k : eth_keywords) {
    if (name.startswith_insensitive(k)) {
      return true;
    }
  }
  return false;
}

void FuncSymbolizePass::analyzeDescRegs(Module &M) {
  std::stack<Function *>candidate_funcs;
  std::set<Function *>analyzed_funcs;
  std::set<int> desc_reg_offsets;
  const DataLayout &DL = M.getDataLayout();
  for (auto &F : TopLevelFunctions) {
    Function *TF = M.getFunction(F);
    if (TF) {
      candidate_funcs.push(TF);
    }
  }
  CallGraph &MCG = *CG;
  while (!candidate_funcs.empty()) {
    Function *TF = candidate_funcs.top();
    candidate_funcs.pop();
    if (analyzed_funcs.find(TF) != analyzed_funcs.end()) {
      continue;
    }
    // push called functions into queue
    CallGraphNode *CGN = MCG[TF];
    for (auto &SF : *CGN) {
      Function *next_func = SF.second->getFunction();
      if (next_func) {
        candidate_funcs.push(next_func);
      }
    }
    analyzed_funcs.insert(TF);
    // analyze it
    if (TF->isDeclaration() || TF->isDebugInfoForProfiling()) {
      continue;
    }
    bool qualified = false;
    for (auto & FS : function_sigs) {
      if (TF->getName().startswith(FS)) {
        qualified = true;
        break;
      }
    }
    if (!qualified) {
      continue;
    }
    std::vector<StoreInst *> store_insts;
    for (auto &B : *TF) {
      for (auto &I : B) {
        StoreInst *SI = dyn_cast<StoreInst>(&I);
        if (SI) {
          store_insts.push_back(SI);
        }
      }
    }
    for (auto SI : store_insts) {
      Value *val = SI->getValueOperand();
      Value *ptr = SI->getPointerOperand();
      // check if ptr is extracted from target peripheral
      if (!isa<GetElementPtrInst>(ptr)) {
        continue;
      }
      GetElementPtrInst *GEPI = cast<GetElementPtrInst>(ptr);
      Type *SrcElemTy = GEPI->getPointerOperandType()->getPointerElementType();
      if (!SrcElemTy->isStructTy() ||
          !SrcElemTy->getStructName().equals(PeripheralPlaceholder)) {
        continue;
      }
      if (GEPI->getNumIndices() != 2) {
        return;
      }
      ConstantInt *CI = cast<ConstantInt>(GEPI->getOperand(2));
      if (!CI) {
        return;
      }
      StructType *TargetStructTy = cast<StructType>(SrcElemTy);
      if (!isa<PtrToIntInst>(val)) {
        continue;
      }
      PtrToIntInst *PTII = cast<PtrToIntInst>(val);
      Type *valTy = PTII->getSrcTy()->getPointerElementType();
      if (!valTy->isStructTy()) {
        continue;
      }
      bool isDesc = false;
      for (auto &DN : desc_struct_names) {
        if (valTy->getStructName().contains(DN)) {
          isDesc = true;
          perry_eth_info->desc_struct_size = DL.getTypeAllocSize(valTy);
          break;
        }
      }
      if (!isDesc) {
        continue;
      }
      // bingo!
      desc_reg_offsets.insert(M.getDataLayout().getStructLayout(TargetStructTy)->getElementOffset(CI->getZExtValue()));
      errs() << "Found Desc Register: offset=" << M.getDataLayout().getStructLayout(TargetStructTy)->getElementOffset(CI->getZExtValue()) << "\n";
    }
  }
  perry_eth_info->rx_desc_reg_offset = *desc_reg_offsets.begin();
  perry_eth_info->tx_desc_reg_offset = *desc_reg_offsets.rbegin();
}

// is `SI` storing into structures in `TS`
static bool isStoreTargetStruct(StoreInst *SI, const std::set<std::string> &TS) {
  Value *ptr = SI->getPointerOperand();
  GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(ptr);
  if (!GEPI) {
    return false;
  }
  StructType *SrcElemTy = dyn_cast<StructType>(GEPI->getSourceElementType());
  if (!SrcElemTy) {
    return false;
  }
  bool qualified = false;
  for (auto &TN : TS) {
    if (SrcElemTy->getStructName().contains(TN)) {
      qualified = true;
    }
  }
  if (!qualified) {
    return false;
  }
  return true;
}

// is `LI` load from structures in `TS`
static bool isLoadTargetStruct(LoadInst *LI, const std::set<std::string> &TS) {
  Value *ptr = LI->getPointerOperand();
  GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(ptr);
  if (!GEPI) {
    return false;
  }
  StructType *SrcElemTy = dyn_cast<StructType>(GEPI->getSourceElementType());
  if (!SrcElemTy) {
    return false;
  }
  bool qualified = false;
  for (auto &TN : TS) {
    if (SrcElemTy->getStructName().contains(TN)) {
      qualified = true;
    }
  }
  if (!qualified) {
    return false;
  }
  return true;
}

// is `LI` load from structures in `TS`
static bool isLoadTargetStruct(LoadInst *LI, const std::set<std::string> &TS,
                               const DataLayout &DL, int &load_idx) {
  Value *ptr = LI->getPointerOperand();
  GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(ptr);
  if (!GEPI) {
    return false;
  }
  StructType *SrcElemTy = dyn_cast<StructType>(GEPI->getSourceElementType());
  if (!SrcElemTy) {
    return false;
  }
  bool qualified = false;
  for (auto &TN : TS) {
    if (SrcElemTy->getStructName().contains(TN)) {
      qualified = true;
    }
  }
  if (!qualified) {
    return false;
  }
  if (GEPI->getNumIndices() != 2) {
    return false;
  }
  ConstantInt *CI = dyn_cast<ConstantInt>(GEPI->getOperand(2));
  if (!CI) {
    return false;
  }
  load_idx = DL.getStructLayout(SrcElemTy)->getElementOffset(CI->getZExtValue());
  return true;
}

static bool isStoreTargetField(StoreInst *SI,
                               const std::string &Struct,
                               int field) {
  Value *ptr = SI->getPointerOperand();
  GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(ptr);
  if (!GEPI) {
    return false;
  }
  std::vector<Value *>indices;
  Type *SrcTy = GEPI->getSourceElementType();
  unsigned num_indices = GEPI->getNumIndices();
  bool check_field = false;
  for (unsigned i = 0; i < num_indices; ++i) {
    Value *ind = GEPI->getOperand(i + 1);
    if (check_field) {
      ConstantInt *CI = dyn_cast<ConstantInt>(ind);
      if (!CI) {
        return false;
      }
      if (CI->getZExtValue() == (uint64_t)field) {
        return true;
      }
      check_field = false;
    }
    indices.push_back(ind);
    StructType *ST = dyn_cast_or_null<StructType>(GEPI->getIndexedType(SrcTy, indices));
    if (!ST) {
      break;
    }
    if (ST->getName().contains(Struct)) {
      // check field
      check_field = true;
    }
  }
  return false;
}

static bool isLoadTargetField(LoadInst *LI,
                              const std::string &Struct,
                              int field) {
  Value *ptr = LI->getPointerOperand();
  GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(ptr);
  if (!GEPI) {
    return false;
  }
  std::vector<Value *>indices;
  Type *SrcTy = GEPI->getSourceElementType();
  unsigned num_indices = GEPI->getNumIndices();
  bool check_field = false;
  for (unsigned i = 0; i < num_indices; ++i) {
    Value *ind = GEPI->getOperand(i + 1);
    ConstantInt *CI = dyn_cast<ConstantInt>(ind);
    if (!CI) {
      return false;
    }
    if (check_field) {
      if (CI->getZExtValue() == (uint64_t)field) {
        return true;
      }
      check_field = false;
    }
    indices.push_back(ind);
    StructType *ST = dyn_cast_or_null<StructType>(GEPI->getIndexedType(SrcTy, indices));
    if (!ST) {
      break;
    }
    if (ST->getName().contains(Struct)) {
      // check field
      check_field = true;
    }
  }
  return false;
}

// how many bits in `dst` come from src
static bool isFromValue(Value *dst, Value *src, const DataLayout &DL,
                        int &num_bits, int &start_pos) {
  if (dst == src) {
    num_bits = DL.getTypeSizeInBits(src->getType());
    return true;
  }
  Instruction *I = dyn_cast<Instruction>(dst);
  if (!I) {
    return false;
  }
  switch (I->getOpcode()) {
    case Instruction::Add:
    case Instruction::Sub: {
      if (isFromValue(I->getOperand(0), src, DL, num_bits, start_pos)) {
        return true;
      }
      if (isFromValue(I->getOperand(1), src, DL, num_bits, start_pos)) {
        return true;
      }
      return false;
    }
    case Instruction::And: {
      if (isFromValue(I->getOperand(0), src, DL, num_bits, start_pos)) {
        ConstantInt *CI = dyn_cast<ConstantInt>(I->getOperand(1));
        if (CI) {
          num_bits = findLastSet(CI->getZExtValue()) - findFirstSet(CI->getZExtValue()) + 1;
        }
        return true;
      }
      if (isFromValue(I->getOperand(1), src, DL, num_bits, start_pos)) {
        ConstantInt *CI = dyn_cast<ConstantInt>(I->getOperand(0));
        if (CI) {
          num_bits = findLastSet(CI->getZExtValue()) - findFirstSet(CI->getZExtValue()) + 1;
        }
        return true;
      }
      return false;
    }
    case Instruction::LShr: {
      if (isFromValue(I->getOperand(0), src, DL, num_bits, start_pos)) {
        ConstantInt *CI = dyn_cast<ConstantInt>(I->getOperand(1));
        if (CI) {
          start_pos += CI->getZExtValue();
        }
        return true;
      }
      return false;
    }
    case Instruction::IntToPtr: {
      if (isFromValue(I->getOperand(0), src, DL, num_bits, start_pos)) {
        return true;
      }
      return false;
    }
    case Instruction::ZExt: {
      if (isFromValue(I->getOperand(0), src, DL, num_bits, start_pos)) {
        return true;
      }
      return false;
    }
    case Instruction::Trunc: {
      TruncInst *TI = cast<TruncInst>(I);
      if (isFromValue(TI->getOperand(0), src, DL, num_bits, start_pos)) {
        num_bits = TI->getDestTy()->getScalarSizeInBits();
        start_pos = 0;
        return true;
      }
      return false;
    }
    case Instruction::ICmp: {
      ICmpInst *CI = cast<ICmpInst>(I);
      Value *lhs = CI->getOperand(0);
      Value *rhs = CI->getOperand(1);
      if (isFromValue(lhs, src, DL, num_bits, start_pos) ||
          isFromValue(rhs, src, DL, num_bits, start_pos)) {
        return true;
      }
      return false;
    }
    default: {
      klee_warning("unhandled instruction when tracking value");
      I->print(errs()); errs() << "\n";
      return false;
    }
  }
  return false;
}

// express `dst` in the form of `src`
static ref<PerryExpr> constructExprUntil(Value *dst, Value *src,
                                         const DataLayout &DL,
                                         int ld_size, int ld_offset) {
  if (dst == src) {
    return PerryReadExpr::alloc("d", PerryConstantExpr::alloc(ld_size, ld_offset), ld_size);
  }
  if (isa<ConstantInt>(dst)) {
    ConstantInt *CI = cast<ConstantInt>(dst);
    return PerryConstantExpr::alloc(
      DL.getTypeAllocSizeInBits(CI->getType()), CI->getZExtValue());
  }
  Instruction *I = dyn_cast<Instruction>(dst);
  assert(I);
  switch (I->getOpcode()) {
    case Instruction::And: {
      return PerryAndExpr::alloc(
        constructExprUntil(I->getOperand(0), src, DL, ld_size, ld_offset),
        constructExprUntil(I->getOperand(1), src, DL, ld_size, ld_offset)
      );
    }
    case Instruction::ICmp: {
      ICmpInst *CI = cast<ICmpInst>(I);
      ref<PerryExpr> lhs = constructExprUntil(I->getOperand(0), src, DL, ld_size, ld_offset);
      ref<PerryExpr> rhs = constructExprUntil(I->getOperand(1), src, DL, ld_size, ld_offset);
      switch (CI->getPredicate()) {
        case CmpInst::ICMP_EQ: {
          return PerryEqExpr::alloc(lhs, rhs);
        }
        case CmpInst::ICMP_NE: {
          return PerryNeExpr::alloc(lhs, rhs);
        }
        case CmpInst::ICMP_SGT: {
          return PerrySgtExpr::alloc(lhs, rhs);
        }
        default: {
          klee_warning("unhandled predicate when constructing expr");
          CI->print(errs()); errs() << "\n";
          return 0;
        }
      }
    }
    default: {
      klee_warning("unhandled instruction when tracking value");
      I->print(errs()); errs() << "\n";
      return 0;
    }
  }
}

void FuncSymbolizePass::analyzeDescTxBufferLen(llvm::Module &M) {
  const DataLayout &DL = M.getDataLayout();
  for (auto &F : M) {
    for (auto &TF : frame_tx_funcs) {
      if (!F.getName().equals(TF.name)) {
        continue;
      }
      if (F.isDeclaration() || F.isDebugInfoForProfiling()) {
        continue;
      }
      for (auto &B : F) {
        for (auto &I : B) {
          StoreInst *SI = dyn_cast<StoreInst>(&I);
          if (!SI) {
            continue;
          }
          if (!isStoreTargetStruct(SI, tx_desc_struct_names)) {
            continue;
          }
          
          Value *val = SI->getValueOperand();
          if (isa<Constant>(val)) {
            continue;
          }
          int num_bits = 0, start_pos = 0;
          if (!isFromValue(val, F.getArg(TF.len_param_idx), DL, num_bits, start_pos)) {
            continue;
          }
          // bingo?
          GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(SI->getPointerOperand());
          StructType *SrcElemTy = dyn_cast<StructType>(GEPI->getSourceElementType());
          ConstantInt *CI = cast<ConstantInt>(GEPI->getOperand(2));
          TxBufLen.offset = DL.getStructLayout(SrcElemTy)->getElementOffset(CI->getZExtValue());
          TxBufLen.num_bits = num_bits;
          TxBufLen.start_bit = start_pos;
          errs() << "Found Tx Buffer Len: offset=" << TxBufLen.offset
                 << ", bits=" << TxBufLen.num_bits
                 << ", start_bit=" << TxBufLen.start_bit << "\n";
          perry_eth_info->desc_tx_buf_len.offset = TxBufLen.offset;
          perry_eth_info->desc_tx_buf_len.start_bit = TxBufLen.start_bit;
          perry_eth_info->desc_tx_buf_len.num_bits = TxBufLen.num_bits;
          break;
        }
      }
    }
  }
}

void FuncSymbolizePass::analyzeDescRxBufferLen(llvm::Module &M) {
  // if rx frame len is not at the same location of tx buffer len, we assume rx
  // buffer len overlap with tx buffer len. Otherwise, we assume rx buffer len
  // is stored in a register and try to locate that register
  const DataLayout &DL = M.getDataLayout();
  if (RxFrameLen == TxBufLen) {
    // register
    std::stack<Function *>candidate_funcs;
    std::set<Function *>analyzed_funcs;
    for (auto &F : TopLevelFunctions) {
      Function *TF = M.getFunction(F);
      if (TF) {
        candidate_funcs.push(TF);
      }
    }
    CallGraph &MCG = *CG;
    while (!candidate_funcs.empty()) {
      Function *TF = candidate_funcs.top();
      candidate_funcs.pop();
      if (analyzed_funcs.find(TF) != analyzed_funcs.end()) {
        continue;
      }
      // push called functions into queue
      CallGraphNode *CGN = MCG[TF];
      for (auto &SF : *CGN) {
        Function *next_func = SF.second->getFunction();
        if (next_func) {
          candidate_funcs.push(next_func);
        }
      }
      analyzed_funcs.insert(TF);
      // analyze it
      if (TF->isDeclaration() || TF->isDebugInfoForProfiling()) {
        continue;
      }
      bool qualified = false;
      for (auto & FS : function_sigs) {
        if (TF->getName().startswith(FS)) {
          qualified = true;
          break;
        }
      }
      if (!qualified) {
        continue;
      }
      std::vector<StoreInst *> store_insts;
      std::vector<LoadInst *> load_insts;
      for (auto &B : *TF) {
        for (auto &I : B) {
          StoreInst *SI = dyn_cast<StoreInst>(&I);
          if (SI) {
            store_insts.push_back(SI);
            continue;
          }
          LoadInst *LI = dyn_cast<LoadInst>(&I);
          if (!LI) {
            continue;
          }
          for (auto &rc : rx_desc_configs) {
            if (!isLoadTargetField(LI, rc.struct_name, rc.rxbuf_size_idx)) {
              continue;
            }
            load_insts.push_back(LI);
            break;
          }
        }
      }
      for (auto SI : store_insts) {
        Value *val = SI->getValueOperand();
        Value *ptr = SI->getPointerOperand();
        // check if ptr is extracted from target peripheral
        if (!isa<GetElementPtrInst>(ptr)) {
          continue;
        }
        GetElementPtrInst *GEPI = cast<GetElementPtrInst>(ptr);
        Type *SrcElemTy = GEPI->getPointerOperandType()->getPointerElementType();
        if (!SrcElemTy->isStructTy() ||
            !SrcElemTy->getStructName().equals(PeripheralPlaceholder)) {
          continue;
        }
        if (GEPI->getNumIndices() != 2) {
          return;
        }
        ConstantInt *CI = cast<ConstantInt>(GEPI->getOperand(2));
        if (!CI) {
          return;
        }
        StructType *TargetStructTy = cast<StructType>(SrcElemTy);
        // check if value is from rx buf config structures
        for (auto LI : load_insts) {
          int num_bits = 0, start_pos = 0;
          if (!isFromValue(val, LI, DL, num_bits, start_pos)) {
            continue;
          }
          // bingo!
          errs() << "Found Rx Buf Len Register: offset=" << M.getDataLayout().getStructLayout(TargetStructTy)->getElementOffset(CI->getZExtValue()) << "\n";
          perry_eth_info->desc_rx_buf_len_stored_in_reg = true;
          perry_eth_info->desc_rx_buf_len.reg_offset = M.getDataLayout().getStructLayout(TargetStructTy)->getElementOffset(CI->getZExtValue());
          break;
        }
      }
    }
  } else {
    RxBufLen = TxBufLen;
    perry_eth_info->desc_rx_buf_len_stored_in_reg = false;
    perry_eth_info->desc_rx_buf_len.f.offset = RxBufLen.offset;
    perry_eth_info->desc_rx_buf_len.f.start_bit = RxBufLen.start_bit;
    perry_eth_info->desc_rx_buf_len.f.num_bits = RxBufLen.num_bits;
  }
}

void FuncSymbolizePass::analyzeDescRxFrameLen(llvm::Module &M) {
  const DataLayout &DL = M.getDataLayout();
  for (auto &F : M) {
    for (auto &RF : frame_rx_funcs) {
      if (!F.getName().equals(RF.name)) {
        continue;
      }
      if (F.isDeclaration() || F.isDebugInfoForProfiling()) {
        continue;
      }
      std::vector<LoadInst *> load_insts;
      for (auto &B : F) {
        for (auto &I : B) {
          LoadInst *LI = dyn_cast<LoadInst>(&I);
          if (!LI) {
            continue;
          }
          if (!isLoadTargetStruct(LI, rx_desc_struct_names)) {
            continue;
          }
          load_insts.push_back(LI);
        }
      }

      for (auto &B : F) {
        for (auto &I : B) {
          StoreInst *SI = dyn_cast<StoreInst>(&I);
          if (!SI) {
            continue;
          }
          if (!isStoreTargetField(SI, RF.recv_len_struct_name, RF.len_idx)) {
            continue;
          }
          // track source
          Value *val = SI->getValueOperand();
          for (auto LI : load_insts) {
            int num_bits = 0, start_pos = 0;
            if (!isFromValue(val, LI, DL, num_bits, start_pos)) {
              continue;
            }
            rx_set_length_block = I.getParent();
            GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(LI->getPointerOperand());
            StructType *SrcElemTy = dyn_cast<StructType>(GEPI->getSourceElementType());
            ConstantInt *CI = cast<ConstantInt>(GEPI->getOperand(2));
            RxFrameLen.offset = DL.getStructLayout(SrcElemTy)->getElementOffset(CI->getZExtValue());
            RxFrameLen.num_bits = num_bits;
            RxFrameLen.start_bit = start_pos;
            errs() << "Found Rx Frame Len: offset=" << RxFrameLen.offset
                   << ", bits=" << RxFrameLen.num_bits
                   << ", start_pos=" << RxFrameLen.start_bit << "\n";
            perry_eth_info->desc_rx_frame_len.offset = RxFrameLen.offset;
            perry_eth_info->desc_rx_frame_len.start_bit = RxFrameLen.start_bit;
            perry_eth_info->desc_rx_frame_len.num_bits = RxFrameLen.num_bits;
            break;
          }
        }
      }
    }
  }
}

void FuncSymbolizePass::analyzeDescBuffer(llvm::Module &M) {
  const DataLayout &DL = M.getDataLayout();
  for (auto &F : M) {
    for (auto &RF : frame_rx_funcs) {
      if (!F.getName().equals(RF.name)) {
        continue;
      }
      if (F.isDeclaration() || F.isDebugInfoForProfiling()) {
        continue;
      }
      std::vector<LoadInst *> load_insts;
      for (auto &B : F) {
        for (auto &I : B) {
          LoadInst *LI = dyn_cast<LoadInst>(&I);
          if (!LI) {
            continue;
          }
          if (!isLoadTargetStruct(LI, rx_desc_struct_names)) {
            continue;
          }
          load_insts.push_back(LI);
        }
      }

      for (auto &B : F) {
        for (auto &I : B) {
          StoreInst *SI = dyn_cast<StoreInst>(&I);
          if (!SI) {
            continue;
          }
          if (!isStoreTargetField(SI, RF.recv_buf_struct_name, RF.buf_idx)) {
            continue;
          }
          // track source
          Value *val = SI->getValueOperand();
          for (auto LI : load_insts) {
            int num_bits = 0, start_pos = 0;
            if (!isFromValue(val, LI, DL, num_bits, start_pos)) {
              continue;
            }
            GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(LI->getPointerOperand());
            StructType *SrcElemTy = dyn_cast<StructType>(GEPI->getSourceElementType());
            ConstantInt *CI = cast<ConstantInt>(GEPI->getOperand(2));
            DescBuf.offset = DL.getStructLayout(SrcElemTy)->getElementOffset(CI->getZExtValue());
            DescBuf.num_bits = num_bits;
            DescBuf.start_bit = start_pos;
            errs() << "Found Desc Buffer: offset=" << DescBuf.offset
                   << ", num_bits=" << DescBuf.num_bits
                   << ", start_bit=" << DescBuf.start_bit << "\n";
            perry_eth_info->desc_buf.offset = DescBuf.offset;
            perry_eth_info->desc_buf.start_bit = DescBuf.start_bit;
            perry_eth_info->desc_buf.num_bits = DescBuf.num_bits;
            break;
          }
        }
      }
    }
  }
}

enum DescMemLayout {
  /* Unknown if not detected */
  Unknown,
  /* Load from descriptors*/
  RingBuffer,
  /* Continuous */
  Array,
};

void FuncSymbolizePass::analyzeDescMemLayout(llvm::Module &M) {
  const DataLayout &DL = M.getDataLayout();
  for (auto &F : M) {
    for (auto &RF : frame_rx_funcs) {
      if (!F.getName().equals(RF.name)) {
        continue;
      }
      if (F.isDeclaration() || F.isDebugInfoForProfiling()) {
        continue;
      }
      std::vector<LoadInst *> load_insts;
      for (auto &B : F) {
        for (auto &I : B) {
          LoadInst *LI = dyn_cast<LoadInst>(&I);
          if (!LI) {
            continue;
          }
          if (!isLoadTargetStruct(LI, rx_desc_struct_names)) {
            continue;
          }
          load_insts.push_back(LI);
        }
      }

      bool detected = false;
      
      // Ring Buffer
      for (auto &B : F) {
        for (auto &I : B) {
          StoreInst *SI = dyn_cast<StoreInst>(&I);
          if (!SI) {
            continue;
          }
          for (auto &rn : rx_desc_struct_names) {
            Type *PET = SI->getPointerOperand()->getType()->getPointerElementType();
            if (!PET->isPointerTy()) {
              continue;
            }
            StructType *ST = dyn_cast<StructType>(PET->getPointerElementType());
            if (!ST) {
              continue;
            }
            if (!ST->getName().contains(rn)) {
              continue;
            }
            // directly assign a typed pointer, track value
            Value *val = SI->getValueOperand();
            for (auto LI : load_insts) {
              int num_bits = 0, start_pos = 0;
              if (!isFromValue(val, LI, DL, num_bits, start_pos)) {
                continue;
              }
              GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(LI->getPointerOperand());
              StructType *SrcElemTy = dyn_cast<StructType>(GEPI->getSourceElementType());
              ConstantInt *CI = cast<ConstantInt>(GEPI->getOperand(2));
              errs() << "Descriptor Memory Layout is Ring Buffer: next=" << DL.getStructLayout(SrcElemTy)->getElementOffset(CI->getZExtValue())
                   << "\n";
              perry_eth_info->mem_layout = PerryEthInfo::DescMemoryLayout::RINGBUF;
              perry_eth_info->desc_next_desc.offset = DL.getStructLayout(SrcElemTy)->getElementOffset(CI->getZExtValue());
              perry_eth_info->desc_next_desc.start_bit = start_pos;
              perry_eth_info->desc_next_desc.num_bits = num_bits;
              detected = true;
            }
          }
        }
      }

      if (detected) {
        continue;
      }

      // Array?
      for (auto LI : load_insts) {
        Value *ptr = LI->getPointerOperand();
        GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(ptr);
        if (!GEPI) {
          continue;
        }
        if (GEPI->getNumIndices() != 2) {
          continue;
        }
        Value *idx1 = GEPI->getOperand(1);
        ConstantInt *CI = dyn_cast<ConstantInt>(idx1);
        if (!CI) {
          errs() << "Descriptor Memory Layout is Array\n";
          perry_eth_info->mem_layout = PerryEthInfo::DescMemoryLayout::ARRAY;
          detected = true;
          // TODO: detect marker of the last descriptor
          break;
        } else {
          // TODO: track the source ptr, good for now
        }
      }

      if (!detected) {
        errs() << "Failed to detect memory layout\n";
        perry_eth_info->mem_layout = PerryEthInfo::DescMemoryLayout::UNKNOWN;
      }
    }
  }
}

// collect continuous blocks until a conditional branch or return
static void collectContinuousBlocks(llvm::BasicBlock *start,
                                    std::set<llvm::BasicBlock *> &res) {
  BasicBlock *cur = start;
  while (true) {
    res.insert(cur);
    Instruction *I = cur->getTerminator();
    BranchInst *BI = dyn_cast<BranchInst>(I);
    if (BI) {
      if (BI->isConditional()) {
        break;
      }
      cur = BI->getSuccessor(0);
      continue;
    }
    ReturnInst *RI = dyn_cast<ReturnInst>(I);
    if (RI) {
      break;
    }
    klee_warning("Unhandled terminator in collectContinuousBlocks");
    I->print(errs()); errs() << "\n";
  }
}

void FuncSymbolizePass::analyzeDescConstraints(llvm::Module &M) {
  // in rx funcs, the out-most descriptor-related constraints
  const DataLayout &DL = M.getDataLayout();
  std::set<BasicBlock *> first_seg_bbs;
  for (auto &F : M) {
    for (auto &RF : frame_rx_funcs) {
      if (!F.getName().equals(RF.name)) {
        continue;
      }
      if (F.isDeclaration() || F.isDebugInfoForProfiling()) {
        continue;
      }
      DominatorTree DT(F);
      std::set<BasicBlock *> dominators;

      std::vector<std::pair<LoadInst *, int>> load_insts;
      for (auto &B : F) {
        for (auto &I : B) {
          LoadInst *LI = dyn_cast<LoadInst>(&I);
          if (!LI) {
            continue;
          }
          int offset;
          if (!isLoadTargetStruct(LI, rx_desc_struct_names, DL, offset)) {
            continue;
          }
          load_insts.emplace_back(std::make_pair(LI, offset));
        }
      }

      for (auto &B : F) {
        if (DT.properlyDominates(&B, rx_set_length_block)) {
          BranchInst *BI = dyn_cast<BranchInst>(B.getTerminator());
          if (!BI) {
            continue;
          }
          if (!BI->isConditional()) {
            continue;
          }
          // track condition source
          Value *cond = BI->getCondition();
          for (auto p : load_insts) {
            int num_bits = 0, start_pos = 0;
            LoadInst *LI = p.first;
            if (!isFromValue(cond, LI, DL, num_bits, start_pos)) {
              continue;
            }
            ICmpInst *CI = dyn_cast<ICmpInst>(cond);
            if (!CI) {
              continue;
            }
            ConstantInt *C = dyn_cast<ConstantInt>(CI->getOperand(1));
            if (!C) {
              continue;
            }
            dominators.insert(&B);
            break;
          }
        }
      }

      for (auto B : dominators) {
        BranchInst *BI = dyn_cast<BranchInst>(B->getTerminator());
        assert(BI);
        assert(BI->isConditional());
        // track condition source
        Value *cond = BI->getCondition();
        for (auto p : load_insts) {
          int num_bits = 0, start_pos = 0;
          LoadInst *LI = p.first;
          int offset = p.second;
          if (!isFromValue(cond, LI, DL, num_bits, start_pos)) {
            continue;
          }
          ICmpInst *CI = dyn_cast<ICmpInst>(cond);
          if (!CI) {
            continue;
          }
          ConstantInt *C = dyn_cast<ConstantInt>(CI->getOperand(1));
          if (!C) {
            continue;
          }
          // construct expr for the constraints
          int ld_size = DL.getTypeAllocSizeInBits(LI->getType());
          ref<PerryExpr> cs = constructExprUntil(cond, LI, DL, ld_size, offset);
          if (!cs) {
            continue;
          }
          
          // now process these constraints
          bool is_last_frag_cs = false;
          BasicBlock *first_frag_bb = nullptr;
          for (auto S : dominators) {
            if (S == B) {
              continue;
            }
            if (DT.properlyDominates(S, B)) {
              is_last_frag_cs = true;
              if (BI->getSuccessor(0) == rx_set_length_block) {
                first_frag_bb = BI->getSuccessor(1);
              } else if (BI->getSuccessor(1) == rx_set_length_block) {
                cs = PerryNotExpr::alloc(cs);
                first_frag_bb = BI->getSuccessor(0);
              } else {
                if (isPotentiallyReachable(BI->getSuccessor(0), rx_set_length_block)) {
                  // true
                  first_frag_bb = BI->getSuccessor(1);
                } else {
                  // false
                  cs = PerryNotExpr::alloc(cs);
                  first_frag_bb = BI->getSuccessor(0);
                }
              }
              break;
            }
          }
          // for (auto S : successors(B)) {
          //   if (S == rx_set_length_block) {
          //     // save as Last Fragment Constraints, determine whether the
          //     // constraint should be true or false
          //     is_last_frag_cs = true;
          //     if (BI->getSuccessor(0) == S) {
          //       // true
          //       first_frag_bb = BI->getSuccessor(1);
          //     } else {
          //       // false
          //       cs = PerryNotExpr::alloc(cs);
          //       first_frag_bb = BI->getSuccessor(0);
          //     }
          //     break;
          //   }
          // }
          if (first_frag_bb) {
            first_seg_bbs.insert(first_frag_bb);
          }
          if (is_last_frag_cs) {
            // save and break
            perry_eth_info->last_seg_cs.insert(cs);
            errs() << "Last Seg CS: \n";
            cs->print(errs()); errs() << "\n";
            break;
          }
          // save as Available Constraints
          std::set<BasicBlock *> tmp;
          collectContinuousBlocks(BI->getSuccessor(0), tmp);
          bool should_be_true = false;
          for (auto ppp : load_insts) {
            if (tmp.find(ppp.first->getParent()) != tmp.end()) {
              should_be_true = true;
              break;
            }
          }
          if (!should_be_true) {
            tmp.clear();
            collectContinuousBlocks(BI->getSuccessor(1), tmp);
            bool should_be_false = false;
            for (auto ppp : load_insts) {
              if (tmp.find(ppp.first->getParent()) != tmp.end()) {
                should_be_false = true;
                break;
              }
            }
            if (should_be_false) {
              cs = PerryNotExpr::alloc(cs);
            } else {
              break;
            }
          }
          // save the cs here
          errs() << "Avail Seg CS: \n";
          cs->print(errs()); errs() << "\n";
          perry_eth_info->avail_cs.insert(cs);
          break;
        }
      }

      for (auto B : first_seg_bbs) {
        BranchInst *_BI = dyn_cast<BranchInst>(B->getTerminator());
        if (_BI && _BI->isConditional()) {
          Value *_cond = _BI->getCondition();
          for (auto ppp : load_insts) {
            int _num_bits = 0, _start_pos = 0;
            LoadInst *_LI = ppp.first;
            int _offset = ppp.second;
            if (!isFromValue(_cond, _LI, DL, _num_bits, _start_pos)) {
              continue;
            }
            ICmpInst *_CI = dyn_cast<ICmpInst>(_cond);
            if (!_CI) {
              continue;
            }
            ConstantInt *_C = dyn_cast<ConstantInt>(_CI->getOperand(1));
            if (!_C) {
              continue;
            }
            // construct expr for the constraints
            int _ld_size = DL.getTypeAllocSizeInBits(_LI->getType());
            ref<PerryExpr> _cs = constructExprUntil(_cond, _LI, DL, _ld_size, _offset);
            if (!_cs) {
              continue;
            }
            BasicBlock *tb = _BI->getSuccessor(0);
            BasicBlock *fb = _BI->getSuccessor(1);
            bool do_store = false;
            if (tb->size() > fb->size()) {
              // just store the condition
              do_store = true;
            } else if (fb->size() > tb->size()) {
              // make _cs false
              _cs = PerryNotExpr::alloc(_cs);
              do_store = true;
            }

            if (!do_store) {
              continue;
            }
            if (!perry_eth_info->avail_cs.empty() &&
                !perry_eth_info->last_seg_cs.empty() &&
                perry_eth_info->avail_cs.find(_cs) == perry_eth_info->avail_cs.end() &&
                perry_eth_info->last_seg_cs.find(_cs) == perry_eth_info->last_seg_cs.end())
            {
              errs() << "First Seg CS: \n";
              _cs->print(errs()); errs() << "\n";
              perry_eth_info->first_seg_cs.insert(_cs);
              break;
            }
          }
        }
      }
    }
  }
}

static const std::set<std::string> tim_keywords = {
  "TIM", "LPTIM", "FTM", "LPTMR", "PIT"
};

struct TimFuncDesc {
  std::string fname;
  DataType ty;
  std::string sname;
  int data_idx;
};

static const std::vector<TimFuncDesc> set_timer_period_funcs = {
  TimFuncDesc {
    .fname = "LL_TIM_SetAutoReload",
    .ty = PARAMETER,
    .sname = "",
    .data_idx = 1,
  },
};

static const std::vector<TimFuncDesc> set_timer_cnt_funcs = {
  TimFuncDesc {
    .fname = "LL_TIM_SetCounter",
    .ty = PARAMETER,
    .sname = "",
    .data_idx = 1,
  },
};

static const std::vector<std::string> enable_timer_funcs = {
  "LL_TIM_EnableCounter",
};

bool FuncSymbolizePass::isTimerPeriph(llvm::StringRef name) {
  for (auto &k : tim_keywords) {
    if (name.startswith_insensitive(k)) {
      return true;
    }
  }
  return false;
}

void FuncSymbolizePass::analyzeTimerPeriodReg(llvm::Module &M) {
  const DataLayout &DL = M.getDataLayout();
  for (auto &F : M) {
    if (F.isDeclaration() || F.isDebugInfoForProfiling()) {
      continue;
    }
    for (auto &sf : set_timer_period_funcs) {
      if (!F.getName().equals(sf.fname)) {
        continue;
      }
      std::set<Value *> src_ops;
      if (sf.ty == STRUCT) {
        for (auto &B : F) {
          for (auto &I : B) {
            LoadInst *LI = dyn_cast<LoadInst>(&I);
            if (!LI) {
              continue;
            }
            if (!isLoadTargetField(LI, sf.sname, sf.data_idx)) {
              continue;
            }
            src_ops.insert(LI);
          }
        }
      } else {
        src_ops.insert(F.getArg(sf.data_idx));
      }
      
      for (auto &B : F) {
        for (auto &I : B) {
          StoreInst *SI = dyn_cast<StoreInst>(&I);
          if (!SI) {
            continue;
          }
          Value *val = SI->getValueOperand();
          Value *ptr = SI->getPointerOperand();
          // check if ptr is extracted from target peripheral
          if (!isa<GetElementPtrInst>(ptr)) {
            continue;
          }
          GetElementPtrInst *GEPI = cast<GetElementPtrInst>(ptr);
          Type *SrcElemTy = GEPI->getPointerOperandType()->getPointerElementType();
          if (!SrcElemTy->isStructTy() ||
              !SrcElemTy->getStructName().equals(PeripheralPlaceholder)) {
            continue;
          }
          if (GEPI->getNumIndices() != 2) {
            return;
          }
          ConstantInt *CI = cast<ConstantInt>(GEPI->getOperand(2));
          if (!CI) {
            return;
          }
          StructType *TargetStructTy = cast<StructType>(SrcElemTy);
          // check if value is from period
          for (auto so : src_ops) {
            int num_bits = 0, start_pos = 0;
            if (!isFromValue(val, so, DL, num_bits, start_pos)) {
              continue;
            }
            // bingo!
            perry_timer_info->period_reg_offset = M.getDataLayout().getStructLayout(TargetStructTy)->getElementOffset(CI->getZExtValue());
            errs() << "Found Timer Period Register: offset=" << perry_timer_info->period_reg_offset << "\n";
            break;
          }
        }
      }
      break;
    }
  }
}

void FuncSymbolizePass::analyzeTimerCounterReg(llvm::Module &M) {
  const DataLayout &DL = M.getDataLayout();
  for (auto &F : M) {
    if (F.isDeclaration() || F.isDebugInfoForProfiling()) {
      continue;
    }
    for (auto &sf : set_timer_cnt_funcs) {
      if (!F.getName().equals(sf.fname)) {
        continue;
      }
      std::set<Value *> src_ops;
      if (sf.ty == STRUCT) {
        for (auto &B : F) {
          for (auto &I : B) {
            LoadInst *LI = dyn_cast<LoadInst>(&I);
            if (!LI) {
              continue;
            }
            if (!isLoadTargetField(LI, sf.sname, sf.data_idx)) {
              continue;
            }
            src_ops.insert(LI);
          }
        }
      } else {
        src_ops.insert(F.getArg(sf.data_idx));
      }
      
      for (auto &B : F) {
        for (auto &I : B) {
          StoreInst *SI = dyn_cast<StoreInst>(&I);
          if (!SI) {
            continue;
          }
          Value *val = SI->getValueOperand();
          Value *ptr = SI->getPointerOperand();
          // check if ptr is extracted from target peripheral
          if (!isa<GetElementPtrInst>(ptr)) {
            continue;
          }
          GetElementPtrInst *GEPI = cast<GetElementPtrInst>(ptr);
          Type *SrcElemTy = GEPI->getPointerOperandType()->getPointerElementType();
          if (!SrcElemTy->isStructTy() ||
              !SrcElemTy->getStructName().equals(PeripheralPlaceholder)) {
            continue;
          }
          if (GEPI->getNumIndices() != 2) {
            return;
          }
          ConstantInt *CI = cast<ConstantInt>(GEPI->getOperand(2));
          if (!CI) {
            return;
          }
          StructType *TargetStructTy = cast<StructType>(SrcElemTy);
          // check if value is from period
          for (auto so : src_ops) {
            int num_bits = 0, start_pos = 0;
            if (!isFromValue(val, so, DL, num_bits, start_pos)) {
              continue;
            }
            // bingo!
            perry_timer_info->counter_reg_offset = M.getDataLayout().getStructLayout(TargetStructTy)->getElementOffset(CI->getZExtValue());
            errs() << "Found Timer Counter Register: offset=" << perry_timer_info->counter_reg_offset << "\n";
            break;
          }
        }
      }
      break;
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

  TargetIsETH = isEthernetPeriph(TargetStruct);
  TargetIsTimer = isTimerPeriph(TargetStruct);
  TargetIsDMA = isDMAPeriph(TargetStruct);

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
  for (auto &DF : dma_init_func) {
    Function *F = M.getFunction(DF);
    if (!F) {
      continue;
    }
    if (F->isDeclaration() || F->isDebugInfoForProfiling()) {
      continue;
    }
    DMAInitFC = FunctionCallee(F->getFunctionType(), F);
    break;
  }

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
    ParamF = TargetF;
    symbolizeParams(IRBF, results);
    FunctionToSymbolName->insert(std::make_pair(TFName, "s0"));
    applyDataHeuristic(IRBF, results, TargetF);
    // taint buffers
    if (!TargetIsETH && !TargetIsTimer && !TargetIsDMA) {
      if (!StringRef(TFName).startswith("LL_")) {
        setTaint(IRBF, results);
      }
    }
    // fill in params
    fillParamas(IRBF, results);
    // prepare function pointers if used
    prepFunctionPtr(M, TargetF, IRBF, results);
    // call the target function & process the return value
    callTarget(TargetF, IRBF, results);
    // collect taint after symbolic execution
    if (!TargetIsETH && !TargetIsTimer && !TargetIsDMA) {
      if (!StringRef(TFName).startswith("LL_")) {
        collectTaint(IRBF);
      }
    }
    collectRetVal(IRBF, TFName);
    GuessedBuffers.clear();
    // then return
    IRBF.CreateRetVoid();
    for (auto root : results) {
      delete root;
    }
    changed = true;
  }

  if (changed && TargetIsETH) {
    analyzeDescRegs(M);
    analyzeDescTxBufferLen(M);
    analyzeDescRxFrameLen(M);
    analyzeDescBuffer(M);
    analyzeDescMemLayout(M);
    analyzeDescRxBufferLen(M);
    analyzeDescConstraints(M);
  }

  if (changed && TargetIsTimer) {
    analyzeTimerPeriodReg(M);
    analyzeTimerCounterReg(M);
  }

  return changed;
}

FuncSymbolizePass::~FuncSymbolizePass() {
  if (CG) {
    delete CG;
    CG = nullptr;
  }
}