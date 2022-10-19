#include "klee/Perry/Passes.h"
#include "klee/Support/ErrorHandling.h"

#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/DebugInfoMetadata.h"

#include <deque>
#include <utility>

using namespace klee;
using namespace llvm;

namespace {
  cl::list<std::string>
  excludeFunctionList("exclude-function-list",
                      cl::desc("Functions to exclude when analyzing top-level "
                               "functions"));
  
  cl::opt<bool>
  enableAutomaticAnalysis("enable-auto-analysis",
                          cl::desc("Enable automatic top-level function analysis"),
                          cl::init(true));
  
  cl::list<std::string>
  includeFunctionList("include-function-list",
                      cl::desc("Functions to include when analyzing top-level functions"));
}

bool StructOffset::operator== (const StructOffset &a) const {
  return (Offset == a.Offset && TypeName == a.TypeName);
}

bool StructOffset::operator< (const StructOffset &a) const {
  return (Offset < a.Offset || TypeName.compare(a.TypeName) < 0);
}

StructOffset::StructOffset()
  : TypeName(""), Offset(-1) {}

StructOffset::StructOffset(const StructOffset &a)
  : TypeName(a.TypeName), Offset(a.Offset) {}

char PerryAnalysisPass::ID = 0;

void klee::trackFunctionPtrPlaceholder(Value *V, std::set<StructOffset> &S) {
  using WLFrame = std::pair<StructOffset, Value*>;
  std::deque<WLFrame> WL;

  WL.push_back(std::make_pair(StructOffset(), V));

  while (!WL.empty()) {
    WLFrame SO = WL.front();
    if (isa<Instruction>(SO.second)) {
      Instruction *I = cast<Instruction>(SO.second);
      switch (I->getOpcode()) {
        case Instruction::PHI: {
          PHINode *PI = cast<PHINode>(I);
          unsigned numVal = PI->getNumIncomingValues();
          for (unsigned i = 0; i < numVal; ++i) {
            WL.push_back(std::make_pair(StructOffset(SO.first),
                                        PI->getIncomingValue(i)));
          }
          break;
        }
        case Instruction::Load: {
          LoadInst *LI = cast<LoadInst>(I);
          WL.push_back(std::make_pair(StructOffset(SO.first),
                                      LI->getPointerOperand()));
          break;
        }
        case Instruction::GetElementPtr: {
          GetElementPtrInst *GEPI = cast<GetElementPtrInst>(I);
          if (GEPI->getNumIndices() == 2) {
            Value *o = GEPI->getOperand(2);
            if (isa<Constant>(o)) {
              StructOffset NSO;
              NSO.TypeName = GEPI->getPointerOperandType()
                             ->getPointerElementType()->getStructName().str();
              NSO.Offset = cast<ConstantInt>(o)->getZExtValue();
              S.insert(NSO);
            }
          }
          break;
        }
        default: {
          klee_warning(
            "Unhandled instruction type %s "
            "when tracking function pointer placeholders",
            I->getOpcodeName());
          break;
        }
      }
    } else {
      // ignore
      std::string ValueString;
      raw_string_ostream OS(ValueString);
      SO.second->print(OS);
      klee_warning(
        "Unhandled value when tracking function pointer placeholders: %s",
        ValueString.c_str());
    }
    WL.pop_front();
  }
}

void klee::trackFunctionPtr(Value *V, std::set<Function*> &PointedFunctions) {
  std::deque<Value*> WL;
  WL.push_back(V);

  while (!WL.empty()) {
    Value *TV = WL.front();
    if (isa<Instruction>(TV)) {
      Instruction *I = cast<Instruction>(TV);
      switch (I->getOpcode()) {
        case Instruction::Select: {
          SelectInst *SI = cast<SelectInst>(I);
          WL.push_back(SI->getTrueValue());
          WL.push_back(SI->getFalseValue());
          break;
        }
        case Instruction::PHI: {
          PHINode *PN = cast<PHINode>(I);
          unsigned numIncome = PN->getNumIncomingValues();
          for (unsigned i = 0; i < numIncome; ++i) {
            WL.push_back(PN->getIncomingValue(i));
          }
          break;
        }
        default: {
          klee_warning(
            "Unhandled instruction type %s when tracking function pointers",
            I->getOpcodeName());
          break;
        }
      }
    } else if (isa<Constant>(TV)) {
      if (isa<Function>(TV)) {
        PointedFunctions.insert(cast<Function>(TV));
      }
    } else {
      std::string ValueString;
      raw_string_ostream OS(ValueString);
      TV->print(OS);
      klee_warning("Unhandled value when tracking function pointers: %s",
                   ValueString.c_str());
    }

    WL.pop_front();
  }
}

bool PerryAnalysisPass::runOnModule(Module &M) {
  CallGraph CG(M);
  std::set<Function*> calledFuncs;
  std::set<Function*> FuncPtrs;

  std::set<std::string> excludeFuncSet;
  for (auto &ef : excludeFunctionList) {
    excludeFuncSet.insert(ef);
  }
  std::set<std::string> includeFuncSet;

  for (auto &F : M) {
    if (F.isDeclaration()) {
      continue;
    }

    CallGraphNode *CGN = CG[&F];
    for (auto &SF : *CGN) {
      calledFuncs.insert(SF.second->getFunction());
    }

    for (auto &B : F) {
      for (auto &I : B) {
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

        // should be a function pointer
        std::set<Function*> PointedFunctions;
        if (isa<Function>(VO)) {
          // constant function pointer
          PointedFunctions.insert(cast<Function>(VO));
        } else {
          // varadic function pointer, track possible values
          trackFunctionPtr(VO, PointedFunctions);
        }

        std::set<StructOffset> SetOffsets;
        trackFunctionPtrPlaceholder(SI->getPointerOperand(), SetOffsets);
        if (SetOffsets.empty()) {
          std::string InsString;
          raw_string_ostream OS(InsString);
          I.print(OS);
          OS << " at ";
          I.getDebugLoc().print(OS);
          klee_warning("Failed to track placeholders: %s", InsString.c_str());
          continue;
        }

        for (auto PF : PointedFunctions) {
          FuncPtrs.insert(PF);
        }

        for (auto &SO : SetOffsets) {
          if (PtrFunction.find(SO) != PtrFunction.end()) {
            for (auto PF : PointedFunctions) {
              PtrFunction[SO].insert(PF->getName().str());
            }
          } else {
            std::set<std::string> tmp;
            for (auto PF : PointedFunctions) {
              tmp.insert(PF->getName().str());
            }
            PtrFunction.insert(std::make_pair(SO, tmp));
          }
        }
      }
    }
  }
  
  if (!enableAutomaticAnalysis || !doAutoAnalyzeApi) {
    if (includeFunctionList.empty() && TopLevelFunction.empty()) {
      klee_error("must specify at least one top-level function when "
                 "automatic analysis is disabled");
    }
  }
  for (auto &iff : includeFunctionList) {
    includeFuncSet.insert(iff);
  }

  for (auto &F : M) {
    if (F.isDeclaration()) {
      continue;
    }

    if (enableAutomaticAnalysis && doAutoAnalyzeApi) {
      if ((calledFuncs.find(&F) == calledFuncs.end() &&
          FuncPtrs.find(&F) == FuncPtrs.end() &&
          excludeFuncSet.find(F.getName().str()) == excludeFuncSet.end()) ||
          includeFuncSet.find(F.getName().str()) != includeFuncSet.end())
      {
        TopLevelFunction.insert(F.getName().str());
      }
    } else {
      if (includeFuncSet.find(F.getName().str()) != includeFuncSet.end()) {
        TopLevelFunction.insert(F.getName().str());
      }
    }
  }

  if (doAutoAnalyzeEnum) {
    for (auto &FN : TopLevelFunction) {
      auto TopF = M.getFunction(FN);
      if (TopF->getReturnType()->isVoidTy()) {
        continue;
      }
      auto SP = TopF->getSubprogram();
      auto retType = SP->getType()->getTypeArray()[0];
      auto middleType = retType;
      bool hasEnumeration = true;
      while (middleType->getTag() != dwarf::Tag::DW_TAG_enumeration_type &&
            hasEnumeration)
      {
        switch (middleType->getMetadataID()) {
          case Metadata::MetadataKind::DIDerivedTypeKind: {
            auto DT = cast<DIDerivedType>(middleType);
            middleType = DT->getBaseType();
            break;
          }
          case Metadata::MetadataKind::DICompositeTypeKind: {
            auto CT = cast<DICompositeType>(middleType);
            middleType = CT->getBaseType();
            break;
          }
          case Metadata::MetadataKind::DIBasicTypeKind: {
            hasEnumeration = false;
            break;
          }
          default: {
            std::string MSG;
            raw_string_ostream OS(MSG);
            middleType->print(OS);
            klee_warning_once("Unhandled DIType %s in %s", MSG.c_str(), FN.c_str());
            hasEnumeration = false;
            break;
          }
        }
      }
      if (!hasEnumeration) {
        continue;
      }
      auto CT = cast<DICompositeType>(middleType);
      if (!CT) {
        continue;
      }
      std::set<uint64_t> OkValues;
      for (auto Node : CT->getElements()) {
        assert(isa<DIEnumerator>(Node));
        auto DIE = cast<DIEnumerator>(Node);
        auto EnumName = DIE->getName();
        auto lowered = EnumName.lower();
        // heuristics to determine whether a enumeration represents success
        if (lowered.find("ok") != std::string::npos ||
            lowered.find("success") != std::string::npos)
        {
          OkValues.insert(DIE->getValue().getZExtValue());
        }
      }
      if (OkValues.empty()) {
        klee_warning("Function \'%s\' returns an enum, but failed to guess "
                    "OK values", FN.c_str());
      } else {
        std::string infoMsg;
        raw_string_ostream IOS(infoMsg);
        for (auto OV : OkValues) {
          IOS << OV << ", ";
        }
        infoMsg = infoMsg.substr(0, infoMsg.size() - 2);
        klee_message("Function \'%s\' returns an enum, inferred OK values: %s",
                    FN.c_str(), infoMsg.c_str());
        OkValuesMap[FN] = OkValues;
      }
    }
  }

  klee_message("Collected Top-Level Functions:");
  for (auto F : TopLevelFunction) {
    klee_message("[*] %s", F.c_str());
  }

  klee_message("Collected Function Pointers:");
  for (auto &e : PtrFunction) {
    std::string tmp;
    for (auto &PF : e.second) {
      tmp += PF;
      tmp += ", ";
    }
    if (tmp.length() >= 2) {
      tmp = tmp.substr(0, tmp.length() - 2);
    }
    klee_message("[*] In %s{%d}: %s",
                 e.first.TypeName.c_str(),
                 e.first.Offset, tmp.c_str());
  }

  return false;
}