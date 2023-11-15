#ifndef __PERRY_STRUCTINFO_H__
#define __PERRY_STRUCTINFO_H__

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/LoopInfo.h"

#include <vector>
#include <set>
#include <unordered_set>
#include <map>

namespace klee {

struct StructOffset {
  std::string TypeName;
  int Offset;

  bool operator== (const StructOffset &a) const;

  bool operator< (const StructOffset &a) const;

  StructOffset();

  StructOffset(const StructOffset &a);
};

void trackFunctionPtrPlaceholder(llvm::Value *V, std::set<StructOffset> &S);

void trackFunctionPtr(llvm::Value *V,
                      std::set<llvm::Function*> &PointedFunctions);

class PerryAnalysisPass : public llvm::ModulePass {
public:
  static char ID;
  PerryAnalysisPass() = delete;
  PerryAnalysisPass(
    std::set<std::string> &_TopLevelFunction,
    std::map<StructOffset, std::set<std::string>> &_PtrFunction,
    std::map<std::string, std::unordered_set<uint64_t>> &_OkValuesMap,
    bool doAutoAnalyzeApi = false,
    bool doAutoAnalyzeEnum = false)
    : llvm::ModulePass(ID),
      TopLevelFunction(_TopLevelFunction), PtrFunction(_PtrFunction),
      OkValuesMap(_OkValuesMap),
      doAutoAnalyzeApi(doAutoAnalyzeApi),
      doAutoAnalyzeEnum(doAutoAnalyzeEnum) {}
  bool runOnModule(llvm::Module &M) override;
private:
  std::set<std::string> &TopLevelFunction;
  std::map<StructOffset, std::set<std::string>> &PtrFunction;
  std::map<std::string, std::unordered_set<uint64_t>> &OkValuesMap;
  bool doAutoAnalyzeApi;
  bool doAutoAnalyzeEnum;
};

class CDGNode {
public:
  using successors = std::set<CDGNode*>;
  using predecessors = std::set<CDGNode*>;
  using child_iterator = typename successors::iterator;

  CDGNode() = delete;
  CDGNode(const llvm::BasicBlock *data) : dataNode(data) {}

  void addSuccessor(CDGNode *s) {
    succ.insert(s);
    s->pred.insert(this);
  }

  child_iterator child_begin() {
    return child_iterator(succ.begin());
  }

  child_iterator child_end() {
    return child_iterator(succ.end());
  }

  const llvm::BasicBlock *getData() {
    return dataNode;
  }

  const successors *getSuccessors() {
    return &succ;
  }

  unsigned getNumSuccessors() { return succ.size(); }
  unsigned getNumPredecessors() { return pred.size(); }

  const predecessors *getPredecessors() {
    return &pred;
  }

private:
  const llvm::BasicBlock *dataNode;
  successors succ;
  predecessors pred;
};

class ControlDependenceGraphPass : public llvm::ModulePass {
public:
  using NodeSet = std::set<CDGNode*>;
  using NodeMap = std::map<llvm::BasicBlock*, CDGNode*>;
  using nodes_iterator = typename NodeSet::iterator;

  static char ID;
  ControlDependenceGraphPass(const std::set<std::string> &_TopLevelFunctions,
                             NodeSet &_nodeSet, NodeMap &_nodeMap);
  ~ControlDependenceGraphPass();

  bool runOnModule(llvm::Module &M) override;
  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
  void constructGraph(llvm::Function &F,
                      std::set<llvm::BasicBlock*> &topBlocks);
  void addEdge(llvm::BasicBlock *src, llvm::BasicBlock *dst);
  static int isControlDependentOn(NodeMap &nm, llvm::BasicBlock *a,
                                               llvm::BasicBlock *b);
  nodes_iterator nodes_begin() {
    return nodes_iterator(nodeSet.begin());
  }

  nodes_iterator nodes_end() {
    return nodes_iterator(nodeSet.end());
  }

  NodeSet* getNodeSet() {
    return &nodeSet;
  }

  NodeMap* getNodeMap() {
    return &nodeMap;
  }

private:
  const std::set<std::string> &TopLevelFunctions;
  NodeSet &nodeSet;
  NodeMap &nodeMap;
  llvm::PostDominatorTree *PDT;
};

class CollectLoopExitingPass : public llvm::ModulePass {
public:
  static char ID;
  CollectLoopExitingPass(std::unordered_set<llvm::BasicBlock*> &M)
    : llvm::ModulePass(ID), loopExitingBlocks(M) {}
  bool runOnModule(llvm::Module &M) override;
  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
private:
  std::unordered_set<llvm::BasicBlock*> &loopExitingBlocks;
  void handleLoop(llvm::Loop *L);
};

}


#endif