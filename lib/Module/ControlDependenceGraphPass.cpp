#include "llvm/IR/Instructions.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/CallGraph.h"

#include "klee/Support/ErrorHandling.h"
#include "klee/Perry/Passes.h"

#include <vector>
#include <stack>

using namespace llvm;
using namespace klee;

char ControlDependenceGraphPass::ID = 0;

ControlDependenceGraphPass::
ControlDependenceGraphPass(const std::set<std::string> &_TopLevelFunctions,
                           NodeSet &_nodeSet, NodeMap &_nodeMap)
  : ModulePass(ControlDependenceGraphPass::ID),
    TopLevelFunctions(_TopLevelFunctions),
    nodeSet(_nodeSet), nodeMap(_nodeMap) { }

ControlDependenceGraphPass::~ControlDependenceGraphPass() {
  // deliberately leak this
	// for (auto node : nodeSet) {
	// 	delete node;
	// }
}

void ControlDependenceGraphPass::
getAnalysisUsage(AnalysisUsage &AU) const{
	AU.addRequired<PostDominatorTreeWrapperPass>();
	AU.setPreservesAll();
}

void ControlDependenceGraphPass::addEdge(BasicBlock *src,
																				 BasicBlock *dst)
{
	CDGNode *srcNode;
	CDGNode *dstNode;
	if (nodeMap.find(src) == nodeMap.end()) {
		srcNode = new CDGNode(src);
		nodeMap[src] = srcNode;
		nodeSet.insert(srcNode);
	} else {
		srcNode = nodeMap[src];
	}

	if (nodeMap.find(dst) == nodeMap.end()) {
		dstNode = new CDGNode(dst);
		nodeMap[dst] = dstNode;
		nodeSet.insert(dstNode);
	} else {
		dstNode = nodeMap[dst];
	}

	srcNode->addSuccessor(dstNode);
}

/// Construct control dependence graph.
/// This implements
/// `https://faculty.cc.gatech.edu/~harrold/6340/cs6340_fall2009/Slides/BasicAnalysis4.pdf`
/// and
/// `https://compilers.cs.uni-saarland.de/teaching/spa/2014/slides/ProgramDependenceGraph.pdf`
void ControlDependenceGraphPass::
constructGraph(Function &F, std::set<BasicBlock*> &topBlocks) {
	std::vector<std::pair<BasicBlock*, BasicBlock*>> EdgeSet;
	
	for (auto &B : F) {
    if (nodeMap.find(&B) == nodeMap.end()) {
      CDGNode *N = new CDGNode(&B);
      nodeMap[&B] = N;
      nodeSet.insert(N);
    }

    for (succ_iterator SI = succ_begin(&B), SE = succ_end(&B); SI != SE; ++SI) {
			BasicBlock *BS = *SI;
			if (!PDT->dominates(BS, &B)) {
				EdgeSet.push_back(std::make_pair(&B, BS));
			}
		}
	}

	for (auto E : EdgeSet) {
		BasicBlock *L = PDT->findNearestCommonDominator(E.first, E.second);

    if (L == E.first) {
			// L == A
      addEdge(L, L);
		}

		DomTreeNode *B = PDT->getNode(E.second);
		while (B && B->getBlock() && B->getBlock() != L) {
      addEdge(E.first, B->getBlock());
			B = B->getIDom();
		}
	}

  for (auto &B : F) {
    if (nodeMap.find(&B) == nodeMap.end()) {
      continue;
    }
    CDGNode *N = nodeMap[&B];
    if (N->getNumPredecessors() == 0) {
      topBlocks.insert(&B);
    }
  }
}

bool ControlDependenceGraphPass::runOnModule(Module &M) {
  std::set<Function*> genedFunc;
  CallGraph CG(M);

  std::vector<Function*> WL;
  std::set<Function*> WLSet;
  for (auto &TF : TopLevelFunctions) {
    auto TargetF = M.getFunction(TF);
    if (!TargetF) {
      klee_error("Failed to locate function %s", TF.c_str());
    }
    WL.push_back(TargetF);
    WLSet.insert(TargetF);
  }
  std::map<Function*, std::set<BasicBlock*>> topBlocks;

  // construct CDG for top level functions and all called functions
  while (!WL.empty()) {
    Function *TargetF = WL.back();
    WL.pop_back();

    if (genedFunc.find(TargetF) == genedFunc.end()) {
      PDT = &getAnalysis<PostDominatorTreeWrapperPass>(*TargetF).getPostDomTree();
      std::set<BasicBlock*> tBlocks;
      constructGraph(*TargetF, tBlocks);
      topBlocks.insert(std::make_pair(TargetF, tBlocks));
      genedFunc.insert(TargetF);
    }
    CallGraphNode *CGN = CG[TargetF];
    for (auto &SF : *CGN) {
      Function *ChildF = SF.second->getFunction();
      if (!ChildF || ChildF->isDeclaration()) {
        continue;
      }

      if (WLSet.find(ChildF) == WLSet.end()) {
        WLSet.insert(ChildF);
        WL.push_back(ChildF);
      }
    }
  }
  WLSet.clear();

  // then merge these CDGs
  for (auto &TF : TopLevelFunctions) {
    auto TargetF = M.getFunction(TF);
    WL.push_back(TargetF);
    WLSet.insert(TargetF);
  }

  // link all these CDG
  while (!WL.empty()) {
    Function *TargetF = WL.back();
    WL.pop_back();
    assert(genedFunc.find(TargetF) != genedFunc.end());

    // locate call instructions and link corresponding CDGs
    for (auto &B : *TargetF) {
      for (auto &I : B) {
        if (I.getOpcode() != Instruction::Call) {
          continue;
        }
        CallInst *CI = cast<CallInst>(&I);
        Function *CF = CI->getCalledFunction();
        if (!CF || CF->isDeclaration()) {
          continue;
        }

        assert(genedFunc.find(CF) != genedFunc.end());
        const std::set<BasicBlock*> &tBlocks = topBlocks[CF];
        for (auto &CB : *CF) {
          if (nodeMap.find(&CB) == nodeMap.end()) {
            continue;
          }
          if (tBlocks.find(&CB) != tBlocks.end()) {
            addEdge(&B, &CB);
          }
        }
        if (WLSet.find(CF) == WLSet.end()) {
          WLSet.insert(CF);
          WL.push_back(CF);
        }
      }
    }
  }

	return false;
}

// check whether `a` is control dependent on `b`
// 1 for yes
// 0 for no
// -1 for don't know
int ControlDependenceGraphPass::
isControlDependentOn(NodeMap &nm, llvm::BasicBlock *a, llvm::BasicBlock *b) {
  if (a == b) {
    return 0;
  }

  if (nm.find(a) == nm.end() || nm.find(b) == nm.end()) {
    return -1;
  }

  CDGNode *na = nm[a];
  CDGNode *nb = nm[b];

  // traverse nb's successors to find na
  std::set<CDGNode*> visited;
  std::stack<CDGNode*> WL;

  WL.push(nb);
  visited.insert(nb);

  while (!WL.empty()) {
    CDGNode *cur = WL.top();
    WL.pop();

    if (cur == na) {
      return 1;
    }

    for (auto it = cur->child_begin(); it != cur->child_end(); ++it) {
      CDGNode *child = *it;
      if (visited.find(child) == visited.end()) {
        // not visited before
        visited.insert(child);
        WL.push(child);
      }
    }
  }

  return 0;
}