#include "klee/Perry/Passes.h"

using namespace klee;
using namespace llvm;

char CollectLoopExitingPass::ID = 0;

void CollectLoopExitingPass::handleLoop(Loop *L) {
  for (auto SL : L->getSubLoops()) {
    handleLoop(SL);
  }
  SmallVector<BasicBlock*, 4> sv;
  L->getExitingBlocks(sv);
  for (auto EB: sv) {
    loopExitingBlocks.insert(EB);
  }
}

void CollectLoopExitingPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<LoopInfoWrapperPass>();
}

bool CollectLoopExitingPass::runOnModule(Module &M) {
  for (auto &F : M) {
    if (F.isDeclaration()) {
      continue;
    }
    LoopInfoWrapperPass &LP = getAnalysis<LoopInfoWrapperPass>(F);
    LoopInfo &LI = LP.getLoopInfo();
    for (auto L : LI) {
      handleLoop(L);
    }
  }
  return false;
}