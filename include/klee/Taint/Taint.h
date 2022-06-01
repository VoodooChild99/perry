#ifndef KLEE_TAINT_H
#define KLEE_TAINT_H

#include <cstddef>

namespace klee {
  using TaintSet = std::size_t;
  using TaintTy = std::size_t;

  const std::size_t MAX_TAINT = (sizeof(TaintTy) * 8) - 1;
  const TaintTy TAINT_MASK = TaintTy(-1);
  const TaintTy NO_TAINT = 0;

  // return true iff `ts` is not empty (i.e., at least one taint)
  bool isTainted(TaintSet ts);
  
  // return true iff `t` is in `ts`
  bool hasTaint(TaintSet ts, TaintTy t);

  // add taint `t` to `ts`
  void addTaint(TaintSet& ts, TaintTy t);

  // delete taint `t` from `ts`
  void delTaint(TaintSet& ts, TaintTy t);

  // clear all taints in `ts`
  void clearTaint(TaintSet& ts);

  // merge two taint sets
  void mergeTaint(TaintSet& dst, TaintSet src);
}

#endif