#ifndef KLEE_TAINT_H
#define KLEE_TAINT_H

#include <set>

namespace klee {
  using TaintTy = unsigned;
  using TaintSet = std::set<TaintTy>;

  // return true iff `ts` is not empty (i.e., at least one taint)
  bool isTainted(TaintSet& ts);
  
  // return true iff `t` is in `ts`
  bool hasTaint(TaintSet& ts, TaintTy t);

  // add taint `t` to `ts`
  void addTaint(TaintSet& ts, TaintTy t);

  // delete taint `t` from `ts`
  void delTaint(TaintSet& ts, TaintTy t);

  // clear all taints in `ts`
  void clearTaint(TaintSet& ts);

  // merge two taint sets
  void mergeTaint(TaintSet& dst, TaintSet& src);
}

#endif