#ifndef KLEE_TAINT_H
#define KLEE_TAINT_H

#include <set>
#include <stdint.h>

namespace klee {
  using TaintTy = uint64_t;
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

  TaintTy getReadCtx(TaintTy t);
  TaintTy getBufferTaint(TaintTy t);
  TaintTy getRegTaint(TaintTy t);
  TaintTy getAllTaint(TaintTy t);

  TaintTy embedReadCtx(TaintTy t, TaintTy ctx);
  TaintTy embedBufferTaint(TaintTy t, TaintTy bt);
  TaintTy embedRegTaint(TaintTy t, TaintTy rt);
}

#endif