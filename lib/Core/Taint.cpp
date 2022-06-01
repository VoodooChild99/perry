#include "klee/Taint/Taint.h"

#include <assert.h>

namespace klee {
  bool isTainted(TaintSet ts) {
    return ((ts & TAINT_MASK) != NO_TAINT);
  }
  
  bool hasTaint(TaintSet ts, TaintTy t) {
    assert(t <= MAX_TAINT);
    return ((ts & t) != NO_TAINT);
  }

  void addTaint(TaintSet& ts, TaintTy t) {
    assert(t <= MAX_TAINT);
    ts |= (1 << t);
  }

  void delTaint(TaintSet& ts, TaintTy t) {
    assert(t <= MAX_TAINT);
    ts &= (~(1 << t));
  }

  void clearTaint(TaintSet& ts) {
    ts = 0;
  }

  void mergeTaint(TaintSet& dst, TaintSet src) {
    dst |= src;
  }
}