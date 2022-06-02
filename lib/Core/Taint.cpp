#include "klee/Taint/Taint.h"

#include <assert.h>

namespace klee {
  bool isTainted(TaintSet& ts) {
    return (!ts.empty());
  }
  
  bool hasTaint(TaintSet& ts, TaintTy t) {
    return (ts.find(t) != ts.end());
  }

  void addTaint(TaintSet& ts, TaintTy t) {
    ts.insert(t);
  }

  void delTaint(TaintSet& ts, TaintTy t) {
    ts.erase(t);
  }

  void clearTaint(TaintSet& ts) {
    ts.clear();
  }

  void mergeTaint(TaintSet& dst, TaintSet& src) {
    dst.insert(src.begin(), src.end());
  }
}