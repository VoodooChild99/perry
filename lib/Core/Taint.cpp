#include "klee/Taint/Taint.h"
#include "klee/Support/ErrorHandling.h"

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

  TaintTy getReadCtx(TaintTy t) {
    return (t & 0xffff);
  }

  TaintTy getBufferTaint(TaintTy t) {
    return (t & 0xffff0000) >> 16;
  }

  TaintTy getRegTaint(TaintTy t) {
    return (t & 0xffff00000000) >> 32;
  }

  TaintTy getAllTaint(TaintTy t) {
    return (t & 0xffffffff0000) >> 16;
  }

  TaintTy embedReadCtx(TaintTy t, TaintTy ctx) {
    if (ctx > 0xffff) {
      klee_error("read ctx too big");
    }
    return t | ctx;
  }

  TaintTy embedBufferTaint(TaintTy t, TaintTy bt) {
    if (bt > 0xffff) {
      klee_error("buffer taint too big");
    }
    return t | (bt << 16);
  }

  TaintTy embedRegTaint(TaintTy t, TaintTy rt) {
    if (rt > 0xffff) {
      klee_error("register taint too big");
    }
    return t | (rt << 32);
  }
}