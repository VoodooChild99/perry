#include "klee/Perry/PerryExprManager.h"

using namespace klee;

ref<PerryExpr> PerryExprManager::
acquirePerryExpr(const ref<Expr> &e) {
  auto allocated_expr = convertToPerryExpr(e);
  auto it = bank.find(allocated_expr);
  if (it == bank.end()) {
    // new expr, insert it into the bank, then return the ref
    bank.insert(allocated_expr);
    return allocated_expr;
  } else {
    // else, return the ref to the element in the set.
    // the allocated expr will be release automatically
    return *it;
  }
}