#ifndef __PERRY_EXPR_MANAGER_H__
#define __PERRY_EXPR_MANAGER_H__

#include "klee/Perry/PerryExpr.h"

namespace klee {

class PerryExprManager {
public:
  PerryExprManager() = default;
  ref<PerryExpr> acquirePerryExpr(const ref<Expr> &e);

private:
  std::set<ref<PerryExpr>> bank;
};

}

#endif