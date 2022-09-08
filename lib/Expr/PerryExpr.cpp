#include "klee/Perry/PerryExpr.h"
#include "klee/Support/ErrorHandling.h"

using namespace klee;

#define PERRY_EXPR_BRANCH(_class_kind)                                        \
case Expr::_class_kind: {                                                     \
  const _class_kind ## Expr *CE = cast<_class_kind ## Expr>(E);               \
  PE = Perry ## _class_kind ## Expr::alloc(CE);                               \
  break;                                                                      \
}                                                                             \

ref<PerryExpr> klee::convertToPerryExpr(const ref<Expr> &E) {
  ref<PerryExpr> PE(0);
  switch (E->getKind()) {
    PERRY_EXPR_BRANCH(Constant)
    PERRY_EXPR_BRANCH(Read)
    PERRY_EXPR_BRANCH(Select)
    PERRY_EXPR_BRANCH(Concat)
    PERRY_EXPR_BRANCH(Extract)
    PERRY_EXPR_BRANCH(ZExt)
    PERRY_EXPR_BRANCH(SExt)
    PERRY_EXPR_BRANCH(Not)
    PERRY_EXPR_BRANCH(Add)
    PERRY_EXPR_BRANCH(Sub)
    PERRY_EXPR_BRANCH(Mul)
    PERRY_EXPR_BRANCH(UDiv)
    PERRY_EXPR_BRANCH(SDiv)
    PERRY_EXPR_BRANCH(URem)
    PERRY_EXPR_BRANCH(SRem)
    PERRY_EXPR_BRANCH(And)
    PERRY_EXPR_BRANCH(Or)
    PERRY_EXPR_BRANCH(Xor)
    PERRY_EXPR_BRANCH(Shl)
    PERRY_EXPR_BRANCH(LShr)
    PERRY_EXPR_BRANCH(AShr)
    PERRY_EXPR_BRANCH(Eq)
    PERRY_EXPR_BRANCH(Ne)
    PERRY_EXPR_BRANCH(Ult)
    PERRY_EXPR_BRANCH(Ule)
    PERRY_EXPR_BRANCH(Ugt)
    PERRY_EXPR_BRANCH(Uge)
    PERRY_EXPR_BRANCH(Slt)
    PERRY_EXPR_BRANCH(Sle)
    PERRY_EXPR_BRANCH(Sgt)
    PERRY_EXPR_BRANCH(Sge)
    default: {
      klee_error("Unhandled Expr type: %d", E->getKind());
      return nullptr;
    }
  }
  return PE;
}

int PerryExpr::compare(const PerryExpr &b) const {
  static PerryExprEquivSet equivs;
  int r = compare(b, equivs);
  equivs.clear();
  return r;
}

int PerryExpr::compare(const PerryExpr &b, PerryExprEquivSet &equivs) const {
  if (this == &b) return 0;

  const PerryExpr *ap, *bp;
  if (this < &b) {
    ap = this; bp = &b;
  } else {
    ap = &b; bp = this;
  }

  if (equivs.count(std::make_pair(ap, bp)))
    return 0;

  Expr::Kind ak = getKind(), bk = b.getKind();
  if (ak!=bk)
    return (ak < bk) ? -1 : 1;

  if (hashValue != b.hashValue) 
    return (hashValue < b.hashValue) ? -1 : 1;

  if (int res = compareContents(b)) 
    return res;

  unsigned aN = getNumKids();
  for (unsigned i=0; i<aN; i++)
    if (int res = getKid(i)->compare(*b.getKid(i), equivs))
      return res;

  equivs.insert(std::make_pair(ap, bp));
  return 0;
}