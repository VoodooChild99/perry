#ifndef __PERRY_EXPR_H__
#define __PERRY_EXPR_H__

#include "klee/Expr/Expr.h"
#include "klee/Support/ErrorHandling.h"

namespace klee {

class PerryExpr {
public:
  class ReferenceCounter _refCount;

  PerryExpr() = default;
  virtual ~PerryExpr() {}

  virtual Expr::Kind getKind() const = 0;
  virtual Expr::Width getWidth() const = 0;

  virtual unsigned getNumKids() const = 0;
  virtual ref<PerryExpr> getKid(unsigned i) const = 0;
  virtual void replaceKid(unsigned i, const ref<PerryExpr> &) = 0;

  virtual void print(llvm::raw_ostream &os) const = 0;

  static bool classof(const PerryExpr *) { return true; }

  int compare(const PerryExpr &b) const;
  virtual unsigned hash() const { return hashValue; }

  virtual unsigned computeHash() {
    unsigned res = getKind() * Expr::MAGIC_HASH_CONSTANT;

    int n = getNumKids();
    for (int i = 0; i < n; i++) {
      res <<= 1;
      res ^= getKid(i)->hash() * Expr::MAGIC_HASH_CONSTANT;
    }
    
    hashValue = res;
    return hashValue;
  }

private:
  using PerryExprEquivSet 
    = llvm::DenseSet<std::pair<const PerryExpr *, const PerryExpr *>>;
  int compare(const PerryExpr &a, PerryExprEquivSet &equivs) const;

protected:
  unsigned hashValue;
  virtual int compareContents(const PerryExpr &b) const = 0;
};

inline bool operator==(const PerryExpr &lhs, const PerryExpr &rhs) {
  return lhs.compare(rhs) == 0;
}

inline bool operator!=(const PerryExpr &lhs, const PerryExpr &rhs) {
  return !(lhs == rhs);
}

inline bool operator<(const PerryExpr &lhs, const PerryExpr &rhs) {
  return lhs.compare(rhs) < 0;
}

inline bool operator>(const PerryExpr &lhs, const PerryExpr &rhs) {
  return rhs < lhs;
}

inline bool operator<=(const PerryExpr &lhs, const PerryExpr &rhs) {
  return !(lhs > rhs);
}

inline bool operator>=(const PerryExpr &lhs, const PerryExpr &rhs) {
  return !(lhs < rhs);
}

ref<PerryExpr> convertToPerryExpr(const ref<Expr> &E);

class PerryConstantExpr : public PerryExpr {
public:
  static const Expr::Kind kind = Expr::Constant;
  static const unsigned numKids = 0;

  static ref<PerryExpr> alloc(const llvm::APInt &_value) {
    ref<PerryConstantExpr> ret(new PerryConstantExpr(_value));
    ret->computeHash();
    return ret;
  }

  static ref<PerryExpr> alloc(const ConstantExpr *CE) {
    ref<PerryConstantExpr> ret(new PerryConstantExpr(CE));
    ret->computeHash();
    return ret;
  }

  static ref<PerryExpr> alloc(unsigned num_bits, uint64_t val) {
    ref<PerryConstantExpr> ret(new PerryConstantExpr(num_bits, val));
    ret->computeHash();
    return ret;
  }

  Expr::Kind getKind() const { return Expr::Constant; }

  Expr::Width getWidth() const { return value.getBitWidth(); }

  unsigned getNumKids() const { return 0; }
  ref<PerryExpr> getKid(unsigned i) const { return 0; }

  void print(llvm::raw_ostream &os) const {
    if (getWidth() == Expr::Bool) {
      if (isTrue()) {
        os << "true";
      } else {
        os << "false";
      }
    } else {
      value.print(os, false);
    }
  }

  int compareContents(const PerryExpr &b) const {
    auto &cb = static_cast<const PerryConstantExpr &>(b);
    if (getWidth() != cb.getWidth())
      return getWidth() < cb.getWidth() ? -1 : 1;
    if (value == cb.value)
      return 0;
    return value.ult(cb.value) ? -1 : 1;
  }

  virtual unsigned computeHash() {
    Expr::Width w = getWidth();
    if (w <= 64)
      hashValue = value.getLimitedValue() ^ (w * Expr::MAGIC_HASH_CONSTANT);
    else
      hashValue = hash_value(value) ^ (w * Expr::MAGIC_HASH_CONSTANT);

    return hashValue;
  }

  void replaceKid(unsigned i, const ref<PerryExpr> &) { return; }

  static bool classof(const PerryExpr *E) {
    return E->getKind() == Expr::Constant;
  }

  static bool classof(const PerryConstantExpr *) { return true; }

  bool isTrue() const {
    return (getWidth() == Expr::Bool && value.getBoolValue() == true);
  }

  bool isFalse() const {
    return (getWidth() == Expr::Bool && value.getBoolValue() == false);
  }

  const llvm::APInt &getAPValue() const { return value; }

private:
  llvm::APInt value;
  PerryConstantExpr(const llvm::APInt &v) : value(v) {}
  PerryConstantExpr(const ConstantExpr *CE) : value(CE->getAPValue()) {}
  PerryConstantExpr(unsigned num_bits, uint64_t val) : value(num_bits, val) {}
};

class PerryReadExpr : public PerryExpr {
public:
  static const Expr::Kind kind = Expr::Read;
  static const unsigned numKids = 1;

  std::string Name;
  ref<PerryExpr> idx;
  Expr::Width width;

  static ref<PerryExpr> alloc(const std::string &_Name,
                              const ref<PerryExpr> &_idx,
                              const Expr::Width _width)
  {
    ref<PerryReadExpr> ret(new PerryReadExpr(_Name, _idx, _width));
    ret->computeHash();
    return ret;
  }

  static ref<PerryExpr> alloc(const ReadExpr *RE) {
    ref<PerryReadExpr> ret(new PerryReadExpr(RE));
    ret->computeHash();
    return ret;
  }
  
  Expr::Kind getKind() const { return Expr::Read; }

  Expr::Width getWidth() const { return width; }

  unsigned getNumKids() const { return 1; }

  ref<PerryExpr> getKid(unsigned i) const {
    return ((i == 0) ? idx : 0);
  }

  void print(llvm::raw_ostream &os) const {
    os << Expr::Read << " " << "w" << width << " " << Name << " (";
    idx->print(os);
    os << ")";
  }

  int compareContents(const PerryExpr &b) const {
    auto &rb = static_cast<const PerryReadExpr &>(b);

    auto rbWidth = rb.getWidth();
    if ((rbWidth == width) && (rb.Name == Name)) {
      return 0;
    } else if (rbWidth != width) {
      return (width < rbWidth) ? -1 : 1;
    } else {
      return Name.compare(rb.Name);
    }
  }

  virtual unsigned computeHash() {
    unsigned res = idx->hash() * Expr::MAGIC_HASH_CONSTANT;
    unsigned tmp = 0;
    for (unsigned i = 0, e = Name.size(); i != e; ++i) {
      tmp = (tmp * Expr::MAGIC_HASH_CONSTANT) + Name[i];
    }
    res ^= tmp;
    res ^= getWidth() * Expr::MAGIC_HASH_CONSTANT;
    hashValue = res;
    return hashValue;
  }

  void replaceKid(unsigned i, const ref<PerryExpr> &PE) {
    if (i == 0) {
      idx = PE;
      computeHash();
    }
  }

  static bool classof(const PerryExpr *E) {
    return E->getKind() == Expr::Read;
  }
  static bool classof(const PerryReadExpr *) { return true; }

private:
  PerryReadExpr(const std::string &_Name, const ref<PerryExpr> &_idx,
                const Expr::Width _width)
    : Name(_Name), idx(_idx), width(_width) {}

  PerryReadExpr(const ReadExpr *RE)
    : Name(RE->updates.root->getName()),
      idx(convertToPerryExpr(RE->index)),
      width(RE->updates.root->getRange()) {}
};

class PerrySelectExpr : public PerryExpr {
public:
  static const Expr::Kind kind = Expr::Select;
  static const unsigned numKids = 3;

  ref<PerryExpr> cond, trueExpr, falseExpr;

  static ref<PerryExpr> alloc(const ref<PerryExpr> &_cond,
                              const ref<PerryExpr> &_trueExpr,
                              const ref<PerryExpr> &_falseExpr)
  {
    ref<PerrySelectExpr> ret(new PerrySelectExpr(_cond, _trueExpr, _falseExpr));
    ret->computeHash();
    return ret;
  }

  static ref<PerryExpr> alloc(const SelectExpr *SE) {
    ref<PerrySelectExpr> ret(new PerrySelectExpr(SE));
    ret->computeHash();
    return ret;
  }
  
  Expr::Kind getKind() const { return Expr::Select; }

  Expr::Width getWidth() const { return trueExpr->getWidth(); }

  unsigned getNumKids() const { return 3; }
  ref<PerryExpr> getKid(unsigned i) const {
    switch (i) {
      case 0:
        return cond;
      case 1:
        return trueExpr;
      case 2:
        return falseExpr;
      default:
        return 0;
    }
  }
  ref<PerryExpr> getCond() const {
    return cond;
  }
  ref<PerryExpr> getTrueExpr() const {
    return trueExpr;
  }
  ref<PerryExpr> getFalseExpr() const {
    return falseExpr;
  }

  void print(llvm::raw_ostream &os) const {
    os << Expr::Select << " w" << getWidth() << " (";
    cond->print(os);
    os << ") ? [";
    trueExpr->print(os);
    os << "] : [";
    falseExpr->print(os);
    os << "]";
  }

  void replaceKid(unsigned i, const ref<PerryExpr> &PE) {
    switch (i) {
      case 0: {
        cond = PE;
        computeHash();
        break;
      }
      case 1: {
        trueExpr = PE;
        computeHash();
        break;
      }
      case 2: {
        falseExpr = PE;
        computeHash();
        break;
      }
      default: break;
    }
  }

  static bool classof(const PerryExpr *E) {
    return E->getKind() == Expr::Select;
  }
  static bool classof(const PerrySelectExpr *) { return true; }

protected:
  virtual int compareContents(const PerryExpr &b) const {
    // No attributes to compare.
    return 0;
  }

private:
  PerrySelectExpr(const ref<PerryExpr> &_cond,
                  const ref<PerryExpr> &_trueExpr,
                  const ref<PerryExpr> &_falseExpr)
    : cond(_cond), trueExpr(_trueExpr), falseExpr(_falseExpr) {}

  PerrySelectExpr(const SelectExpr *SE)
    : cond(convertToPerryExpr(SE->cond)),
      trueExpr(convertToPerryExpr(SE->trueExpr)),
      falseExpr(convertToPerryExpr(SE->falseExpr)) {}
};

class PerryConcatExpr : public PerryExpr {
public:
  static const Expr::Kind kind = Expr::Concat;
  static const unsigned numKids = 2;

  ref<PerryExpr> left, right;
  Expr::Width width;

  static ref<PerryExpr> alloc(const ref<PerryExpr> &_left,
                              const ref<PerryExpr> &_right)
  {
    ref<PerryConcatExpr> ret(new PerryConcatExpr(_left, _right));
    ret->computeHash();
    return ret;
  }

  static ref<PerryExpr> alloc(const ConcatExpr *CE) {
    ref<PerryConcatExpr> ret(new PerryConcatExpr(CE));
    ret->computeHash();
    return ret;
  }
  
  Expr::Kind getKind() const { return Expr::Concat; }

  Expr::Width getWidth() const { return width; }

  unsigned getNumKids() const { return 2; }

  ref<PerryExpr> getKid(unsigned i) const {
    switch (i) {
      case 0:
        return left;
      case 1:
        return right;
      default:
        return 0;
    }
  }
  ref<PerryExpr> getLeft() const {
    return left;
  }
  ref<PerryExpr> getRight() const {
    return right;
  }

  void print(llvm::raw_ostream &os) const {
    os << Expr::Concat << " w" << getWidth() << " (";
    left->print(os);
    os << ") (";
    right->print(os);
    os << ")";
  }

  void replaceKid(unsigned i, const ref<PerryExpr> &PE) {
    switch (i) {
      case 0: {
        left = PE;
        computeHash();
        break;
      }
      case 1: {
        right = PE;
        computeHash();
        break;
      }
      default: break;
    }
  }

  static bool classof(const PerryExpr *E) {
    return E->getKind() == Expr::Concat;
  }
  static bool classof(const PerryConcatExpr *) { return true; }

protected:
  virtual int compareContents(const PerryExpr &b) const {
    auto &eb = static_cast<const PerryConcatExpr &>(b);
    if (width != eb.width)
      return width < eb.width ? -1 : 1;
    return 0;
  }

private:
  PerryConcatExpr(const ref<PerryExpr> &_left,
                  const ref<PerryExpr> &_right)
    : left(_left), right(_right)
  {
    width = left->getWidth() + right->getWidth();
  }

  PerryConcatExpr(const ConcatExpr *CE)
    : left(convertToPerryExpr(CE->getLeft())),
      right(convertToPerryExpr(CE->getRight()))
  {   
    width = left->getWidth() + right->getWidth();
  }
};

class PerryExtractExpr : public PerryExpr {
public:
  static const Expr::Kind kind = Expr::Extract;
  static const unsigned numKids = 1;

  ref<PerryExpr> expr;
  unsigned offset;
  Expr::Width width;

  static ref<PerryExpr> alloc(const ref<PerryExpr> &_expr,
                              unsigned _offset,
                              Expr::Width _width)
  {
    ref<PerryExtractExpr> ret(new PerryExtractExpr(_expr, _offset, _width));
    ret->computeHash();
    return ret;
  }

  static ref<PerryExpr> alloc(const ExtractExpr *EE) {
    ref<PerryExtractExpr> ret(new PerryExtractExpr(EE));
    ret->computeHash();
    return ret;
  }
  
  Expr::Kind getKind() const { return Expr::Extract; }

  Expr::Width getWidth() const { return width; }

  unsigned getNumKids() const { return 1; }

  ref<PerryExpr> getKid(unsigned i) const {
    return ((i == 0) ? expr : 0);
  }

  void print(llvm::raw_ostream &os) const {
    os << Expr::Extract << " w" << width << " " << offset << " (";
    expr->print(os);
    os << ")";
  }

  int compareContents(const PerryExpr &b) const {
    auto &eb = static_cast<const PerryExtractExpr &>(b);
    if (offset != eb.offset) return offset < eb.offset ? -1 : 1;
    if (width != eb.width) return width < eb.width ? -1 : 1;
    return 0;
  }

  virtual unsigned computeHash() {
    unsigned res = offset * Expr::MAGIC_HASH_CONSTANT;
    res ^= getWidth() * Expr::MAGIC_HASH_CONSTANT;
    hashValue = res ^ expr->hash() * Expr::MAGIC_HASH_CONSTANT;
    return hashValue;
  }

  void replaceKid(unsigned i, const ref<PerryExpr> &PE) {
    if (i == 0) {
      expr = PE;
      computeHash();
    }
  }

  static bool classof(const PerryExpr *E) {
    return E->getKind() == Expr::Extract;
  }
  static bool classof(const PerryExtractExpr *) { return true; }

private:
  PerryExtractExpr(const ref<PerryExpr> &_expr,
                   unsigned _offset,
                   Expr::Width _width)
    : expr(_expr), offset(_offset), width(_width) {}

  PerryExtractExpr(const ExtractExpr *EE)
    : expr(convertToPerryExpr(EE->expr)),
      offset(EE->offset),
      width(EE->width) {}
};

class PerryCastExpr : public PerryExpr {
public:
  ref<PerryExpr> src;
  Expr::Width width;

  PerryCastExpr(const ref<PerryExpr> &_src, Expr::Width _width)
    : src(_src), width(_width) {}

  PerryCastExpr(const CastExpr *CE)
    : src(convertToPerryExpr(CE->src)), width(CE->width) {}
  
  Expr::Width getWidth() const { return width; }
  unsigned getNumKids() const { return 1; }

  ref<PerryExpr> getKid(unsigned i) const {return ((i == 0) ? src : 0);}

  void print(llvm::raw_ostream &os) const {
    os << getKind() << " w" << width << " (";
    src->print(os);
    os << ")";
  }

  int compareContents(const PerryExpr &b) const {
    auto &eb = static_cast<const PerryCastExpr &>(b);
    if (width != eb.width) return width < eb.width ? -1 : 1;
    return 0;
  }

  virtual unsigned computeHash() {
    unsigned res = getWidth() * Expr::MAGIC_HASH_CONSTANT;
    hashValue = res ^ src->hash() * Expr::MAGIC_HASH_CONSTANT;
    return hashValue;
  }

  void replaceKid(unsigned i, const ref<PerryExpr> &PE) {
    if (i == 0) {
      src = PE;
      computeHash();
    }
  }

  static bool classof(const PerryExpr *E) {
    Expr::Kind k = E->getKind();
    return (k == Expr::ZExt || k == Expr::SExt);
  }
  static bool classof(const PerryCastExpr *) { return true; }
};

#define CAST_PERRY_EXPR_CLASS(_class_kind)                                    \
class Perry ## _class_kind ## Expr : public PerryCastExpr {                   \
public:                                                                       \
  static const Expr::Kind kind = Expr::_class_kind;                           \
  static const unsigned numKids = 1;                                          \
  static ref<PerryExpr> alloc(const ref<PerryExpr> &_src,                     \
                              Expr::Width _width)                             \
  {                                                                           \
    ref<Perry ## _class_kind ## Expr> ret(new Perry ## _class_kind ## Expr(_src, _width));  \
    ret->computeHash();                                                       \
    return ret;                                                               \
  }                                                                           \
  static ref<PerryExpr> alloc(const _class_kind ## Expr *CE) {                \
    ref<Perry ## _class_kind ## Expr> ret(new Perry ## _class_kind ## Expr(CE));  \
    ret->computeHash();                                                       \
    return ret;                                                               \
  }                                                                           \
  Expr::Kind getKind() const { return Expr::_class_kind; }                    \
  static bool classof(const PerryExpr *E) {                                   \
    return E->getKind() == Expr::_class_kind;                                 \
  }                                                                           \
  static bool classof(const Perry ## _class_kind ## Expr *) { return true; }  \
private:                                                                      \
  Perry ## _class_kind ## Expr(const ref<PerryExpr> &_src,                    \
                               Expr::Width _width)                            \
    : PerryCastExpr(_src, _width) {}                                          \
  Perry ## _class_kind ## Expr(const _class_kind ## Expr *CE)                 \
    : PerryCastExpr(CE) { }                                                   \
};                                                                            \

CAST_PERRY_EXPR_CLASS(SExt)
CAST_PERRY_EXPR_CLASS(ZExt)

class PerryNotExpr : public PerryExpr {
public:
  static const Expr::Kind kind = Expr::Not;
  static const unsigned numKids = 1;

  ref<PerryExpr> expr;

  static ref<PerryExpr> alloc(const ref<PerryExpr> &_expr) {
    ref<PerryNotExpr> ret(new PerryNotExpr(_expr));
    ret->computeHash();
    return ret;
  }

  static ref<PerryExpr> alloc(const NotExpr *NE) {
    ref<PerryNotExpr> ret(new PerryNotExpr(NE));
    ret->computeHash();
    return ret;
  }

  Expr::Width getWidth() const { return expr->getWidth(); }
  Expr::Kind getKind() const { return Expr::Not; }

  unsigned getNumKids() const { return 1; }

  ref<PerryExpr> getKid(unsigned i) const {
    return ((i == 0) ? expr : 0);
  }

  void print(llvm::raw_ostream &os) const {
    os << Expr::Not << " w" << getWidth() << " (";
    expr->print(os);
    os << ")";
  }

  virtual unsigned computeHash() {
    hashValue = expr->hash() * Expr::MAGIC_HASH_CONSTANT * Expr::Not;
    return hashValue;
  }

  void replaceKid(unsigned i, const ref<PerryExpr> &PE) {
    if (i == 0) {
      expr = PE;
      computeHash();
    }
  }

  static bool classof(const PerryExpr *E) { return E->getKind() == Expr::Not; }
  static bool classof(const PerryNotExpr *) { return true; }

protected:
  virtual int compareContents(const PerryExpr &b) const {
    // No attributes to compare.
    return 0;
  }

private:
  PerryNotExpr(const ref<PerryExpr> &_expr) : expr(_expr) {}

  PerryNotExpr(const NotExpr *NE)
    : expr(convertToPerryExpr(NE->expr)) {}
};

class PerryBinaryExpr : public PerryExpr {
public:
  ref<PerryExpr> left, right;

  unsigned getNumKids() const { return 2; }
  ref<PerryExpr> getKid(unsigned i) const {
    switch (i) {
      case 0:
        return left;
      case 1:
        return right;
      default:
        return 0;
    }
  }

  ref<PerryExpr> getLeft() const { return left; }
  ref<PerryExpr> getRight() const { return right; }

  void print(llvm::raw_ostream &os) const {
    os << getKind() << " w" << getWidth() << " (";
    left->print(os);
    os << ") (";
    right->print(os);
    os << ")";
  }

  void replaceKid(unsigned i, const ref<PerryExpr> &PE) {
    switch (i) {
      case 0: {
        left = PE;
        computeHash();
        break;
      }
      case 1: {
        right = PE;
        computeHash();
        break;
      }
      default: break;
    }
  }

protected:
  PerryBinaryExpr(const ref<PerryExpr> &l, const ref<PerryExpr> &r)
    : left(l), right(r) {}

  PerryBinaryExpr(const BinaryExpr *BE)
    : left(convertToPerryExpr(BE->left)),
      right(convertToPerryExpr(BE->right)) {}

public:
  static bool classof(const PerryExpr *E) {
    Expr::Kind k = E->getKind();
    return (Expr::BinaryKindFirst <= k && k <= Expr::BinaryKindLast);
  }
  static bool classof(const PerryBinaryExpr *) { return true; }
};

#define PERRY_ARITHMETIC_EXPR_CLASS(_class_kind)                              \
class Perry ## _class_kind ## Expr : public PerryBinaryExpr {                 \
public:                                                                       \
  static const Expr::Kind kind = Expr::_class_kind;                           \
  static const unsigned numKids = 2;                                          \
  static ref<PerryExpr> alloc(const ref<PerryExpr> &l,                        \
                              const ref<PerryExpr> &r)                        \
  {                                                                           \
    ref<Perry ## _class_kind ## Expr> ret(new Perry ## _class_kind ## Expr(l, r));  \
    ret->computeHash();                                                       \
    return ret;                                                               \
  }                                                                           \
  static ref<PerryExpr> alloc(const _class_kind ## Expr *CE) {                \
    ref<Perry ## _class_kind ## Expr> ret(new Perry ## _class_kind ## Expr(CE));  \
    ret->computeHash();                                                       \
    return ret;                                                               \
  }                                                                           \
  Expr::Width getWidth() const { return left->getWidth(); }                   \
  Expr::Kind getKind() const { return Expr::_class_kind; }                    \
  static bool classof(const PerryExpr *E) {                                   \
    return E->getKind() == Expr::_class_kind;                                 \
  }                                                                           \
  static bool classof(const Perry ## _class_kind ## Expr *) { return true; }  \
protected:                                                                    \
  virtual int compareContents(const PerryExpr &b) const {                     \
    /* No attributes to compare.*/                                            \
    return 0;                                                                 \
  }                                                                           \
private:                                                                      \
  Perry ## _class_kind ## Expr(const ref<PerryExpr> &l,                       \
                               const ref<PerryExpr> &r)                       \
    : PerryBinaryExpr(l, r) {}                                                \
  Perry ## _class_kind ## Expr(const _class_kind ## Expr *CE)                 \
    : PerryBinaryExpr(CE) {}                                                  \
};                                                                            \

PERRY_ARITHMETIC_EXPR_CLASS(Add)
PERRY_ARITHMETIC_EXPR_CLASS(Sub)
PERRY_ARITHMETIC_EXPR_CLASS(Mul)
PERRY_ARITHMETIC_EXPR_CLASS(UDiv)
PERRY_ARITHMETIC_EXPR_CLASS(SDiv)
PERRY_ARITHMETIC_EXPR_CLASS(URem)
PERRY_ARITHMETIC_EXPR_CLASS(SRem)
PERRY_ARITHMETIC_EXPR_CLASS(And)
PERRY_ARITHMETIC_EXPR_CLASS(Or)
PERRY_ARITHMETIC_EXPR_CLASS(Xor)
PERRY_ARITHMETIC_EXPR_CLASS(Shl)
PERRY_ARITHMETIC_EXPR_CLASS(LShr)
PERRY_ARITHMETIC_EXPR_CLASS(AShr)

class PerryCmpExpr : public PerryBinaryExpr {
protected:
  PerryCmpExpr(const ref<PerryExpr> &l, const ref<PerryExpr> &r)
    : PerryBinaryExpr(l, r) {}
  PerryCmpExpr(const CmpExpr *CE)
    : PerryBinaryExpr(CE) {}
public:
  Expr::Width getWidth() const { return Expr::Bool; }
  void print(llvm::raw_ostream &os) const {
    os << getKind() << " (";
    left->print(os);
    os << ") (";
    right->print(os);
    os << ")";
  }
  static bool classof(const PerryExpr *E) {
    Expr::Kind k = E->getKind();
    return (Expr::CmpKindFirst <= k && k <= Expr::CmpKindLast);
  }
  static bool classof(const PerryCmpExpr *) { return true; }
};

#define PERRY_COMPARISON_EXPR_CLASS(_class_kind)                              \
class Perry ## _class_kind ## Expr : public PerryCmpExpr {                    \
public:                                                                       \
  static const Expr::Kind kind = Expr::_class_kind;                           \
  static const unsigned numKids = 2;                                          \
  static ref<PerryExpr> alloc(const ref<PerryExpr> &l,                        \
                              const ref<PerryExpr> &r)                        \
  {                                                                           \
    ref<Perry ## _class_kind ## Expr> ret(new Perry ## _class_kind ## Expr(l, r));  \
    ret->computeHash();                                                       \
    return ret;                                                               \
  }                                                                           \
  static ref<PerryExpr> alloc(const _class_kind ## Expr *CE) {                \
    ref<Perry ## _class_kind ## Expr> ret(new Perry ## _class_kind ## Expr(CE));  \
    ret->computeHash();                                                       \
    return ret;                                                               \
  }                                                                           \
  Expr::Kind getKind() const { return Expr::_class_kind; }                    \
  static bool classof(const PerryExpr *E) {                                   \
    return E->getKind() == Expr::_class_kind;                                 \
  }                                                                           \
  static bool classof(const Perry ## _class_kind ## Expr *) { return true; }  \
protected:                                                                    \
  virtual int compareContents(const PerryExpr &b) const {                     \
    /* No attributes to compare.*/                                            \
    return 0;                                                                 \
  }                                                                           \
private:                                                                      \
  Perry ## _class_kind ## Expr(const ref<PerryExpr> &l,                       \
                               const ref<PerryExpr> &r)                       \
    : PerryCmpExpr(l, r) {}                                                   \
  Perry ## _class_kind ## Expr(const _class_kind ## Expr *CE)                 \
    : PerryCmpExpr(CE) {}                                                     \
};                                                                            \

PERRY_COMPARISON_EXPR_CLASS(Eq)
PERRY_COMPARISON_EXPR_CLASS(Ne)
PERRY_COMPARISON_EXPR_CLASS(Ult)
PERRY_COMPARISON_EXPR_CLASS(Ule)
PERRY_COMPARISON_EXPR_CLASS(Ugt)
PERRY_COMPARISON_EXPR_CLASS(Uge)
PERRY_COMPARISON_EXPR_CLASS(Slt)
PERRY_COMPARISON_EXPR_CLASS(Sle)
PERRY_COMPARISON_EXPR_CLASS(Sgt)
PERRY_COMPARISON_EXPR_CLASS(Sge)

}
#endif