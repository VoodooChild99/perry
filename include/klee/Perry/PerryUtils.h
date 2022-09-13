#ifndef __PERRY_SYM_READ_H__
#define __PERRY_SYM_READ_H__

#include <string>
#include "klee/Perry/PerryTrace.h"
#include "llvm/Support/raw_os_ostream.h"
#include <iostream>

namespace klee {

struct SymRead {
  std::string name;
  unsigned idx;
  unsigned width;

  SymRead(const std::string &_name, unsigned _idx, unsigned _width)
    : name(_name), idx(_idx), width(_width) { }
  
  SymRead(const SymRead &SR)
    : name(SR.name), idx(SR.idx), width(SR.width) { }

  bool operator<(const SymRead &SR) const {
    int name_cmp = name.compare(SR.name);
    if (name_cmp < 0) {
      return true;
    } else if (name_cmp == 0) {
      if (idx < SR.idx) {
        return true;
      } else if (idx == SR.idx) {
        if (width < SR.width) {
          return true;
        } else {
          return false;
        }
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  bool relatedWith(const SymRead &SR) const {
    if (name != SR.name) {
      return false;
    }
    auto this_end = idx + (width / 8);
    auto that_end = SR.idx + (SR.width / 8);
    if (SR.idx >= this_end || idx >= that_end) {
      return false;
    }
    return true;
  }

  bool operator==(const SymRead &SR) const {
    return ((name == SR.name) && (idx == SR.idx) && (width == SR.width));
  }

  SymRead& operator=(const SymRead &SR) {
    name = SR.name;
    idx = SR.idx;
    width = SR.width;
    return *this;
  }

  friend std::ostream &operator<<(std::ostream &os, const SymRead &SR) {
    os << SR.name << ":" << SR.idx << ":" << SR.width;
    return os;
  }

  friend llvm::raw_ostream &operator<<(llvm::raw_ostream &os,
                                       const SymRead &SR)
  {
    os << SR.name << ":" << SR.idx << ":" << SR.width;
    return os;
  }

  std::string to_string() const {
    std::string ret;
    llvm::raw_string_ostream OS(ret);
    OS << *this;
    return ret;
  }
};

struct DependentItemKey {
  SymRead sym;
  ref<PerryExpr> expr;
  std::vector<ref<PerryExpr>> constraints;

  DependentItemKey(const SymRead &SR, const ref<PerryExpr> &_expr,
                   const std::vector<ref<PerryExpr>> &_constraints)
    : sym(SR), expr(_expr), constraints(_constraints) {}

  bool operator<(const DependentItemKey &DI) const {
    if (sym == DI.sym) {
      int expr_cmp = expr->compare(*DI.expr);
      if (expr_cmp < 0) {
        return true;
      } else if (expr_cmp > 0) {
        return false;
      } else {
        unsigned num_cs_this = constraints.size();
        unsigned num_cs_that = DI.constraints.size();
        if (num_cs_this < num_cs_that) {
          return true;
        } else if (num_cs_this > num_cs_that) {
          return false;
        } else {
          for (unsigned i = 0; i < num_cs_this; ++i) {
            expr_cmp = constraints[i]->compare(*DI.constraints[i]);
            if (expr_cmp < 0) {
              return true;
            } else if (expr_cmp > 0) {
              return false;
            }
          }
          return false;
        }
      }
    } else if (sym < DI.sym) {
      return true;
    } else {
      return false;
    }
  }

  friend std::ostream &operator<<(std::ostream &os,
                                  const DependentItemKey &DI) {
    std::string tmp;
    llvm::raw_string_ostream OS(tmp);
    OS << "Loc: " << DI.sym << "\n";
    OS << "Expr: ";
    DI.expr->print(OS);
    OS << "\n";
    OS << "Constraints:\n";
    for (auto PE : DI.constraints) {
      OS << "\t";
      PE->print(OS);
      OS << ",\n";
    }
    return os;
  }

  friend llvm::raw_ostream &operator<<(llvm::raw_ostream &os,
                                       const DependentItemKey &DI)
  {
    os << "Loc: " << DI.sym << "\n";
    os << "Expr: ";
    DI.expr->print(os);
    os << "\n";
    os << "Constraints:\n";
    for (auto PE : DI.constraints) {
      os << "\t";
      PE->print(os);
      os << ",\n";
    }
    return os;
  }

};

// using PerryRRDependentMap = std::map<DependentItem, std::set<DependentItem>>;

struct DependentItemVal {
  SymRead sym;
  SymRead before_sym;
  ref<PerryExpr> before;
  ref<PerryExpr> after;
  std::vector<ref<PerryExpr>> constraints;

  DependentItemVal(const SymRead &SR,
                   const ref<PerryExpr> &_before,
                   const ref<PerryExpr> &_after,
                   const std::vector<ref<PerryExpr>> &_constraints)
    : sym(SR), before_sym(SR),
      before(_before), after(_after), constraints(_constraints) {}

  bool operator<(const DependentItemVal &DI) const {
    if (sym == DI.sym) {
      if (!before && DI.before) {
        return true;
      } else if (before && !DI.before) {
        return false;
      } else {
        int expr_cmp;
        if (before && DI.before) {
          expr_cmp = before->compare(*DI.before);
          if (expr_cmp < 0) {
            return true;
          } else if (expr_cmp > 0) {
            return false;
          }
        }
        // same before
        if (before_sym == DI.before_sym) {
          expr_cmp = after->compare(*DI.after);
          if (expr_cmp < 0) {
            return true;
          } else if (expr_cmp > 0) {
            return false;
          } else {
            unsigned num_cs_this = constraints.size();
            unsigned num_cs_that = DI.constraints.size();
            if (num_cs_this < num_cs_that) {
              return true;
            } else if (num_cs_this > num_cs_that) {
              return false;
            } else {
              for (unsigned i = 0; i < num_cs_this; ++i) {
                expr_cmp = constraints[i]->compare(*DI.constraints[i]);
                if (expr_cmp < 0) {
                  return true;
                } else if (expr_cmp > 0) {
                  return false;
                }
              }
              return false;
            }
          }
        } else if (before_sym < DI.before_sym) {
          return true;
        } else {
          return false;
        }
      }
    } else if (sym < DI.sym) {
      return true;
    } else {
      return false;
    }
  }

  friend std::ostream &operator<<(std::ostream &os,
                                  const DependentItemVal &DI) {
    std::string tmp;
    llvm::raw_string_ostream OS(tmp);
    OS << "Loc: " << DI.sym << "\n";
    OS << "Expr Before: ";
    if (DI.before) {
      DI.before->print(OS);
    }
    OS << "\n";
    OS << "Expr After: ";
    DI.after->print(OS);
    OS << "\n";
    OS << "Constraints:\n";
    for (auto PE : DI.constraints) {
      OS << "\t";
      PE->print(OS);
      OS << ",\n";
    }
    return os;
  }

  friend llvm::raw_ostream &operator<<(llvm::raw_ostream &os,
                                       const DependentItemVal &DI)
  {
    os << "Loc: " << DI.sym << "\n";
    os << "Expr Before: ";
    if (DI.before) {
      DI.before->print(os);
    }
    os << "\n";
    os << "Expr After: ";
    DI.after->print(os);
    os << "\n";
    os << "Constraints:\n";
    for (auto PE : DI.constraints) {
      os << "\t";
      PE->print(os);
      os << ",\n";
    }
    return os;
  }
};

using PerryDependentMap
  = std::map<DependentItemKey, std::set<DependentItemVal>>;


}

#endif