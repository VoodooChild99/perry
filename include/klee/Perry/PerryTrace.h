#ifndef __PERRY_TRACE_H__
#define __PERRY_TRACE_H__

#include "llvm/IR/Instruction.h"

#include "klee/Expr/Expr.h"
#include "klee/Taint/Taint.h"
#include "klee/Expr/Constraints.h"
#include "klee/Perry/PerryExpr.h"

namespace klee {

struct RegisterAccess {
  enum Type{
    NONE = 0,
    REG_READ,
    REG_WRITE
  };

  class ReferenceCounter _refCount;

  Type AccessType = NONE;
  TaintTy idx;
  ref<PerryExpr> ExprInReg;
  std::string name;
  unsigned offset;
  unsigned width;
  llvm::Instruction *place;

  static ref<RegisterAccess>
  alloc(TaintTy _idx, Type _AccessType,
        const std::string &_name, unsigned _offset, unsigned _width,
        const ref<PerryExpr> &_ExprInReg = 0,
        llvm::Instruction *_place = nullptr)
  {
    ref<RegisterAccess> ret(new RegisterAccess(
      _idx, _AccessType, _name, _offset, _width, _ExprInReg, _place));
    return ret;
  }

private:
  // RegisterAccess() = default;
  
  RegisterAccess(TaintTy _idx, Type _AccessType,
                 const std::string &_name, unsigned _offset, unsigned _width,
                 const ref<PerryExpr> &_ExprInReg,
                 llvm::Instruction *_place)
    : AccessType(_AccessType), idx(_idx), ExprInReg(_ExprInReg),
      name(_name), offset(_offset), width(_width), place(_place) {}

public:
  bool operator<(const RegisterAccess &RA) const {
    int name_compare = name.compare(RA.name);
    if (name_compare < 0) {
      return true;
    } else if (name_compare > 0) {
      return false;
    } else {
      if (AccessType < RA.AccessType) {
        return true;
      } else if (AccessType > RA.AccessType) {
        return false;
      } else {
        if (offset < RA.offset) {
          return true;
        } else if (offset > RA.offset) {
          return false;
        } else {
          if (width < RA.width) {
            return true;
          } else if (width > RA.width) {
            return false;
          } else {
            if (idx < RA.idx) {
              return true;
            } else if (idx > RA.idx) {
              return false;
            } else {
              int expr_cmp = ExprInReg->compare(*RA.ExprInReg);
              if (expr_cmp < 0) {
                return true;
              } else if (expr_cmp > 0) {
                return false;
              } else {
                return (place < RA.place);
              }
            }
          }
        }
      }
    }
  }

  friend llvm::raw_ostream &operator<<(llvm::raw_ostream &os,
                                       const RegisterAccess &RA) {
    if (RA.AccessType == REG_READ) {
      os << "Read ";
    } else if (RA.AccessType == REG_WRITE) {
      os << "Write ";
    } else {
      os << "UNKNOWN ";
    }

    os << "|" << RA.name << ":" << RA.offset << ":" << RA.width << "| --> ";
    RA.ExprInReg->print(os);
    os << "\n";
    return os;
  }
};

class PerryTrace {
public:
  using Constraints = std::vector<ref<PerryExpr>>;
  // <register access, total number of constraints collected so far>
  // the idx will be used on the final constraint on this path
  struct PerryTraceItem {
    unsigned reg_access_idx;
    // unsigned constraint_idx;
    Constraints cur_constraints;

    PerryTraceItem(unsigned _reg_access_idx,
                   const std::vector<ref<PerryExpr>> &_cur_constraints)
      : reg_access_idx(_reg_access_idx),
        cur_constraints(std::move(_cur_constraints)) {}
  };
  using perry_trace_ty = std::vector<PerryTraceItem>;
  using iterator = perry_trace_ty::iterator;
  using const_iterator = perry_trace_ty::const_iterator;
  using perry_trace_iterator = const_iterator;

  bool empty() const;
  perry_trace_iterator begin() const;
  perry_trace_iterator end() const;
  size_t size() const noexcept;
  perry_trace_iterator erase(perry_trace_iterator it);
  void setTaintSet(TaintSet &_ts) { ts = _ts; }
  const TaintSet& getTaintSet() const { return ts; }
  PerryTraceItem& back() { return trace.back(); }
  const PerryTraceItem& back() const { return trace.back(); }
  const PerryTraceItem& operator[](std::size_t i) const { return trace[i]; }

  PerryTrace() = default;
  PerryTrace(const PerryTrace &);

  void emplace_back(PerryTraceItem &&PTI);
  void push_back(const PerryTraceItem &PTI);

private:
  perry_trace_ty trace;
  TaintSet ts;
};

struct PerryCheckPoint {
  unsigned ptrace_size;
  unsigned reg_access_size;
  unsigned reg_access_size_post;
  ref<PerryExpr> condition;
  PerryTrace::Constraints constraints;

  PerryCheckPoint(unsigned ptrace_size, unsigned reg_access_size,
                  unsigned reg_access_size_post,
                  const ref<PerryExpr> &condition,
                  const PerryTrace::Constraints &constraints)
    : ptrace_size(ptrace_size), reg_access_size(reg_access_size),
      reg_access_size_post(reg_access_size_post),
      condition(condition), constraints(constraints) {}

  PerryCheckPoint(const PerryCheckPoint &CP)
    : ptrace_size(CP.ptrace_size), reg_access_size(CP.reg_access_size),
      reg_access_size_post(CP.reg_access_size_post),
      condition(CP.condition), constraints(CP.constraints) {}
};

struct PerryCheckPointInternal {
  unsigned ptrace_size;
  unsigned reg_access_size;
  ref<Expr> condition;
  ConstraintSet constraints;
  llvm::MDNode *pc = nullptr;

  PerryCheckPointInternal() = default;

  PerryCheckPointInternal(unsigned ptrace_size, unsigned reg_access_size,
                          const ref<Expr> &condition,
                          const ConstraintSet &constraints,
                          llvm::MDNode *pc)
    : ptrace_size(ptrace_size), reg_access_size(reg_access_size),
      condition(condition), constraints(constraints), pc(pc) {}

  PerryCheckPointInternal(const PerryCheckPointInternal &CP)
    : ptrace_size(CP.ptrace_size), reg_access_size(CP.reg_access_size),
      condition(CP.condition), constraints(CP.constraints), pc(CP.pc) {}
  
  inline PerryCheckPointInternal &operator=(const PerryCheckPointInternal &CP) {
    if (this == &CP) {
      return *this;
    }
    ptrace_size = CP.ptrace_size;
    reg_access_size = CP.reg_access_size;
    condition = CP.condition;
    constraints = CP.constraints;
    pc = CP.pc;
    return *this;
  }
};

struct PerryHook {
  std::string hook_name;
  PerryTrace::Constraints constraints;

  PerryHook(const std::string &hook_name, const PerryTrace::Constraints &constraints)
    : hook_name(hook_name), constraints(constraints) {}
};

struct PerryRecord {
  bool success = false;
  uint64_t return_value = 0xdeadbeef;
  PerryTrace::Constraints final_constraints;
  std::vector<ref<RegisterAccess>> register_accesses;
  PerryTrace trace;
  std::vector<PerryCheckPoint> checkpoints;
  std::vector<PerryHook> triggerred_hooks;
  
  PerryRecord(bool _success, uint64_t _return_value,
              const PerryTrace::Constraints &_final_constraints,
              const std::vector<ref<RegisterAccess>> &_register_accesses,
              const PerryTrace &_trace,
              const std::vector<PerryCheckPoint> &_checkpoints,
              const std::vector<PerryHook> &_triggerred_hooks)
    : success(_success), return_value(_return_value),
      final_constraints(std::move(_final_constraints)),
      register_accesses(std::move(_register_accesses)),
      trace(std::move(_trace)),
      checkpoints(std::move(_checkpoints)),
      triggerred_hooks(std::move(_triggerred_hooks)) {}
};

}

#endif