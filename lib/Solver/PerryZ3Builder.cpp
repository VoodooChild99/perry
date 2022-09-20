#include "klee/Perry/PerryZ3Builder.h"

#include <stack>
#include <iostream>
#include <regex>

using namespace klee;

z3::expr PerryZ3Builder::toZ3Expr(const ref<PerryExpr> &PE) {
  switch (PE->getKind()) {
    case Expr::Constant: {
      const PerryConstantExpr *CE = cast<PerryConstantExpr>(PE);
      if (CE->getWidth() == Expr::Bool) {
        return CE->isTrue() ? ctx.bool_val(true) : ctx.bool_val(false);
      }
      return ctx.bv_val(CE->getAPValue().getZExtValue(), CE->getWidth());
    }
    case Expr::Read: {
      const PerryReadExpr *RE = cast<PerryReadExpr>(PE);
      if (RE->idx->getKind() != Expr::Constant) {
        std::string err_msg;
        llvm::raw_string_ostream OS(err_msg);
        OS << "Symbolic idx is not supported "
           << "when converting a PerryReadExpr to a Z3 expression: ";
        RE->idx->print(OS);
        klee_error("%s", err_msg.c_str());
      }
      PerryConstantExpr *CE = cast<PerryConstantExpr>(RE->idx.get());
      // auto const_ce = CE->getAPValue().getZExtValue();
      // align by 4 bytes
      // auto base_ce = (const_ce & ~(3UL));
      // auto offset_ce = (const_ce & 4UL);
      std::string symName 
        = RE->Name + ":" + std::to_string(CE->getAPValue().getZExtValue())
                   + ":" + std::to_string(RE->getWidth());
      return ctx.bv_const(symName.c_str(), RE->getWidth());
    }
    case Expr::Select: {
      const PerrySelectExpr *SE = cast<PerrySelectExpr>(PE);
      auto cond = toZ3Expr(SE->getCond());
      auto trueExpr = toZ3Expr(SE->getTrueExpr());
      auto falseExpr = toZ3Expr(SE->getFalseExpr());
      return z3::ite(cond, trueExpr, falseExpr);
    }
    case Expr::Concat: {
      const PerryConcatExpr *CE = cast<PerryConcatExpr>(PE);
      auto left = toZ3Expr(CE->getLeft());
      auto right = toZ3Expr(CE->getRight());
      return z3::concat(left, right);
    }
    case Expr::Extract: {
      const PerryExtractExpr *EE = cast<PerryExtractExpr>(PE);
      auto expr = toZ3Expr(EE->expr.get());
      return expr.extract(EE->offset + EE->width - 1, EE->offset);
    }
    case Expr::ZExt: {
      const PerryZExtExpr *ZE = cast<PerryZExtExpr>(PE);
      auto src = toZ3Expr(ZE->src.get());
      return z3::zext(src, ZE->getWidth() - ZE->src->getWidth());
    }
    case Expr::SExt: {
      const PerrySExtExpr *SE = cast<PerrySExtExpr>(PE);
      auto src = toZ3Expr(SE->src.get());
      return z3::sext(src, SE->getWidth() - SE->src->getWidth());
    }
    case Expr::Not: {
      const PerryNotExpr *NE = cast<PerryNotExpr>(PE);
      auto expr = toZ3Expr(NE->expr.get());
      if (NE->getWidth() == Expr::Bool) {
        return !expr;
      } else {
        return ~expr;
      }
    }
    case Expr::Add: {
      const PerryAddExpr *AE = cast<PerryAddExpr>(PE);
      auto left = toZ3Expr(AE->getLeft());
      auto right = toZ3Expr(AE->getRight());
      return (left + right);
    }
    case Expr::Sub: {
      const PerrySubExpr *SE = cast<PerrySubExpr>(PE);
      auto left = toZ3Expr(SE->getLeft());
      auto right = toZ3Expr(SE->getRight());
      return (left - right);
    }
    case Expr::Mul: {
      const PerryMulExpr *ME = cast<PerryMulExpr>(PE);
      auto left = toZ3Expr(ME->getLeft());
      auto right = toZ3Expr(ME->getRight());
      return (left * right);
    }
    case Expr::UDiv: {
      const PerryUDivExpr *UE = cast<PerryUDivExpr>(PE);
      auto left = toZ3Expr(UE->getLeft());
      if (PerryConstantExpr *CE = dyn_cast<PerryConstantExpr>(UE->getRight())) {
        uint64_t divisor = CE->getAPValue().getZExtValue();
        if (bits64::isPowerOfTwo(divisor)) {
          unsigned shift = bits64::indexOfSingleBit(divisor);
          return z3::concat(ctx.bv_val(0, shift),
                            left.extract(UE->getWidth() - 1, shift));
        }
      }
      auto right = toZ3Expr(UE->getRight());
      return z3::udiv(left, right);
    }
    case Expr::SDiv: {
      const PerrySDivExpr *SE = cast<PerrySDivExpr>(PE);
      auto left = toZ3Expr(SE->getLeft());
      auto right = toZ3Expr(SE->getRight());
      return (left / right);
    }
    case Expr::URem: {
      const PerryURemExpr *UE = cast<PerryURemExpr>(PE);
      auto left = toZ3Expr(UE->getLeft());
      if (PerryConstantExpr *CE = dyn_cast<PerryConstantExpr>(UE->getRight())) {
        uint64_t divisor = CE->getAPValue().getZExtValue();
        if (bits64::isPowerOfTwo(divisor)) {
          int bits = bits64::indexOfSingleBit(divisor);
          if (bits == 0) {
            return ctx.bv_val(0, UE->getLeft()->getWidth());
          } else {
            return z3::concat(ctx.bv_val(0, UE->getWidth() - bits),
                              left.extract(bits - 1, 0));
          }
        }
      }
      auto right = toZ3Expr(UE->getRight());
      return z3::urem(left, right);
    }
    case Expr::SRem: {
      const PerrySRemExpr *SE = cast<PerrySRemExpr>(PE);
      auto left = toZ3Expr(SE->getLeft());
      auto right = toZ3Expr(SE->getRight());
      return z3::srem(left, right);
    }
    case Expr::And: {
      const PerryAndExpr *AE = cast<PerryAndExpr>(PE);
      auto left = toZ3Expr(AE->getLeft());
      auto right = toZ3Expr(AE->getRight());
      return (left & right);
    }
    case Expr::Or: {
      const PerryOrExpr *OE = cast<PerryOrExpr>(PE);
      auto left = toZ3Expr(OE->getLeft());
      auto right = toZ3Expr(OE->getRight());
      return (left | right);
    }
    case Expr::Xor: {
      const PerryXorExpr *XE = cast<PerryXorExpr>(PE);
      auto left = toZ3Expr(XE->getLeft());
      auto right = toZ3Expr(XE->getRight());
      return (left ^ right);
    }
    case Expr::Shl: {
      const PerryShlExpr *SE = cast<PerryShlExpr>(PE);
      auto left = toZ3Expr(SE->getLeft());
      if (PerryConstantExpr *CE = dyn_cast<PerryConstantExpr>(SE->getRight())) {
        unsigned shift = CE->getAPValue().getZExtValue();
        if (shift == 0) {
          return left;
        } else if (shift >= SE->getWidth()) {
          return ctx.bv_val(0, SE->getWidth());
        } else {
          return z3::concat(left.extract(SE->getWidth() - shift - 1, 0),
                            ctx.bv_val(0, shift));
        }
      } else {
        auto right = toZ3Expr(SE->getRight());
        return z3::shl(left, right);
      }
    }
    case Expr::LShr: {
      const PerryLShrExpr *LE = cast<PerryLShrExpr>(PE);
      auto left = toZ3Expr(LE->getLeft());
      if (PerryConstantExpr *CE = dyn_cast<PerryConstantExpr>(LE->getRight())) {
        unsigned shift = CE->getAPValue().getZExtValue();
        if (shift == 0) {
          return left;
        } else if (shift >= LE->getWidth()) {
          return ctx.bv_val(0, LE->getWidth());
        } else {
          return z3::concat(ctx.bv_val(0, shift),
                            left.extract(LE->getWidth() - 1, shift));
        }
      } else {
        auto right = toZ3Expr(LE->getRight());
        return z3::lshr(left, right);
      }
    }
    case Expr::AShr: {
      const PerryAShrExpr *AE = cast<PerryAShrExpr>(PE);
      auto left = toZ3Expr(AE->getLeft());
      if (PerryConstantExpr *CE = dyn_cast<PerryConstantExpr>(AE->getRight())) {
        unsigned shift = CE->getAPValue().getZExtValue();
        if (shift == 0) {
          return left;
        } else if (shift >= AE->getWidth()) {
          return ctx.bv_val(0, AE->getWidth());
        }
      }
      auto right = toZ3Expr(AE->getRight());
      return z3::ashr(left, right);
    }
    case Expr::Eq: {
      const PerryEqExpr *EE = cast<PerryEqExpr>(PE);
      auto left = toZ3Expr(EE->getLeft());
      auto right = toZ3Expr(EE->getRight());
      return (left == right);
    }
    case Expr::Ne: {
      const PerryNeExpr *NE = cast<PerryNeExpr>(PE);
      auto left = toZ3Expr(NE->getLeft());
      auto right = toZ3Expr(NE->getRight());
      return (left != right);
    }
    case Expr::Ult: {
      const PerryUltExpr *UE = cast<PerryUltExpr>(PE);
      auto left = toZ3Expr(UE->getLeft());
      auto right = toZ3Expr(UE->getRight());
      return z3::ult(left, right);
    }
    case Expr::Ule: {
      const PerryUleExpr *UE = cast<PerryUleExpr>(PE);
      auto left = toZ3Expr(UE->getLeft());
      auto right = toZ3Expr(UE->getRight());
      return z3::ule(left, right);
    }
    case Expr::Ugt: {
      const PerryUgtExpr *UE = cast<PerryUgtExpr>(PE);
      auto left = toZ3Expr(UE->getLeft());
      auto right = toZ3Expr(UE->getRight());
      return z3::ugt(left, right);
    }
    case Expr::Uge: {
      const PerryUgeExpr *UE = cast<PerryUgeExpr>(PE);
      auto left = toZ3Expr(UE->getLeft());
      auto right = toZ3Expr(UE->getRight());
      return z3::uge(left, right);
    }
    case Expr::Slt: {
      const PerrySltExpr *SE = cast<PerrySltExpr>(PE);
      auto left = toZ3Expr(SE->getLeft());
      auto right = toZ3Expr(SE->getRight());
      return z3::slt(left, right);
    }
    case Expr::Sle: {
      const PerrySleExpr *SE = cast<PerrySleExpr>(PE);
      auto left = toZ3Expr(SE->getLeft());
      auto right = toZ3Expr(SE->getRight());
      return z3::sle(left, right);
    }
    case Expr::Sgt: {
      const PerrySgtExpr *SE = cast<PerrySgtExpr>(PE);
      auto left = toZ3Expr(SE->getLeft());
      auto right = toZ3Expr(SE->getRight());
      return z3::sgt(left, right);
    }
    case Expr::Sge: {
      const PerrySgeExpr *SE = cast<PerrySgeExpr>(PE);
      auto left = toZ3Expr(SE->getLeft());
      auto right = toZ3Expr(SE->getRight());
      return z3::sge(left, right);
    }
    default: {
      klee_error("Unhandled PerryExpr type when building Z3 expressions.");
    }
  }
}

z3::expr PerryZ3Builder::
toZ3ExprBatchOr(const std::vector<std::vector<ref<PerryExpr>>> &CS) {
  // inner constraints are and-ed together
  // outter constraints are or-ed together
  z3::expr_vector outter(ctx);
  unsigned num_outter = CS.size();
  for (unsigned i = 0; i < num_outter; ++i) {
    outter.push_back(toZ3ExprAnd(CS[i]));
  }
  unsigned outter_size = outter.size();
  if (outter_size == 0) {
    return ctx.bool_val(true);
  } else if (outter_size == 1) {
    return outter[0];
  } else {
    return z3::mk_or(outter);
  }
}

z3::expr PerryZ3Builder::
toZ3ExprAnd(const std::vector<ref<PerryExpr>> &CS) {
  z3::expr_vector tmp(ctx);
  for (auto &c : CS) {
    auto single = toZ3Expr(c);
    if (containsUnsupportedExpr(single)) {
      klee_warning("Unsupported z3 expression in constraints: %s, ignore",
                   single.to_string().c_str());
      continue;
    }
    tmp.push_back(single);
  }
  unsigned tmp_size = tmp.size();
  if (tmp_size == 0) {
    return ctx.bool_val(true);
  } else if (tmp_size == 1) {
    return tmp[0];
  } else {
    return z3::mk_and(tmp);
  }
}

// This implements the algorithm in https://github.com/Z3Prover/z3/issues/4822
z3::expr PerryZ3Builder::simplifyLogicExpr(const z3::expr &original) {
  z3::solver s1 = z3::solver(ctx);
  z3::solver s2 = z3::solver(ctx);

  s1.add(original);
  s2.add(!original);
  s1.set("core.minimize", true);

  z3::expr_vector clauses(ctx);
  while (s2.check() == z3::sat) {
    z3::model mdl = s2.get_model();
    unsigned num_const = mdl.num_consts();
    z3::expr_vector core(ctx);
    z3::expr_vector clause(ctx);
    for (unsigned i = 0; i < num_const; ++i) {
      auto decl = mdl.get_const_decl(i);
      auto expr = mdl.get_const_interp(decl);
      if (expr.is_true()) {
        core.push_back(decl());
      } else if (expr.is_false()) {
        core.push_back(!(decl()));
      }
    }
    assert(z3::unsat == s1.check(core));
    for (auto c : s1.unsat_core()) {
      clause.push_back(!c);
    }
    if (clause.size() > 1) {
      auto tmp = z3::mk_or(clause);
      clauses.push_back(tmp);
      s2.add(tmp);
    } else {
      auto tmp = clause[0];
      clauses.push_back(tmp);
      s2.add(tmp);
    }
  }
  if (clauses.size() == 0) {
    return ctx.bool_val(true);
  } else if (clauses.size() > 1) {
    return z3::mk_and(clauses);
  } else {
    return clauses[0];
  }
  
}

#define ImplVisitLogicOperator(_kind)                                     \
void PerryZ3Builder::                                                     \
visitLogic ## _kind(const z3::expr &e, z3::expr_vector &result,           \
                    z3::expr_vector &orig, z3::expr_vector &bool_vars,    \
                    std::map<unsigned, unsigned> &bv_id_to_idx,           \
                    std::map<unsigned, unsigned> &bool_id_to_idx,         \
                    unsigned &cnt)                                        \

// logical operators
ImplVisitLogicOperator(AND) {
  auto num_args = e.num_args();
  z3::expr_vector local_and(ctx);
  for (unsigned i = 0; i < num_args; ++i) {
    z3::expr_vector res(ctx);
    visitLogicBitLevel(
      e.arg(i), res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
    assert(res.size() == 1);
    local_and.push_back(res[0]);
  }
  if (local_and.size() == 1) {
    result.push_back(local_and[0]);
  } else if (local_and.size() > 1) {
    result.push_back(z3::mk_and(local_and));
  }
}

ImplVisitLogicOperator(OR) {
  auto num_args = e.num_args();
  z3::expr_vector local_or(ctx);
  for (unsigned i = 0; i < num_args; ++i) {
    z3::expr_vector res(ctx);
    visitLogicBitLevel(
      e.arg(i), res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
    assert(res.size() == 1);
    local_or.push_back(res[0]);
  }
  if (local_or.size() == 1) {
    result.push_back(local_or[0]);
  } else if (local_or.size() > 1) {
    result.push_back(z3::mk_or(local_or));
  }
}

ImplVisitLogicOperator(XOR) {
  auto num_args = e.num_args();
  z3::expr_vector local_xor(ctx);
  for (unsigned i = 0; i < num_args; ++i) {
    z3::expr_vector res(ctx);
    visitLogicBitLevel(
      e.arg(i), res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
    assert(res.size() == 1);
    local_xor.push_back(res[0]);
  }
  assert(local_xor.size() > 1);
  result.push_back(z3::mk_xor(local_xor));
}

ImplVisitLogicOperator(NOT) {
  assert(e.num_args() == 1);
  z3::expr_vector res(ctx);
  visitLogicBitLevel(
    e.arg(0), res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  assert(res.size() == 1);
  result.push_back(!res[0]);
}

// relation operators
ImplVisitLogicOperator(EQ) {
  auto left = e.arg(0);
  auto right = e.arg(1);
  z3::expr_vector left_res(ctx);
  z3::expr_vector right_res(ctx);
  visitLogicBitLevel(
    left, left_res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  visitLogicBitLevel(
    right, right_res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  unsigned num_bits = left_res.size();
  assert(num_bits == right_res.size());
  z3::expr_vector local_and(ctx);
  unsigned mode;
  if (left.is_numeral() && !right.is_numeral()) {
    mode = 0;
  } else if (!left.is_numeral() && right.is_numeral()) {
    mode = 1;
  } else if (!left.is_numeral() && !right.is_numeral()) {
    mode = 2; 
  } else {
    klee_error("Should not happen concret value EQ concret value");
  }
  for (unsigned i = 0; i < num_bits; ++i) {
    auto left_bit = left_res[i];
    auto right_bit = right_res[i];
    if (mode == 0) {
      if (left_bit.is_true()) {
        local_and.push_back(right_bit);
      } else {
        assert(left_bit.is_false());
        local_and.push_back(!right_bit);
      }
    } else if (mode == 1) {
      if (right_bit.is_true()) {
        local_and.push_back(left_bit);
      } else {
        assert(right_bit.is_false());
        local_and.push_back(!left_bit);
      }
    } else if (mode == 2) {
      local_and.push_back(
        (left_bit && right_bit) || ((!left_bit) && (!right_bit)));
    }
  }
  if (local_and.size() == 1) {
    result.push_back(local_and[0]);
  } else if (local_and.size() > 1) {
    result.push_back(z3::mk_and(local_and));
  }
}

// mode == 0: sym <= val
// mode == 1: sym <= sym
z3::expr PerryZ3Builder::
constructULEQFromVector(const z3::expr_vector& left,
                        const z3::expr_vector& right, int mode,
                        z3::expr_vector &bool_vars,
                        std::map<unsigned, unsigned> &bool_id_to_idx)
{
  assert(mode == 0 || mode == 1);
  unsigned num_bits = left.size();
  if (mode == 0) {
    z3::expr_vector local_and(ctx);
    z3::expr_vector syms(ctx);
    z3::expr_vector vals(ctx);
    syms = left;
    vals = right;
    // sym <= val
    std::vector<unsigned> set_idx;
    for (unsigned i = num_bits; i > 0; --i) {
      auto sym_bit = syms[i - 1];
      auto val_bit = vals[i - 1];
      if (val_bit.is_true()) {
        // save the index to this bit, no constraint
        set_idx.push_back(i - 1);
      } else {
        assert(val_bit.is_false());
        z3::expr_vector local_or(ctx);
        local_or.push_back(!sym_bit);
        for (auto idx : set_idx) {
          auto tmp_expr = bool_vars[bool_id_to_idx[syms[idx].id()]];
          local_or.push_back(!tmp_expr);
        }
        if (local_or.size() == 1) {
          local_and.push_back(local_or[0]);
        } else if (local_or.size() > 1) {
          local_and.push_back(z3::mk_or(local_or));
        }
      }
    }
    if (local_and.size() == 1) {
      return local_and[0];
    } else {
      assert(local_and.size() > 1);
      return z3::mk_and(local_and);
    }
  } else {
    // (!syma[sz] & symb[sz]) || ((syma[sz] == symb[sz]) && (...))
    z3::expr left_bit = left[0];
    z3::expr right_bit = right[0];
    z3::expr tmp = ((!left_bit) && right_bit) ||
                   ((left_bit && right_bit) || ((!left_bit) && (!right_bit)));
    for (unsigned i = 1; i < num_bits; ++i) {
      left_bit = left[i];
      right_bit = right[i];
      tmp = ((!left_bit) && right_bit) ||
            (((left_bit && right_bit) || ((!left_bit) && (!right_bit))) && tmp);
    }
    return tmp.simplify();
  }
}

ImplVisitLogicOperator(ULEQ) {
  auto left = e.arg(0);
  auto right = e.arg(1);
  int mode;
  if (!left.is_numeral() && right.is_numeral()) {
    // sym <= val
    mode = 0;
  } else if (left.is_numeral() && !right.is_numeral()) {
    // sym >= val := !((sym <= val) && !(sym == val))
    visitLogicBitLevel(
      !(z3::ule(right, left) && (!(right == left))),
      result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
    return;
  } else {
    // sym <= sym
    mode = 1;
  }
  z3::expr_vector left_res(ctx);
  z3::expr_vector right_res(ctx);
  visitLogicBitLevel(
    left, left_res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  visitLogicBitLevel(
    right, right_res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  unsigned num_bits = left_res.size();
  assert(num_bits == right_res.size());
  assert(num_bits > 0);
  result.push_back(constructULEQFromVector(left_res, right_res, mode,
                                           bool_vars, bool_id_to_idx));
}

ImplVisitLogicOperator(ULT) {
  auto left = e.arg(0);
  auto right = e.arg(1);
  // a < b := (a <= b) && (a != b)
  visitLogicBitLevel(
    z3::ule(left, right) && !(left == right),
    result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  return;
}

// bv logical operators
ImplVisitLogicOperator(BAND) {
  auto num_args = e.num_args();
  auto num_bits = e.get_sort().bv_size();
  std::vector<z3::expr_vector> all_res;
  for (unsigned i = 0; i < num_args; ++i) {
    z3::expr_vector res(ctx);
    visitLogicBitLevel(
      e.arg(i), res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
    all_res.push_back(res);
  }
  for (unsigned i = 0; i < num_bits; ++i) {
    z3::expr_vector local_and(ctx);
    for (unsigned j = 0; j < num_args; ++j) {
      local_and.push_back(all_res[j][i]);
    }
    if (local_and.size() == 1) {
      result.push_back(local_and[0]);
    } else if (local_and.size() > 1) {
      result.push_back(z3::mk_and(local_and));
    }
  }
}

ImplVisitLogicOperator(BOR) {
  auto num_args = e.num_args();
  auto num_bits = e.get_sort().bv_size();
  std::vector<z3::expr_vector> all_res;
  for (unsigned i = 0; i < num_args; ++i) {
    z3::expr_vector res(ctx);
    visitLogicBitLevel(
      e.arg(i), res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
    all_res.push_back(res);
  }
  for (unsigned i = 0; i < num_bits; ++i) {
    z3::expr_vector local_or(ctx);
    for (unsigned j = 0; j < num_args; ++j) {
      local_or.push_back(all_res[j][i]);
    }
    if (local_or.size() == 1) {
      result.push_back(local_or[0]);
    } else if (local_or.size() > 1) {
      result.push_back(z3::mk_or(local_or));
    }
  }
}

ImplVisitLogicOperator(BNOT) {
  assert(e.num_args() == 1);
  visitLogicBitLevel(
    e.arg(0), result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  unsigned num_bits = result.size();
  for (unsigned i = 0; i < num_bits; ++i) {
    auto tmp = !result[i];
    result.set(i, tmp);
  }
}

// bv concat & extract
ImplVisitLogicOperator(CONCAT) {
  auto num_args = e.num_args();
  std::vector<z3::expr_vector> all_res;
  for (unsigned i = 0; i < num_args; ++i) {
    z3::expr_vector res(ctx);
    visitLogicBitLevel(
      e.arg(i), res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
    all_res.push_back(res);
  }
  while (!all_res.empty()) {
    auto res = all_res.back();
    all_res.pop_back();
    auto num_bits = res.size();
    for (unsigned i = 0; i < num_bits; ++i) {
      result.push_back(res[i]);
    }
  }
}

ImplVisitLogicOperator(EXTRACT) {
  z3::expr_vector res(ctx);
  visitLogicBitLevel(
    e.arg(0), res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  unsigned low = e.lo();
  unsigned high = e.hi();
  for ( ; low <= high; ++low) {
    result.push_back(res[low]);
  }
}

ImplVisitLogicOperator(BMUL) {
  assert(e.num_args() == 2);
  auto left = e.arg(0);
  auto right = e.arg(1);
  if (!left.is_numeral() && !right.is_numeral()) {
    klee_error("BMUL of two symbols are not supported: %s",
               e.to_string().c_str());
  }
  assert(left.is_numeral() || right.is_numeral());
  uint64_t num;
  z3::expr_vector res(ctx);
  if (left.is_numeral()) {
    num = left.get_numeral_uint64(); 
    visitLogicBitLevel(
      right, res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  } else {
    num = right.get_numeral_uint64();
    visitLogicBitLevel(
      left, res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  }
  auto num_bits = res.size();
  for (unsigned i = 0; i < num_bits; ++i) {
    result.push_back(ctx.bool_val(false));
  }
  while (num != 0) {
    unsigned bit_idx = bits64::indexOfRightmostBit(num);
    num = bits64::withoutRightmostBit(num);
    z3::expr_vector tmp(ctx);
    for (unsigned i = 0; i < num_bits; ++i) {
      if (i < bit_idx) {
        tmp.push_back(ctx.bool_val(false));
      } else {
        tmp.push_back(res[i - bit_idx]);
      }
    }
    result = constructBADDFromVector(result, tmp);
  }
}

z3::expr_vector PerryZ3Builder::
constructBADDFromVector(const z3::expr_vector& left,
                        const z3::expr_vector& right)
{
  unsigned num_bits = left.size();
  z3::expr_vector ret(ctx);
  ret.push_back(((left[0] && (!right[0])) || ((!left[0]) && right[0])).simplify());
  z3::expr carry_bit = (left[0] && right[0]).simplify();
  for (unsigned i = 1; i < num_bits; ++i) {
    z3::expr sum_of_two = (left[i] && (!right[i])) || ((!left[i]) && right[i]);
    sum_of_two = (sum_of_two && (!carry_bit)) || ((!sum_of_two) && carry_bit);
    carry_bit = (left[i] && right[i]) || ((left[i] || right[i]) && carry_bit);
    carry_bit = carry_bit.simplify();
    ret.push_back(sum_of_two.simplify());
  }
  return ret;
}

z3::expr_vector PerryZ3Builder::
constructBSUBFromVector(const z3::expr_vector& left,
                        const z3::expr_vector& right)
{
  // left - right = left + right' + 1
  unsigned num_bits = left.size();
  z3::expr_vector not_right(ctx);
  for (unsigned i = 0; i < num_bits; ++i) {
    not_right.push_back(!right[i]);
  }
  z3::expr_vector one(ctx);
  one.push_back(ctx.bool_val(true));
  for (unsigned i = 1; i < num_bits; ++i) {
    one.push_back(ctx.bool_val(false));
  }
  return constructBADDFromVector(constructBADDFromVector(left, not_right), one);
}

ImplVisitLogicOperator(BADD) {
  unsigned num_operands = e.num_args();
  assert(num_operands > 0);
  visitLogicBitLevel(
    e.arg(0), result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  unsigned num_bits = result.size();
  unsigned idx = 1;
  while (idx < num_operands) {
    z3::expr_vector cur(ctx);
    visitLogicBitLevel(
      e.arg(idx), cur, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
    assert(cur.size() == num_bits);
    ++idx;
    // result = result + cur
    assert(num_bits > 0);
    result = constructBADDFromVector(result, cur);
  }
}

ImplVisitLogicOperator(BSUB) {
  // a - b = a + b' + 1
  assert(e.num_args() == 2);
  unsigned num_bits = e.get_sort().bv_size();
  visitLogicBitLevel(
    e.arg(0) + (~(e.arg(1))) + ctx.bv_val(1, num_bits),
    result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
}

ImplVisitLogicOperator(BUDIV) {
  assert(e.num_args() == 2);
  z3::expr_vector dividend(ctx);
  z3::expr_vector divisor(ctx);
  z3::expr_vector quotient(ctx);
  unsigned num_bits = e.get_sort().bv_size();
  visitLogicBitLevel(
    z3::concat(ctx.bv_val(0, num_bits), e.arg(0)),
    dividend, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  visitLogicBitLevel(
    z3::concat(e.arg(1), ctx.bv_val(0, num_bits)),
    divisor, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  auto zero = ctx.bool_val(false);
  for (unsigned i = 0; i < num_bits; ++i) {
    // 1. dividend << 1
    for (unsigned j = 2 * num_bits; j > 1; --j) {
      auto prev = dividend[j - 2];
      dividend.set(j - 1, prev);
    }
    dividend.set(0, zero);
    // 2. quotient[i] = (dividend >= divisor)
    z3::expr q_bit = constructULEQFromVector(divisor, dividend, 1,
                                             bool_vars, bool_id_to_idx);
    q_bit = q_bit.simplify();
    quotient.push_back(q_bit);
    // 3. dividend = (quotient[i] && (dividend - divisor)) || dividend
    z3::expr_vector tmp = constructBSUBFromVector(dividend, divisor);
    for (unsigned j = 0; j < 2 * num_bits; ++j) {
      z3::expr new_dividend = ((q_bit && tmp[j]) || ((!q_bit) && dividend[j]));
      new_dividend = new_dividend.simplify();
      dividend.set(j, new_dividend);
    }
  }
  for (unsigned i = 0; i < num_bits; ++i) {
    result.push_back(quotient.back());
    quotient.pop_back();
  }
}

z3::expr_vector PerryZ3Builder::
reconstructExpr(const z3::expr &e, z3::expr_vector &orig,
                std::map<unsigned, unsigned> &bool_id_to_idx,
                const std::string &SymName, const std::set<SymRead> &SR,
                bool simplify_not, bool preserve_all)
{
  static const std::regex NameRegex("(.+):(\\d+):(\\d+)");
  z3::expr_vector ret(ctx);
  if (e.is_true() || e.is_false()) {
    ret.push_back(e);
  } else if (e.is_const()) {
    if (bool_id_to_idx.find(e.id()) == bool_id_to_idx.end()) {
      klee_error("Missing mapping from boolean to bv");
    }
    // eq extract 1
    auto orig_bv_expr = orig[bool_id_to_idx[e.id()]];
    // the target to extract
    if (preserve_all) {
      ret.push_back(orig_bv_expr);
    } else {
      auto varName = orig_bv_expr.arg(0).arg(0).decl().name().str();
      bool doSave = false;
      if (!SymName.empty() && varName.find(SymName) != std::string::npos) {
        // TODO: remove this eq expression
        doSave = true;
      } else if (!SR.empty()) {
        std::smatch m;
        std::regex_search(varName, m, NameRegex);
        assert(m.size() == 4);
        auto _name = m.str(1);
        auto _offset = std::stoi(m.str(2));
        auto _width = std::stoi(m.str(3));
        if (SR.find(SymRead(_name, _offset, _width)) != SR.end()) {
          doSave = true;
        }
      }
      if (doSave) {
        ret.push_back(orig_bv_expr);
      }
    }
  } else {
    auto kind = e.decl().decl_kind();
    switch (kind) {
      case Z3_OP_AND: {
        z3::expr_vector local_and(ctx);
        for (auto arg : e.args()) {
          auto tmp_vec = reconstructExpr(
            arg, orig, bool_id_to_idx, SymName, SR, simplify_not, preserve_all);
          if (!tmp_vec.empty()) {
            local_and.push_back(tmp_vec[0]);
          }
        }
        if (local_and.size() == 1) {
          ret.push_back(local_and[0]);
        } else if (local_and.size() > 1){
          ret.push_back(z3::mk_and(local_and));
        }
        break;
      }
      case Z3_OP_OR: {
        z3::expr_vector local_or(ctx);
        for (auto arg : e.args()) {
          auto tmp_vec = reconstructExpr(
            arg, orig, bool_id_to_idx, SymName, SR, simplify_not, preserve_all);
          if (!tmp_vec.empty()) {
            local_or.push_back(tmp_vec[0]);
          }
        }
        if (local_or.size() == 1) {
          ret.push_back(local_or[0]);
        } else if (local_or.size() > 1){
          ret.push_back(z3::mk_or(local_or));
        }
        break;
      }
      case Z3_OP_NOT: {
        assert(e.num_args() == 1);
        auto res = reconstructExpr(
          e.arg(0), orig, bool_id_to_idx, SymName, SR, simplify_not, preserve_all);
        if (!res.empty()) {
          if (simplify_not) {
            auto child = e.arg(0);
            if (!child.is_true() && !child.is_false() && child.is_const()) {
              // !(sym == 1) --> sym == 0
              assert(res[0].is_eq());
              ret.push_back(res[0].arg(0) == 0);
              break;
            }
          }
          if (res.size() > 0) {
            ret.push_back(!res[0]);
          }
        }
        break;
      }
      case Z3_OP_XOR: {
        z3::expr_vector local_xor(ctx);
        for (auto arg : e.args()) {
          auto tmp_vec = reconstructExpr(
            arg, orig, bool_id_to_idx, SymName, SR, simplify_not, preserve_all);
          if (!tmp_vec.empty()) {
            local_xor.push_back(tmp_vec[0]);
          }
        }
        if (local_xor.size() == 1) {
          ret.push_back(local_xor[0]);
        } else if (local_xor.size() > 1){
          ret.push_back(z3::mk_xor(local_xor));
        }
        break;
      }
      default: {
        klee_error("Unsupported expression when reconstruct expression: %s",
                   e.to_string().c_str());
      }
    }
  }
  return ret;
}

void PerryZ3Builder::
visitLogicBitLevel(const z3::expr &e, z3::expr_vector &result,
                   z3::expr_vector &orig, z3::expr_vector &bool_vars,
                   std::map<unsigned, unsigned> &bv_id_to_idx,
                   std::map<unsigned, unsigned> &bool_id_to_idx,
                   unsigned &cnt)
{
  if (!e.is_app()) {
    klee_error("Only applications are supported now");
  }
  Z3_decl_kind kind = e.decl().decl_kind();
  if (e.is_bv()) {
    unsigned num_bits = e.get_sort().bv_size();
    // expression or variable
    if (e.is_numeral()) {
      // numerical literal
      uint64_t number = e.get_numeral_uint64();
      for (unsigned i = 0; i < num_bits; ++i) {
        bool bitset;
        if (number & (1 << i)) {
          bitset = true;
        } else {
          bitset = false;
        }
        result.push_back(ctx.bool_val(bitset));
      }
    } else if (e.is_const()) {
      // variable
      for (unsigned i = 0; i < num_bits; ++i) {
        auto bv_expr = (e.extract(i, i) == 1);
        if (bv_id_to_idx.find(bv_expr.id()) == bv_id_to_idx.end()) {
          // newly created bv expression
          bv_id_to_idx.insert(std::make_pair(bv_expr.id(), orig.size()));
          orig.push_back(bv_expr);
          std::string name = "z" + std::to_string(cnt);
          cnt += 1;
          auto bool_expr = ctx.bool_const(name.c_str());
          bool_id_to_idx.insert(std::make_pair(bool_expr.id(),
                                               bool_vars.size()));
          bool_vars.push_back(bool_expr);
          result.push_back(bool_expr);
        } else {
          auto bool_expr = bool_vars[bv_id_to_idx[bv_expr.id()]];
          result.push_back(bool_expr);
        }
      }
    } else {
      switch (kind) {
        // bv logical operators
        case Z3_OP_BAND: {
          visitLogicBAND(
            e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
          break;
        }
        case Z3_OP_BOR: {
          visitLogicBOR(
            e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
          break;
        }
        case Z3_OP_BNOT: {
          visitLogicBNOT(
            e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
          break;
        }
        // bv concat and extract
        case Z3_OP_CONCAT: {
          visitLogicCONCAT(
            e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
          break;
        }
        case Z3_OP_EXTRACT: {
          visitLogicEXTRACT(
            e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
          break;
        }
        // bv arith
        case Z3_OP_BMUL: {
          visitLogicBMUL(
            e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
          break;
        }
        case Z3_OP_BADD: {
          visitLogicBADD(
            e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
          break;
        }
        case Z3_OP_BSUB: {
          visitLogicBSUB(
            e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
          break;
        }
        case Z3_OP_BUDIV: {
          // TODO: add constraint indicating that the divisor must not be 0
          visitLogicBUDIV(
            e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
          break;
        }
        case Z3_OP_BUDIV_I: {
          visitLogicBUDIV(
            e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
          break;
        }
        default: {
          klee_error("Unsupported bv operator %s", e.to_string().c_str());
        }
      }
    }
  } else if (e.is_bool()) {
    if (e.is_true() || e.is_false()) {
      result.push_back(e);
      return;
    }
    switch (kind) {
      // logical operators
      case Z3_OP_AND: {
        visitLogicAND(
          e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
        break;
      }
      case Z3_OP_OR: {
        visitLogicOR(
          e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
        break;
      }
      case Z3_OP_XOR: {
        visitLogicXOR(
          e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
        break;
      }
      case Z3_OP_NOT: {
        visitLogicNOT(
          e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
        break;
      }
      // bv relational operators
      case Z3_OP_EQ: {
        visitLogicEQ(
          e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
        break;
      }
      case Z3_OP_ULEQ: {
        visitLogicULEQ(
          e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
        break;
      }
      case Z3_OP_ULT: {
        visitLogicULT(
          e, result, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
        break;
      }
      default: {
        klee_error("Unsupported bool operator %s", e.to_string().c_str());
      }
    }
  } else {
    klee_error(
      "Unsupported expression sort: %s", e.get_sort().to_string().c_str());
  }
}

z3::expr PerryZ3Builder::
getLogicalBitExpr(const z3::expr &src, const std::string &SymName,
                  bool simplify_not, bool preserve_all,
                  const std::set<SymRead> &SR)
{
  assert(src.is_bool());
  z3::expr_vector res(ctx);
  z3::expr_vector bool_vars(ctx);
  z3::expr_vector orig(ctx);
  std::map<unsigned, unsigned> bv_id_to_idx;
  std::map<unsigned, unsigned> bool_id_to_idx;
  unsigned cnt = 0;
  // std::cerr << src << "\n0000000000000000000\n";
  auto naive = src.simplify();
  // std::cerr << naive << "\n11111111111111111\n";
  visitLogicBitLevel(
    naive, res, orig, bool_vars, bv_id_to_idx, bool_id_to_idx, cnt);
  assert(res.size() == 1);
  // std::cerr << res[0] << "\n22222222222222222222\n";
  auto logic_expr = res[0].simplify();
  // std::cerr << logic_expr << "\n33333333333333333333\n";
  logic_expr = simplifyLogicExpr(logic_expr);
  // std::cerr << logic_expr << "\n4444444444444444444\n";
  logic_expr = logic_expr.simplify();
  // std::cerr << logic_expr << "\n555555555555555555\n";
  auto ret = reconstructExpr(
    logic_expr, orig, bool_id_to_idx, SymName, SR, simplify_not, preserve_all);
  // std::cerr << ret << "\n666666666666666666666666\n";
  assert(ret.size() <= 1);
  if (ret.size() == 1) {
    auto result = ret[0].simplify();
    return result;
  } else {
    auto result = ctx.bool_val(true);
    return result;
  }
}

z3::expr PerryZ3Builder::
getLogicalBitExprAnd(const std::vector<ref<PerryExpr>> &CS,
                     const std::string &SymName,
                     bool simplify_not,
                     const std::set<SymRead> &SR,
                     bool preserve_all)
{
  return getLogicalBitExpr(
    toZ3ExprAnd(CS), SymName, simplify_not, preserve_all, SR);
}

z3::expr PerryZ3Builder::
getLogicalBitExprOr(const z3::expr_vector &CS, bool simplify_not,
                    bool preserve_all)
{
  return getLogicalBitExpr(mk_or(CS), "", simplify_not, preserve_all);
}

z3::expr PerryZ3Builder::
getLogicalBitExprBatchOr(const std::vector<std::vector<ref<PerryExpr>>> &CS,
                         const std::string &SymName, bool simplify_not,
                         const std::set<SymRead> &SR, bool preserve_all)
{
  return getLogicalBitExpr(
    toZ3ExprBatchOr(CS), SymName, simplify_not, preserve_all, SR);
}

void PerryZ3Builder::
visitBitLevel(const z3::expr &e, z3::expr_vector &result) {
  if (!e.is_app()) {
    klee_error("Only applications are supported now");
  }
  if (!e.is_bv()) {
    klee_error("Only bitvector expressions are supported now");
  }
  unsigned num_bits = e.get_sort().bv_size();
  Z3_decl_kind kind = e.decl().decl_kind();
  
  if (e.is_numeral()) {
    // leaf node (numeric value)
    uint64_t num = e.get_numeral_uint64();
    for (unsigned i = 0; i < num_bits; ++i) {
      int bitset;
      if (num & (1 << i)) {
        bitset = 1;
      } else {
        bitset = 0;
      }
      result.push_back(ctx.bv_val(bitset, 1));
    }
  } else if (e.is_const()) {
    // leaf node (variable)
    // extract every bit
    for (unsigned i = 0; i < num_bits; ++i) {
      result.push_back(e.extract(i, i));
    }
  } else {
    // parent node
    if (kind != Z3_OP_BAND    &&
        kind != Z3_OP_BOR     &&
        kind != Z3_OP_CONCAT  &&
        kind != Z3_OP_EXTRACT)
    {
      klee_error("visitBitLevel: unsupported operator in expression %s",
                 e.to_string().c_str());
    }
    unsigned num_args = e.num_args();
    std::vector<z3::expr_vector> child_result;
    for (unsigned i = 0; i < num_args; ++i) {
      z3::expr_vector result(ctx);
      visitBitLevel(e.arg(i), result);
      child_result.push_back(result);
    }
    switch (kind) {
      case Z3_OP_BAND: {
        while (child_result.size() > 1) {
          z3::expr_vector a = child_result.back();
          child_result.pop_back();
          z3::expr_vector b = child_result.back();
          child_result.pop_back();
          z3::expr_vector res(ctx);
          assert(a.size() == b.size());
          unsigned num = a.size();
          for (unsigned i = 0; i < num; ++i) {
            if (!a[i].is_numeral() && !b[i].is_numeral()) {
              // syma & symb = self
              res.push_back(a[i] & b[i]);
            } else if (!a[i].is_numeral() && b[i].is_numeral()) {
              if (b[i].get_numeral_uint64()) {
                // sym & 1 = sym
                res.push_back(a[i]);
              } else {
                // sym & 0 = 0
                res.push_back(ctx.bv_val(0, 1));
              }
            } else if (a[i].is_numeral() && !b[i].is_numeral()) {
              if (a[i].get_numeral_uint64()) {
                // sym & 1 = sym
                res.push_back(b[i]);
              } else {
                // sym & 0 = 0
                res.push_back(ctx.bv_val(0, 1));
              }
            } else {
              // val & val = self
              uint64_t concrete 
                = a[i].get_numeral_uint64() & b[i].get_numeral_uint64();
              res.push_back(ctx.bv_val(concrete, 1));
            }
          }
          child_result.push_back(res);
        }
        result = child_result.back();
        child_result.pop_back();
        break;
      }
      case Z3_OP_BOR: {
        while (child_result.size() > 1) {
          z3::expr_vector a = child_result.back();
          child_result.pop_back();
          z3::expr_vector b = child_result.back();
          child_result.pop_back();
          z3::expr_vector res(ctx);
          assert(a.size() == b.size());
          unsigned num = a.size();
          for (unsigned i = 0; i < num; ++i) {
            if (!a[i].is_numeral() && !b[i].is_numeral()) {
              // syma | symb = self
              res.push_back(a[i] | b[i]);
            } else if (!a[i].is_numeral() && b[i].is_numeral()) {
              if (b[i].get_numeral_uint64()) {
                // sym | 1 = 1
                res.push_back(ctx.bv_val(1, 1));
              } else {
                // sym | 0 = sym
                res.push_back(a[i]);
              }
            } else if (a[i].is_numeral() && !b[i].is_numeral()) {
              if (a[i].get_numeral_uint64()) {
                // sym | 1 = 1
                res.push_back(ctx.bv_val(1, 1));
              } else {
                // sym | 0 = sym
                res.push_back(b[i]);
              }
            } else {
              // val | val = self
              uint64_t concrete
                = a[i].get_numeral_uint64() | b[i].get_numeral_uint64();
              res.push_back(ctx.bv_val(concrete, 1));
            }
          }
          child_result.push_back(res);
        }
        result = child_result.back();
        child_result.pop_back();
        break;
      }
      case Z3_OP_CONCAT: {
        while (!child_result.empty()) {
          z3::expr_vector c = child_result.back();
          child_result.pop_back();
          for (auto ce : c) {
            result.push_back(ce);
          }
        }
        assert(result.size() == num_bits);
        break;
      }
      case Z3_OP_EXTRACT: {
        unsigned low = e.lo();
        unsigned high = e.hi();
        z3::expr_vector c = child_result[0];
        for ( ; low <= high; ++low) {
          assert(low < c.size());
          result.push_back(c[low]);
        }
        break;
      }
      default: {
        klee_error("should not happen");
      }
    }
  }
}

void PerryZ3Builder::
getBitLevelExpr(const ref<PerryExpr> &expr, z3::expr_vector &out) {
  z3::expr z3expr = toZ3Expr(expr);
  z3expr = z3expr.simplify();
  visitBitLevel(z3expr, out);
}

z3::expr_vector PerryZ3Builder::
inferBitLevelConstraintInternal(const z3::expr &in_cs, const SymRead &SR,
                                z3::expr_vector &bit_level_expr,
                                const z3::expr_vector &blacklist,
                                bool contain_concrete)
{
  z3::solver s(ctx);
  z3::expr_vector out_bit_cs(ctx);
  z3::expr target_expr = ctx.bool_val(true);
  if (SR.width > 8) {
    auto orig_width = SR.width;
    unsigned idx = SR.idx + orig_width / 8;
    z3::expr_vector tmp_vec(ctx);
    while (orig_width > 0) {
      SymRead tmpSR(SR.name, idx - 1, 8);
      --idx;
      orig_width -= 8;
      tmp_vec.push_back(ctx.bv_const(tmpSR.to_string().c_str(), 8));
    }
    target_expr = z3::concat(tmp_vec);
  } else {
    assert(SR.width == 8);
    target_expr = ctx.bv_const(SR.to_string().c_str(), SR.width);
  }
  s.add(in_cs);
  s.push();
  unsigned num_bits = bit_level_expr.size();
  for (unsigned i = 0; i < num_bits; ++i) {
    z3::expr ble = bit_level_expr[i];
    int one_or_zero;
    bool skip;
    if (ble.is_numeral()) {
      if (contain_concrete) {
        one_or_zero = (ble.get_numeral_uint() == 0) ? 0 : 1;
        auto exp = (target_expr.extract(i, i) == one_or_zero);
        skip = false;
        for (auto e : blacklist) {
          if (e.id() == exp.id()) {
            skip = true;
            break;
          }
        }
        if (!skip) {
          out_bit_cs.push_back(exp);
        }
      }
      continue;
    }
    bool could_be_true;
    bool could_be_false;
    s.add(ble == 1);
    if (s.check() == z3::sat) {
      could_be_true = true;
    } else {
      could_be_true = false;
    }
    s.pop();
    s.push();

    s.add(ble == 0);
    if (s.check() == z3::sat) {
      could_be_false = true;
    } else {
      could_be_false = false;
    }
    s.pop();
    s.push();

    if (could_be_true && could_be_false) {
      // no constraint on this bit
      continue;
    } else if (could_be_true && !could_be_false) {
      // this bit must be true
      one_or_zero = 1;
    } else if (!could_be_true && could_be_false) {
      // this bit must be false
      one_or_zero = 0;
    } else {
      // should not happen
      std::string err_msg;
      llvm::raw_string_ostream OS(err_msg);
      OS << "inferBitLevelConstraint: should not happen\n"
         << "In constraints: \n"
         << in_cs.to_string() << "\n"
         << "Symbol: " << SR << "\n"
         << "Blacklist:\n"
         << blacklist.to_string() << "\n"
         << "Contain concrete: " << contain_concrete << "\n"
         << "---------------------------------\n";
      klee_error("%s", err_msg.c_str());
    }
    auto sub_exp = (target_expr.extract(i, i) == one_or_zero);
    skip = false;
    for (auto e : blacklist) {
      if (e.id() == sub_exp.id()) {
        skip = true;
        break;
      }
    }
    if (!skip) {
      out_bit_cs.push_back(sub_exp);
    }
  }
  return out_bit_cs;
}

z3::expr PerryZ3Builder::
inferBitLevelConstraint(const z3::expr &in_cs, const SymRead &SR,
                        z3::expr_vector &bit_level_expr)
{
  z3::expr_vector empty_blacklist(ctx);
  z3::expr_vector out_bit_cs = inferBitLevelConstraintInternal(
    in_cs, SR, bit_level_expr, empty_blacklist, false);

  return mk_and(out_bit_cs);
}

z3::expr_vector PerryZ3Builder::
inferBitLevelConstraintRaw(const z3::expr &in_cs, const SymRead &SR,
                           z3::expr_vector &bit_level_expr)
{
  z3::expr_vector empty_blacklist(ctx);
  z3::expr_vector out_bit_cs = inferBitLevelConstraintInternal(
    in_cs, SR, bit_level_expr, empty_blacklist);

  return out_bit_cs;
}

z3::expr PerryZ3Builder::
inferBitLevelConstraintWithBlacklist(const z3::expr &in_cs, const SymRead &SR, 
                                     const z3::expr_vector &blacklist,
                                     z3::expr_vector &bit_level_expr)
{
  // select bits from bit_level_expr, with regard to SR
  z3::expr_vector out_bit_cs = inferBitLevelConstraintInternal(
    in_cs, SR, bit_level_expr, blacklist);

  return mk_and(out_bit_cs);
}

z3::expr PerryZ3Builder::
getConstantConstraint(const SymRead &SR, int constant) {
  z3::expr target_expr = ctx.bv_const(SR.to_string().c_str(), SR.width);
  return (target_expr == constant);
}

z3::expr PerryZ3Builder::
getBitConstantConstraint(const SymRead &SR, int idx, int val) {
  assert(val == 0 || val == 1);
  z3::expr target_expr = ctx.bv_const(SR.to_string().c_str(), SR.width);
  return (target_expr.extract(idx, idx) == val);
}

z3::expr PerryZ3Builder::mk_and(const z3::expr_vector &v) {
  auto v_size = v.size();
  if (v_size == 0) {
    return ctx.bool_val(true);
  } else if (v_size == 1) {
    return v[0];
  } else {
    return z3::mk_and(v);
  }
}

z3::expr PerryZ3Builder::mk_or(const z3::expr_vector &v) {
  auto v_size = v.size();
  if (v_size == 0) {
    return ctx.bool_val(true);
  } else if (v_size == 1) {
    return v[0];
  } else {
    return z3::mk_or(v);
  }
}

bool PerryZ3Builder::containsUnsupportedExpr(const z3::expr &e) {
  static const std::set<Z3_decl_kind> supported_expr_kind {
    Z3_OP_AND, Z3_OP_OR, Z3_OP_XOR, Z3_OP_NOT,
    Z3_OP_EQ, Z3_OP_ULEQ, Z3_OP_ULT,
    Z3_OP_BAND, Z3_OP_BOR, Z3_OP_BNOT,
    Z3_OP_CONCAT, Z3_OP_EXTRACT,
    Z3_OP_BMUL, Z3_OP_BADD, Z3_OP_BSUB, Z3_OP_BUDIV, Z3_OP_BUDIV_I
  };
  z3::expr_vector WL(ctx);
  WL.push_back(e);
  while (!WL.empty()) {
    auto cur_expr = WL.back();
    WL.pop_back();
    if (cur_expr.is_const() || cur_expr.is_numeral()) {
      continue;
    }
    auto cur_kind = cur_expr.decl().decl_kind();
    if (supported_expr_kind.find(cur_kind) ==
        supported_expr_kind.end())
    {
      return true;
    }
    for (auto arg : cur_expr.args()) {
      WL.push_back(arg);
    }
  }
  return false;
}
