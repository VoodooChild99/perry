#ifndef __PERRY_Z3_BUILDER_H__
#define __PERRY_Z3_BUILDER_H__

#include <regex>

#include <z3++.h>

#include "klee/Perry/PerryExpr.h"
#include "klee/Perry/PerryUtils.h"

namespace klee {

class PerryZ3Builder {
public:
  PerryZ3Builder()
    : NameRegex("(.+):(\\d+):(\\d+)") {}

  z3::expr mk_and(const z3::expr_vector &v);
  z3::expr mk_or(const z3::expr_vector &v);

  z3::expr toZ3Expr(const ref<PerryExpr> &PE);
  z3::expr toZ3ExprBatchOr(const std::vector<std::vector<ref<PerryExpr>>> &CS);
  z3::expr toZ3ExprAnd(const std::vector<ref<PerryExpr>> &CS);

  z3::expr
  getLogicalBitExprAnd(const std::vector<ref<PerryExpr>> &CS,
                       const std::string &SymName,
                       bool simplify_not = false,
                       const std::set<SymRead> &SR = std::set<SymRead>(),
                       bool preserve_all = false);
  z3::expr
  getLogicalBitExprOr(const z3::expr_vector &CS,
                      bool simplify_not = false, bool preserve_all = false);

  z3::expr
  getLogicalBitExprBatchOr(const std::vector<std::vector<ref<PerryExpr>>> &CS,
                           const std::string &SymName,
                           bool simplify_not = false,
                           const std::set<SymRead> &SR = std::set<SymRead>(),
                           bool preserve_all = false);
  
  void getBitLevelExpr(const ref<PerryExpr> &expr, z3::expr_vector &out);

  z3::expr getConstantConstraint(const SymRead &SR, int constant);

  z3::expr getBitConstantConstraint(const SymRead &SR, int idx, int val);

  z3::expr inferBitLevelConstraint(const z3::expr &in_cs, const SymRead &SR,
                                   z3::expr_vector &bit_level_expr);

  z3::expr_vector inferBitLevelConstraintRaw(const z3::expr &in_cs,
                                             const SymRead &SR,
                                             z3::expr_vector &bit_level_expr);
  z3::expr
  inferBitLevelConstraintWithBlacklist(const z3::expr &in_cs, const SymRead &SR,
                                       const z3::expr_vector &blacklist,
                                       z3::expr_vector &bit_level_expr);
  
  // expressing `target` using a linear formula of the form `c1 * expr + c2` satifying:
  // `pre_cond \implies \forall var \in expr cond[target -> (c1 * expr + c2)]`
  // it's assumed that 
  z3::expr synthesizeLinearFormula(const z3::expr &pre_cond,
                                   const z3::expr &cond,
                                   const z3::expr &target,
                                   const z3::expr &common_expr,
                                   const z3::expr &new_symbol,
                                   bool &success);
  z3::expr getSym(unsigned width);

  z3::context &getContext() { return ctx; };
  // returns true if `a` contains b
  bool contains(const z3::expr &a, const z3::expr &b);
  bool contains_bv_const(const z3::expr &a, const std::string &name, bool full);
private:
  z3::expr simplifyLogicExpr(const z3::expr &original);
  void visitBitLevel(const z3::expr &e, z3::expr_vector &result);
  void visitLogicBitLevel(const z3::expr &e, z3::expr_vector &result,
                          z3::expr_vector &orig, z3::expr_vector &bool_vars,
                          std::map<unsigned, unsigned> &bv_id_to_idx,
                          std::map<unsigned, unsigned> &bool_id_to_idx,
                          unsigned &cnt);
  #define DefVisitLogicOperator(_kind)                                        \
  void visitLogic ## _kind(const z3::expr &e, z3::expr_vector &result,        \
                           z3::expr_vector &orig, z3::expr_vector &bool_vars, \
                           std::map<unsigned, unsigned> &bv_id_to_idx,        \
                           std::map<unsigned, unsigned> &bool_id_to_idx,      \
                           unsigned &cnt)                                     \

  // bool logical
  DefVisitLogicOperator(AND);
  DefVisitLogicOperator(OR);
  DefVisitLogicOperator(XOR);
  DefVisitLogicOperator(NOT);
  // bv relation
  DefVisitLogicOperator(EQ);
  DefVisitLogicOperator(ULEQ);
  DefVisitLogicOperator(ULT);
  DefVisitLogicOperator(SGT);
  DefVisitLogicOperator(SLEQ);
  // bv logical
  DefVisitLogicOperator(BAND);
  DefVisitLogicOperator(BOR);
  DefVisitLogicOperator(BNOT);
  // bv segmentation
  DefVisitLogicOperator(CONCAT);
  DefVisitLogicOperator(EXTRACT);
  DefVisitLogicOperator(ZERO_EXT);
  DefVisitLogicOperator(SIGN_EXT);
  // bv shift
  DefVisitLogicOperator(BSHL);
  DefVisitLogicOperator(BLSHR);
  DefVisitLogicOperator(BASHR);
  // bv arith
  DefVisitLogicOperator(BMUL);
  DefVisitLogicOperator(BADD);
  DefVisitLogicOperator(BSUB);
  DefVisitLogicOperator(BUDIV);
  // ite
  DefVisitLogicOperator(ITE);
  #undef DefVisitLogicOperator

  z3::expr
  constructULEQFromVector(const z3::expr_vector& left,
                          const z3::expr_vector& right, int mode,
                          z3::expr_vector &bool_vars);
  z3::expr_vector
  constructBADDFromVector(const z3::expr_vector& left,
                          const z3::expr_vector& right);
  z3::expr_vector
  constructBSUBFromVector(const z3::expr_vector& left,
                          const z3::expr_vector& right);
  
  z3::expr_vector inferBitLevelConstraintInternal(const z3::expr &in_cs,
                                                  const SymRead &SR,
                                                  z3::expr_vector &bit_level_expr,
                                                  const z3::expr_vector &blacklist,
                                                  bool contain_concrete = true);

  z3::expr
  getLogicalBitExpr(const z3::expr &src, const std::string &SymName,
                    bool simplify_not, bool preserve_all,
                    const std::set<SymRead> &SR = std::set<SymRead>());

  z3::expr_vector reconstructExpr(const z3::expr &e, z3::expr_vector &orig,
                                  std::map<unsigned, unsigned> &bool_id_to_idx,
                                  const std::string &SymName,
                                  const std::set<SymRead> &SR,
                                  bool simplify_not,
                                  bool preserve_all);

  bool containsUnsupportedExpr(const z3::expr &e);
  void ifContainVisit(std::set<unsigned> &visited, bool &result,
                      const z3::expr &a, const z3::expr &b);
  void extractAllConstantVisit(std::set<unsigned> &visited,
                               z3::expr_vector &result, const z3::expr &a);
  void ifContainBvConstVisit(std::set<unsigned> &visited, bool &result,
                             const z3::expr &a, const std::string &name,
                             bool full);
  z3::context ctx;
  const std::regex NameRegex;
};

}

#endif