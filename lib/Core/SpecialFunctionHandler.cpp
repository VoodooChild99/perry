//===-- SpecialFunctionHandler.cpp ----------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "SpecialFunctionHandler.h"

#include "ExecutionState.h"
#include "Executor.h"
#include "Memory.h"
#include "MemoryManager.h"
#include "MergeHandler.h"
#include "Searcher.h"
#include "StatsTracker.h"
#include "TimingSolver.h"

#include "klee/Config/config.h"
#include "klee/Module/KInstruction.h"
#include "klee/Module/KModule.h"
#include "klee/Solver/SolverCmdLine.h"
#include "klee/Support/Casting.h"
#include "klee/Support/Debug.h"
#include "klee/Support/ErrorHandling.h"
#include "klee/Support/OptionCategories.h"
#include "klee/Perry/PerryTrace.h"
#include "klee/Perry/PerryCustomHook.h"

#include "llvm/ADT/Twine.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cerrno>
#include <sstream>

using namespace llvm;
using namespace klee;

namespace {
cl::opt<bool>
    ReadablePosix("readable-posix-inputs", cl::init(false),
                  cl::desc("Prefer creation of POSIX inputs (command-line "
                           "arguments, files, etc.) with human readable bytes. "
                           "Note: option is expensive when creating lots of "
                           "tests (default=false)"),
                  cl::cat(TestGenCat));

cl::opt<bool>
    SilentKleeAssume("silent-klee-assume", cl::init(false),
                     cl::desc("Silently terminate paths with an infeasible "
                              "condition given to klee_assume() rather than "
                              "emitting an error (default=false)"),
                     cl::cat(TerminationCat));
} // namespace

/// \todo Almost all of the demands in this file should be replaced
/// with terminateState calls.

///

// FIXME: We are more or less committed to requiring an intrinsic
// library these days. We can move some of this stuff there,
// especially things like realloc which have complicated semantics
// w.r.t. forking. Among other things this makes delayed query
// dispatch easier to implement.
static SpecialFunctionHandler::HandlerInfo handlerInfo[] = {
#define add(name, handler, ret) { name, \
                                  &SpecialFunctionHandler::handler, \
                                  false, ret, false }
#define addDNR(name, handler) { name, \
                                &SpecialFunctionHandler::handler, \
                                true, false, false }
  addDNR("__assert_rtn", handleAssertFail),
  addDNR("__assert_fail", handleAssertFail),
  addDNR("__assert", handleAssertFail),
  addDNR("_assert", handleAssert),
  addDNR("abort", handleAbort),
  addDNR("_exit", handleExit),
  { "exit", &SpecialFunctionHandler::handleExit, true, false, true },
  addDNR("klee_abort", handleAbort),
  addDNR("klee_silent_exit", handleSilentExit),
  addDNR("klee_report_error", handleReportError),
  add("calloc", handleCalloc, true),
  add("free", handleFree, false),
  add("klee_assume", handleAssume, false),
  add("klee_check_memory_access", handleCheckMemoryAccess, false),
  add("klee_get_valuef", handleGetValue, true),
  add("klee_get_valued", handleGetValue, true),
  add("klee_get_valuel", handleGetValue, true),
  add("klee_get_valuell", handleGetValue, true),
  add("klee_get_value_i32", handleGetValue, true),
  add("klee_get_value_i64", handleGetValue, true),
  add("klee_define_fixed_object", handleDefineFixedObject, false),
  add("klee_get_obj_size", handleGetObjSize, true),
  add("klee_get_errno", handleGetErrno, true),
#ifndef __APPLE__
  add("__errno_location", handleErrnoLocation, true),
#else
  add("__error", handleErrnoLocation, true),
#endif
  add("klee_is_symbolic", handleIsSymbolic, true),
  add("klee_make_symbolic", handleMakeSymbolic, false),
  add("klee_mark_global", handleMarkGlobal, false),
  add("klee_open_merge", handleOpenMerge, false),
  add("klee_close_merge", handleCloseMerge, false),
  add("klee_prefer_cex", handlePreferCex, false),
  add("klee_posix_prefer_cex", handlePosixPreferCex, false),
  add("klee_print_expr", handlePrintExpr, false),
  add("klee_print_range", handlePrintRange, false),
  add("klee_set_forking", handleSetForking, false),
  add("klee_stack_trace", handleStackTrace, false),
  add("klee_warning", handleWarning, false),
  add("klee_warning_once", handleWarningOnce, false),
  add("malloc", handleMalloc, true),
  add("memalign", handleMemalign, true),
  add("realloc", handleRealloc, true),

#ifdef SUPPORT_KLEE_EH_CXX
  add("_klee_eh_Unwind_RaiseException_impl", handleEhUnwindRaiseExceptionImpl, false),
  add("klee_eh_typeid_for", handleEhTypeid, true),
#endif

  // operator delete[](void*)
  add("_ZdaPv", handleDeleteArray, false),
  // operator delete(void*)
  add("_ZdlPv", handleDelete, false),

  // operator new[](unsigned int)
  add("_Znaj", handleNewArray, true),
  // operator new(unsigned int)
  add("_Znwj", handleNew, true),

  // FIXME-64: This is wrong for 64-bit long...

  // operator new[](unsigned long)
  add("_Znam", handleNewArray, true),
  // operator new(unsigned long)
  add("_Znwm", handleNew, true),

  // Run clang with -fsanitize=signed-integer-overflow and/or
  // -fsanitize=unsigned-integer-overflow
  add("__ubsan_handle_add_overflow", handleAddOverflow, false),
  add("__ubsan_handle_sub_overflow", handleSubOverflow, false),
  add("__ubsan_handle_mul_overflow", handleMulOverflow, false),
  add("__ubsan_handle_divrem_overflow", handleDivRemOverflow, false),

  add("klee_set_taint", handleSetTaint, false),
  add("klee_set_persist_taint", handleSetPersistTaint, false),
  add("klee_has_taint", handleHasTaint, true),
  add("klee_get_taint", handleGetTaint, true),
  add("klee_get_taint_number", handleGetTaintNum, true),
  add("klee_get_taint_internal", handleGetTaintInternal, false),
  add("klee_get_return_value", handleGetReturnValue, false),
  add("__assert_func", handleAssertFunc, false),
  add("__ubsan_handle_out_of_bounds", handleOOB, false),
  addDNR("perry_klee_hook", handlePerryCustomHook),
  addDNR("perry_klee_hook_wrapper", handlePerryCustomHookWrapper),

#undef addDNR
#undef add
};

SpecialFunctionHandler::const_iterator SpecialFunctionHandler::begin() {
  return SpecialFunctionHandler::const_iterator(handlerInfo);
}

SpecialFunctionHandler::const_iterator SpecialFunctionHandler::end() {
  // NULL pointer is sentinel
  return SpecialFunctionHandler::const_iterator(0);
}

SpecialFunctionHandler::const_iterator& SpecialFunctionHandler::const_iterator::operator++() {
  ++index;
  if ( index >= SpecialFunctionHandler::size())
  {
    // Out of range, return .end()
    base=0; // Sentinel
    index=0;
  }

  return *this;
}

int SpecialFunctionHandler::size() {
	return sizeof(handlerInfo)/sizeof(handlerInfo[0]);
}

SpecialFunctionHandler::SpecialFunctionHandler(Executor &_executor) 
  : executor(_executor) {}

void SpecialFunctionHandler::prepare(
    std::vector<const char *> &preservedFunctions) {
  unsigned N = size();

  for (unsigned i=0; i<N; ++i) {
    HandlerInfo &hi = handlerInfo[i];
    Function *f = executor.kmodule->module->getFunction(hi.name);

    // No need to create if the function doesn't exist, since it cannot
    // be called in that case.
    if (f && (!hi.doNotOverride || f->isDeclaration())) {
      preservedFunctions.push_back(hi.name);
      // Make sure NoReturn attribute is set, for optimization and
      // coverage counting.
      if (hi.doesNotReturn)
        f->addFnAttr(Attribute::NoReturn);

      // Change to a declaration since we handle internally (simplifies
      // module and allows deleting dead code).
      if (!f->isDeclaration())
        f->deleteBody();
    }
  }
}

void SpecialFunctionHandler::
staticPrepare(KModule &KM, std::vector<const char *> &preservedFunctions)
{
  unsigned N = size();
  for (unsigned i=0; i<N; ++i) {
    HandlerInfo &hi = handlerInfo[i];
    Function *f = KM.module->getFunction(hi.name);

    // No need to create if the function doesn't exist, since it cannot
    // be called in that case.
    if (f && (!hi.doNotOverride || f->isDeclaration())) {
      preservedFunctions.push_back(hi.name);
      // Make sure NoReturn attribute is set, for optimization and
      // coverage counting.
      if (hi.doesNotReturn)
        f->addFnAttr(Attribute::NoReturn);

      // Change to a declaration since we handle internally (simplifies
      // module and allows deleting dead code).
      if (!f->isDeclaration())
        f->deleteBody();
    }
  }
}

void SpecialFunctionHandler::bind() {
  unsigned N = size();

  for (unsigned i=0; i<N; ++i) {
    HandlerInfo &hi = handlerInfo[i];
    Function *f = executor.kmodule->module->getFunction(hi.name);
    
    if (f && (!hi.doNotOverride || f->isDeclaration()))
      handlers[f] = std::make_pair(hi.handler, hi.hasReturnValue);
  }
}


bool SpecialFunctionHandler::handle(ExecutionState &state, 
                                    Function *f,
                                    KInstruction *target,
                                    std::vector< ref<Expr> > &arguments) {
  handlers_ty::iterator it = handlers.find(f);
  if (it != handlers.end()) {    
    Handler h = it->second.first;
    bool hasReturnValue = it->second.second;
     // FIXME: Check this... add test?
    if (!hasReturnValue && !target->inst->use_empty()) {
      executor.terminateStateOnExecError(state, 
                                         "expected return value from void special function");
    } else {
      (this->*h)(state, target, arguments);
    }
    return true;
  } else {
    return false;
  }
}

/****/

// reads a concrete string from memory
std::string 
SpecialFunctionHandler::readStringAtAddress(ExecutionState &state, 
                                            ref<Expr> addressExpr) {
  ObjectPair op;
  addressExpr = executor.toUnique(state, addressExpr);
  if (!isa<ConstantExpr>(addressExpr)) {
    executor.terminateStateOnUserError(
        state, "Symbolic string pointer passed to one of the klee_ functions");
    return "";
  }
  ref<ConstantExpr> address = cast<ConstantExpr>(addressExpr);
  if (!state.addressSpace.resolveOne(address, op)) {
    executor.terminateStateOnUserError(
        state, "Invalid string pointer passed to one of the klee_ functions");
    return "";
  }
  const MemoryObject *mo = op.first;
  const ObjectState *os = op.second;

  auto relativeOffset = mo->getOffsetExpr(address);
  // the relativeOffset must be concrete as the address is concrete
  size_t offset = cast<ConstantExpr>(relativeOffset)->getZExtValue();

  std::ostringstream buf;
  char c = 0;
  for (size_t i = offset; i < mo->size; ++i) {
    ref<Expr> cur = os->read8(i);
    cur = executor.toUnique(state, cur);
    assert(isa<ConstantExpr>(cur) && 
           "hit symbolic char while reading concrete string");
    c = cast<ConstantExpr>(cur)->getZExtValue(8);
    if (c == '\0') {
      // we read the whole string
      break;
    }

    buf << c;
  }

  if (c != '\0') {
      klee_warning_once(0, "String not terminated by \\0 passed to "
                           "one of the klee_ functions");
  }

  return buf.str();
}

/****/

void SpecialFunctionHandler::handleAbort(ExecutionState &state,
                                         KInstruction *target,
                                         std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 0 && "invalid number of arguments to abort");
  executor.terminateStateOnError(state, "abort failure",
                                 StateTerminationType::Abort);
}

void SpecialFunctionHandler::handleExit(ExecutionState &state,
                                        KInstruction *target,
                                        std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 && "invalid number of arguments to exit");
  executor.terminateStateOnExit(state);
}

void SpecialFunctionHandler::handleSilentExit(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 && "invalid number of arguments to exit");
  executor.terminateStateEarly(state, "", StateTerminationType::SilentExit);
}

void SpecialFunctionHandler::handleAssert(ExecutionState &state,
                                          KInstruction *target,
                                          std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 3 && "invalid number of arguments to _assert");
  executor.terminateStateOnError(
      state, "ASSERTION FAIL: " + readStringAtAddress(state, arguments[0]),
      StateTerminationType::Assert);
}

void SpecialFunctionHandler::
handleAssertFunc(ExecutionState &state, KInstruction *target,
                 std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 4 && "invalid number of arguments to __assert_func");
  ref<Expr> val = arguments[1];
  klee::ConstantExpr  *CE_val = dyn_cast<ConstantExpr>(val);
  assert(CE_val);
  executor.terminateStateOnError(
      state, "ASSERTION FAIL: " + readStringAtAddress(state, arguments[0])
                                + ":" +std::to_string(CE_val->getZExtValue()),
      StateTerminationType::Assert);
}

void SpecialFunctionHandler::handleAssertFail(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 4 &&
         "invalid number of arguments to __assert_fail");
  executor.terminateStateOnError(
      state, "ASSERTION FAIL: " + readStringAtAddress(state, arguments[0]),
      StateTerminationType::Assert);
}

void SpecialFunctionHandler::handleReportError(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 4 &&
         "invalid number of arguments to klee_report_error");

  // arguments[0,1,2,3] are file, line, message, suffix
  executor.terminateStateOnError(
      state, readStringAtAddress(state, arguments[2]),
      StateTerminationType::ReportError, "",
      readStringAtAddress(state, arguments[3]).c_str());
}

void SpecialFunctionHandler::handleOpenMerge(ExecutionState &state,
    KInstruction *target,
    std::vector<ref<Expr> > &arguments) {
  if (!UseMerge) {
    klee_warning_once(0, "klee_open_merge ignored, use '-use-merge'");
    return;
  }

  state.openMergeStack.push_back(
      ref<MergeHandler>(new MergeHandler(&executor, &state)));

  if (DebugLogMerge)
    llvm::errs() << "open merge: " << &state << "\n";
}

void SpecialFunctionHandler::handleCloseMerge(ExecutionState &state,
    KInstruction *target,
    std::vector<ref<Expr> > &arguments) {
  if (!UseMerge) {
    klee_warning_once(0, "klee_close_merge ignored, use '-use-merge'");
    return;
  }
  Instruction *i = target->inst;

  if (DebugLogMerge)
    llvm::errs() << "close merge: " << &state << " at [" << *i << "]\n";

  if (state.openMergeStack.empty()) {
    std::ostringstream warning;
    warning << &state << " ran into a close at " << i << " without a preceding open";
    klee_warning("%s", warning.str().c_str());
  } else {
    assert(executor.mergingSearcher->inCloseMerge.find(&state) ==
               executor.mergingSearcher->inCloseMerge.end() &&
           "State cannot run into close_merge while being closed");
    executor.mergingSearcher->inCloseMerge.insert(&state);
    state.openMergeStack.back()->addClosedState(&state, i);
    state.openMergeStack.pop_back();
  }
}

void SpecialFunctionHandler::handleNew(ExecutionState &state,
                         KInstruction *target,
                         std::vector<ref<Expr> > &arguments) {
  // XXX should type check args
  assert(arguments.size()==1 && "invalid number of arguments to new");

  executor.executeAlloc(state, arguments[0], false, target);
}

void SpecialFunctionHandler::handleDelete(ExecutionState &state,
                            KInstruction *target,
                            std::vector<ref<Expr> > &arguments) {
  // FIXME: Should check proper pairing with allocation type (malloc/free,
  // new/delete, new[]/delete[]).

  // XXX should type check args
  assert(arguments.size()==1 && "invalid number of arguments to delete");
  executor.executeFree(state, arguments[0]);
}

void SpecialFunctionHandler::handleNewArray(ExecutionState &state,
                              KInstruction *target,
                              std::vector<ref<Expr> > &arguments) {
  // XXX should type check args
  assert(arguments.size()==1 && "invalid number of arguments to new[]");
  executor.executeAlloc(state, arguments[0], false, target);
}

void SpecialFunctionHandler::handleDeleteArray(ExecutionState &state,
                                 KInstruction *target,
                                 std::vector<ref<Expr> > &arguments) {
  // XXX should type check args
  assert(arguments.size()==1 && "invalid number of arguments to delete[]");
  executor.executeFree(state, arguments[0]);
}

void SpecialFunctionHandler::handleMalloc(ExecutionState &state,
                                  KInstruction *target,
                                  std::vector<ref<Expr> > &arguments) {
  // XXX should type check args
  assert(arguments.size()==1 && "invalid number of arguments to malloc");
  executor.executeAlloc(state, arguments[0], false, target);
}

void SpecialFunctionHandler::handleMemalign(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  if (arguments.size() != 2) {
    executor.terminateStateOnUserError(state,
      "Incorrect number of arguments to memalign(size_t alignment, size_t size)");
    return;
  }

  std::pair<ref<Expr>, ref<Expr>> alignmentRangeExpr =
      executor.solver->getRange(state.constraints, arguments[0],
                                state.queryMetaData);
  ref<Expr> alignmentExpr = alignmentRangeExpr.first;
  auto alignmentConstExpr = dyn_cast<ConstantExpr>(alignmentExpr);

  if (!alignmentConstExpr) {
    executor.terminateStateOnUserError(state, "Could not determine size of symbolic alignment");
    return;
  }

  uint64_t alignment = alignmentConstExpr->getZExtValue();

  // Warn, if the expression has more than one solution
  if (alignmentRangeExpr.first != alignmentRangeExpr.second) {
    klee_warning_once(
        0, "Symbolic alignment for memalign. Choosing smallest alignment");
  }

  executor.executeAlloc(state, arguments[1], false, target, false, 0,
                        alignment);
}

#ifdef SUPPORT_KLEE_EH_CXX
void SpecialFunctionHandler::handleEhUnwindRaiseExceptionImpl(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to _klee_eh_Unwind_RaiseException_impl");

  ref<ConstantExpr> exceptionObject = dyn_cast<ConstantExpr>(arguments[0]);
  if (!exceptionObject.get()) {
    executor.terminateStateOnExecError(state, "Internal error: Symbolic exception pointer");
    return;
  }

  if (isa_and_nonnull<SearchPhaseUnwindingInformation>(
          state.unwindingInformation.get())) {
    executor.terminateStateOnExecError(
        state,
        "Internal error: Unwinding restarted during an ongoing search phase");
    return;
  }

  state.unwindingInformation =
      std::make_unique<SearchPhaseUnwindingInformation>(exceptionObject,
                                                        state.stack.size() - 1);

  executor.unwindToNextLandingpad(state);
}

void SpecialFunctionHandler::handleEhTypeid(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_eh_typeid_for");

  executor.bindLocal(target, state, executor.getEhTypeidFor(arguments[0]));
}
#endif // SUPPORT_KLEE_EH_CXX

void SpecialFunctionHandler::handleAssume(ExecutionState &state,
                            KInstruction *target,
                            std::vector<ref<Expr> > &arguments) {
  assert(arguments.size()==1 && "invalid number of arguments to klee_assume");
  
  ref<Expr> e = arguments[0];
  
  if (e->getWidth() != Expr::Bool)
    e = NeExpr::create(e, ConstantExpr::create(0, e->getWidth()));
  
  bool res;
  bool success __attribute__((unused)) = executor.solver->mustBeFalse(
      state.constraints, e, res, state.queryMetaData);
  assert(success && "FIXME: Unhandled solver failure");
  if (res) {
    if (SilentKleeAssume) {
      executor.terminateState(state);
    } else {
      executor.terminateStateOnUserError(
          state, "invalid klee_assume call (provably false)");
    }
  } else {
    executor.addConstraint(state, e);
  }
}

void SpecialFunctionHandler::handleIsSymbolic(ExecutionState &state,
                                KInstruction *target,
                                std::vector<ref<Expr> > &arguments) {
  assert(arguments.size()==1 && "invalid number of arguments to klee_is_symbolic");

  executor.bindLocal(target, state, 
                     ConstantExpr::create(!isa<ConstantExpr>(arguments[0]),
                                          Expr::Int32));
}

void SpecialFunctionHandler::handlePreferCex(ExecutionState &state,
                                             KInstruction *target,
                                             std::vector<ref<Expr> > &arguments) {
  assert(arguments.size()==2 &&
         "invalid number of arguments to klee_prefex_cex");

  ref<Expr> cond = arguments[1];
  if (cond->getWidth() != Expr::Bool)
    cond = NeExpr::create(cond, ConstantExpr::alloc(0, cond->getWidth()));

  state.addCexPreference(cond);
}

void SpecialFunctionHandler::handlePosixPreferCex(ExecutionState &state,
                                             KInstruction *target,
                                             std::vector<ref<Expr> > &arguments) {
  if (ReadablePosix)
    return handlePreferCex(state, target, arguments);
}

void SpecialFunctionHandler::handlePrintExpr(ExecutionState &state,
                                  KInstruction *target,
                                  std::vector<ref<Expr> > &arguments) {
  assert(arguments.size()==2 &&
         "invalid number of arguments to klee_print_expr");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  llvm::errs() << msg_str << ":" << arguments[1] << "\n";
}

void SpecialFunctionHandler::handleSetForking(ExecutionState &state,
                                              KInstruction *target,
                                              std::vector<ref<Expr> > &arguments) {
  assert(arguments.size()==1 &&
         "invalid number of arguments to klee_set_forking");
  ref<Expr> value = executor.toUnique(state, arguments[0]);
  
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(value)) {
    state.forkDisabled = CE->isZero();
  } else {
    executor.terminateStateOnUserError(state, "klee_set_forking requires a constant arg");
  }
}

void SpecialFunctionHandler::handleStackTrace(ExecutionState &state,
                                              KInstruction *target,
                                              std::vector<ref<Expr> > &arguments) {
  state.dumpStack(outs());
}

void SpecialFunctionHandler::handleWarning(ExecutionState &state,
                                           KInstruction *target,
                                           std::vector<ref<Expr> > &arguments) {
  assert(arguments.size()==1 && "invalid number of arguments to klee_warning");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  klee_warning("%s: %s", state.stack.back().kf->function->getName().data(), 
               msg_str.c_str());
}

void SpecialFunctionHandler::handleWarningOnce(ExecutionState &state,
                                               KInstruction *target,
                                               std::vector<ref<Expr> > &arguments) {
  assert(arguments.size()==1 &&
         "invalid number of arguments to klee_warning_once");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  klee_warning_once(0, "%s: %s", state.stack.back().kf->function->getName().data(),
                    msg_str.c_str());
}

void SpecialFunctionHandler::handlePrintRange(ExecutionState &state,
                                  KInstruction *target,
                                  std::vector<ref<Expr> > &arguments) {
  assert(arguments.size()==2 &&
         "invalid number of arguments to klee_print_range");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  llvm::errs() << msg_str << ":" << arguments[1];
  if (!isa<ConstantExpr>(arguments[1])) {
    // FIXME: Pull into a unique value method?
    ref<ConstantExpr> value;
    bool success __attribute__((unused)) = executor.solver->getValue(
        state.constraints, arguments[1], value, state.queryMetaData);
    assert(success && "FIXME: Unhandled solver failure");
    bool res;
    success = executor.solver->mustBeTrue(state.constraints,
                                          EqExpr::create(arguments[1], value),
                                          res, state.queryMetaData);
    assert(success && "FIXME: Unhandled solver failure");
    if (res) {
      llvm::errs() << " == " << value;
    } else { 
      llvm::errs() << " ~= " << value;
      std::pair<ref<Expr>, ref<Expr>> res = executor.solver->getRange(
          state.constraints, arguments[1], state.queryMetaData);
      llvm::errs() << " (in [" << res.first << ", " << res.second <<"])";
    }
  }
  llvm::errs() << "\n";
}

void SpecialFunctionHandler::handleGetObjSize(ExecutionState &state,
                                  KInstruction *target,
                                  std::vector<ref<Expr> > &arguments) {
  // XXX should type check args
  assert(arguments.size()==1 &&
         "invalid number of arguments to klee_get_obj_size");
  Executor::ExactResolutionList rl;
  executor.resolveExact(state, arguments[0], rl, "klee_get_obj_size");
  for (Executor::ExactResolutionList::iterator it = rl.begin(), 
         ie = rl.end(); it != ie; ++it) {
    executor.bindLocal(
        target, *it->second,
        ConstantExpr::create(it->first.first->size,
                             executor.kmodule->targetData->getTypeSizeInBits(
                                 target->inst->getType())));
  }
}

void SpecialFunctionHandler::handleGetErrno(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr> > &arguments) {
  // XXX should type check args
  assert(arguments.size()==0 &&
         "invalid number of arguments to klee_get_errno");
#ifndef WINDOWS
  int *errno_addr = executor.getErrnoLocation(state);
#else
  int *errno_addr = nullptr;
#endif

  // Retrieve the memory object of the errno variable
  ObjectPair result;
  bool resolved = state.addressSpace.resolveOne(
      ConstantExpr::create((uint64_t)errno_addr, Expr::Int64), result);
  if (!resolved)
    executor.terminateStateOnUserError(state, "Could not resolve address for errno");
  executor.bindLocal(target, state, result.second->read(0, Expr::Int32));
}

void SpecialFunctionHandler::handleErrnoLocation(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr> > &arguments) {
  // Returns the address of the errno variable
  assert(arguments.size() == 0 &&
         "invalid number of arguments to __errno_location/__error");

#ifndef WINDOWS
  int *errno_addr = executor.getErrnoLocation(state);
#else
  int *errno_addr = nullptr;
#endif

  executor.bindLocal(
      target, state,
      ConstantExpr::create((uint64_t)errno_addr,
                           executor.kmodule->targetData->getTypeSizeInBits(
                               target->inst->getType())));
}
void SpecialFunctionHandler::handleCalloc(ExecutionState &state,
                            KInstruction *target,
                            std::vector<ref<Expr> > &arguments) {
  // XXX should type check args
  assert(arguments.size()==2 &&
         "invalid number of arguments to calloc");

  ref<Expr> size = MulExpr::create(arguments[0],
                                   arguments[1]);
  executor.executeAlloc(state, size, false, target, true);
}

void SpecialFunctionHandler::handleRealloc(ExecutionState &state,
                            KInstruction *target,
                            std::vector<ref<Expr> > &arguments) {
  // XXX should type check args
  assert(arguments.size()==2 &&
         "invalid number of arguments to realloc");
  ref<Expr> address = arguments[0];
  ref<Expr> size = arguments[1];

  Executor::StatePair zeroSize =
      executor.fork(state, Expr::createIsZero(size), true, BranchType::Realloc);

  if (zeroSize.first) { // size == 0
    executor.executeFree(*zeroSize.first, address, target);   
  }
  if (zeroSize.second) { // size != 0
    Executor::StatePair zeroPointer =
        executor.fork(*zeroSize.second, Expr::createIsZero(address), true,
                      BranchType::Realloc);

    if (zeroPointer.first) { // address == 0
      executor.executeAlloc(*zeroPointer.first, size, false, target);
    } 
    if (zeroPointer.second) { // address != 0
      Executor::ExactResolutionList rl;
      executor.resolveExact(*zeroPointer.second, address, rl, "realloc");
      
      for (Executor::ExactResolutionList::iterator it = rl.begin(), 
             ie = rl.end(); it != ie; ++it) {
        executor.executeAlloc(*it->second, size, false, target, false, 
                              it->first.second);
      }
    }
  }
}

void SpecialFunctionHandler::handleFree(ExecutionState &state,
                          KInstruction *target,
                          std::vector<ref<Expr> > &arguments) {
  // XXX should type check args
  assert(arguments.size()==1 &&
         "invalid number of arguments to free");
  executor.executeFree(state, arguments[0]);
}

void SpecialFunctionHandler::handleCheckMemoryAccess(ExecutionState &state,
                                                     KInstruction *target,
                                                     std::vector<ref<Expr> > 
                                                       &arguments) {
  assert(arguments.size()==2 &&
         "invalid number of arguments to klee_check_memory_access");

  ref<Expr> address = executor.toUnique(state, arguments[0]);
  ref<Expr> size = executor.toUnique(state, arguments[1]);
  if (!isa<ConstantExpr>(address) || !isa<ConstantExpr>(size)) {
    executor.terminateStateOnUserError(state, "check_memory_access requires constant args");
  } else {
    ObjectPair op;

    if (!state.addressSpace.resolveOne(cast<ConstantExpr>(address), op)) {
      executor.terminateStateOnError(state,
                                     "check_memory_access: memory error",
                                     StateTerminationType::Ptr,
                                     executor.getAddressInfo(state, address));
    } else {
      ref<Expr> chk = 
        op.first->getBoundsCheckPointer(address, 
                                        cast<ConstantExpr>(size)->getZExtValue());
      if (!chk->isTrue()) {
        executor.terminateStateOnError(state,
                                       "check_memory_access: memory error",
                                       StateTerminationType::Ptr,
                                       executor.getAddressInfo(state, address));
      }
    }
  }
}

void SpecialFunctionHandler::handleGetValue(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr> > &arguments) {
  assert(arguments.size()==1 &&
         "invalid number of arguments to klee_get_value");

  executor.executeGetValue(state, arguments[0], target);
}

void SpecialFunctionHandler::handleDefineFixedObject(ExecutionState &state,
                                                     KInstruction *target,
                                                     std::vector<ref<Expr> > &arguments) {
  assert(arguments.size()==2 &&
         "invalid number of arguments to klee_define_fixed_object");
  assert(isa<ConstantExpr>(arguments[0]) &&
         "expect constant address argument to klee_define_fixed_object");
  assert(isa<ConstantExpr>(arguments[1]) &&
         "expect constant size argument to klee_define_fixed_object");
  
  uint64_t address = cast<ConstantExpr>(arguments[0])->getZExtValue();
  uint64_t size = cast<ConstantExpr>(arguments[1])->getZExtValue();
  MemoryObject *mo = executor.memory->allocateFixed(address, size, state.prevPC->inst);
  executor.bindObjectInState(state, mo, false);
  mo->isUserSpecified = true; // XXX hack;
}

void SpecialFunctionHandler::handleMakeSymbolic(ExecutionState &state,
                                                KInstruction *target,
                                                std::vector<ref<Expr> > &arguments) {
  std::string name;

  if (arguments.size() != 3) {
    executor.terminateStateOnUserError(state,
        "Incorrect number of arguments to klee_make_symbolic(void*, size_t, char*)");
    return;
  }

  name = arguments[2]->isZero() ? "" : readStringAtAddress(state, arguments[2]);

  if (name.length() == 0) {
    name = "unnamed";
    klee_warning("klee_make_symbolic: renamed empty name to \"unnamed\"");
  }

  Executor::ExactResolutionList rl;
  executor.resolveExact(state, arguments[0], rl, "make_symbolic");
  
  for (Executor::ExactResolutionList::iterator it = rl.begin(), 
         ie = rl.end(); it != ie; ++it) {
    const MemoryObject *mo = it->first.first;
    mo->setName(name);
    
    const ObjectState *old = it->first.second;
    ExecutionState *s = it->second;
    
    if (old->readOnly) {
      executor.terminateStateOnUserError(*s, "cannot make readonly object symbolic");
      return;
    } 

    // FIXME: Type coercion should be done consistently somewhere.
    bool res;
    bool success __attribute__((unused)) = executor.solver->mustBeTrue(
        s->constraints,
        EqExpr::create(
            ZExtExpr::create(arguments[1], Context::get().getPointerWidth()),
            mo->getSizeExpr()),
        res, s->queryMetaData);
    assert(success && "FIXME: Unhandled solver failure");
    
    if (res) {
      executor.executeMakeSymbolic(*s, mo, name);
    } else {      
      executor.terminateStateOnUserError(*s, "Wrong size given to klee_make_symbolic");
    }
  }
}

void SpecialFunctionHandler::handleMarkGlobal(ExecutionState &state,
                                              KInstruction *target,
                                              std::vector<ref<Expr> > &arguments) {
  assert(arguments.size()==1 &&
         "invalid number of arguments to klee_mark_global");  

  Executor::ExactResolutionList rl;
  executor.resolveExact(state, arguments[0], rl, "mark_global");
  
  for (Executor::ExactResolutionList::iterator it = rl.begin(), 
         ie = rl.end(); it != ie; ++it) {
    const MemoryObject *mo = it->first.first;
    assert(!mo->isLocal);
    mo->isGlobal = true;
  }
}

void SpecialFunctionHandler::handleAddOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on addition",
                                 StateTerminationType::Overflow);
}

void SpecialFunctionHandler::handleSubOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on subtraction",
                                 StateTerminationType::Overflow);
}

void SpecialFunctionHandler::handleMulOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on multiplication",
                                 StateTerminationType::Overflow);
}

void SpecialFunctionHandler::handleDivRemOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on division or remainder",
                                 StateTerminationType::Overflow);
}


// void klee_set_taint(i32 taint, i8 *addr, i32 size)
void SpecialFunctionHandler::handleSetTaint(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments)
{
  if (arguments.size() != 3) {
    executor.terminateStateOnUserError(state,
        "Incorrect number of arguments to klee_set_taint(size_t, void*, size_t)");
    return;
  }

  ref<Expr> taint = arguments[0];
  ref<Expr> address = arguments[1];
  ref<Expr> size = arguments[2];

  klee::ConstantExpr *CE = dyn_cast<ConstantExpr>(taint);
  if (!CE) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint is not supported");
    return;
  }
  klee::ConstantExpr *CE_size = dyn_cast<ConstantExpr>(size);
  if (!CE_size) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint size not supported");
    return;
  }
  klee::ConstantExpr *CE_addr = dyn_cast<ConstantExpr>(address);
  if (!CE_addr) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint address not supported");
    return;
  }

  ObjectPair op;
  if (state.addressSpace.resolveOne(CE_addr, op)) {
    const MemoryObject *mo = op.first;
    ObjectState *os = const_cast<ObjectState*>(op.second);
    // ObjectState *wos = state.addressSpace.getWriteable(mo, os);

    unsigned int taint_size = CE_size->getZExtValue();
    TaintSet ts;
    ts.insert(CE->getZExtValue());
    uint64_t offset = CE_addr->getZExtValue() - mo->address;
    for (unsigned i = 0; i < taint_size; ++i) {
      os->writeTaint(i + offset, ts);
    }
  } else {
    klee_warning_once(
      (void*)CE_addr->getZExtValue(),
      "Cannot resolve the address to be tainted");
    return;
  }
}

// void klee_set_persist_taint(i32 persist_taint, i8 *addr, i32 size)
void SpecialFunctionHandler::
handleSetPersistTaint(ExecutionState &state, KInstruction *target,
                      std::vector<ref<Expr>> &arguments)
{
  if (arguments.size() != 3) {
    executor.terminateStateOnUserError(state,
        "Incorrect number of arguments to klee_set_persist_taint(size_t, void*, size_t)");
    return;
  }

  ref<Expr> taint = arguments[0];
  ref<Expr> address = arguments[1];
  ref<Expr> size = arguments[2];

  klee::ConstantExpr *CE = dyn_cast<ConstantExpr>(taint);
  if (!CE) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint is not supported");
    return;
  }
  klee::ConstantExpr *CE_size = dyn_cast<ConstantExpr>(size);
  if (!CE_size) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint size not supported");
    return;
  }
  klee::ConstantExpr *CE_addr = dyn_cast<ConstantExpr>(address);
  if (!CE_addr) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint address not supported");
    return;
  }

  ObjectPair op;
  if (state.addressSpace.resolveOne(CE_addr, op)) {
    const MemoryObject *mo = op.first;
    ObjectState *os = const_cast<ObjectState*>(op.second);
    // ObjectState *wos = state.addressSpace.getWriteable(mo, os);

    unsigned int taint_size = CE_size->getZExtValue();
    TaintTy theTaint = CE->getZExtValue();
    uint64_t offset = CE_addr->getZExtValue() - mo->address;
    for (unsigned i = 0; i < taint_size; ++i) {
      os->setPersistTaint(i + offset, theTaint);
    }
  } else {
    std::stringstream err_msg;
    err_msg << "Cannot resolve the address to be persistently tainted: "
            << std::hex << CE_addr->getZExtValue();
    klee_warning_once((void*)CE_addr->getZExtValue(),
                      "%s", err_msg.str().c_str());
    return;
  }
}

// i8 klee_has_taint(i8 *addr, i32 size, i32 taint)
void SpecialFunctionHandler::handleHasTaint(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments)
{
  if (arguments.size() != 3) {
    executor.terminateStateOnUserError(state,
        "Incorrect number of arguments to klee_has_taint(void*, size_t, size_t)");
    return;
  }

  ref<Expr> address = arguments[0];
  ref<Expr> size = arguments[1];
  ref<Expr> taint = arguments[2];

  klee::ConstantExpr *CE_size = dyn_cast<ConstantExpr>(size);
  if (!CE_size) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint size not supported");
    return;
  }
  klee::ConstantExpr *CE_addr = dyn_cast<ConstantExpr>(address);
  if (!CE_addr) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint address not supported");
    return;
  }
  klee::ConstantExpr *CE_taint = dyn_cast<ConstantExpr>(taint);
  if (!CE_taint) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint lookup not supported");
    return;
  }

  ObjectPair op;
  if (state.addressSpace.resolveOne(CE_addr, op)) {
    const MemoryObject *mo = op.first;
    const ObjectState *os = op.second;
    // ObjectState *wos = state.addressSpace.getWriteable(mo, os);

    unsigned int taint_size = CE_size->getZExtValue();
    TaintSet ts;
    uint64_t offset = CE_addr->getZExtValue() - mo->address;
    for (unsigned i = 0; i < taint_size; ++i) {
      TaintSet *rt = os->readTaint(i + offset);
      if (rt) {
        mergeTaint(ts, *rt);
      }
    }

    executor.bindLocal(target, state, ConstantExpr::create(
      hasTaint(ts, CE_taint->getZExtValue()),
      Expr::Int8
    ));
  } else {
    executor.terminateStateOnUserError(state,
        "Cannot resolve the address to get taint from");
    return;
  }
}

// i32 klee_get_taint_num(void* addr, size_t size)
void SpecialFunctionHandler::handleGetTaintNum(ExecutionState &state,
                                               KInstruction *target,
                                               std::vector<ref<Expr>> &arguments)
{
  if (arguments.size() != 2) {
    executor.terminateStateOnUserError(state,
        "Incorrect number of arguments to klee_get_taint_num(void*, size_t)");
    return;
  }

  ref<Expr> address = arguments[0];
  ref<Expr> size = arguments[1];

  klee::ConstantExpr *CE_size = dyn_cast<ConstantExpr>(size);
  if (!CE_size) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint size not supported");
    return;
  }
  klee::ConstantExpr *CE_addr = dyn_cast<ConstantExpr>(address);
  if (!CE_addr) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint address not supported");
    return;
  }

  ObjectPair op;
  if (state.addressSpace.resolveOne(CE_addr, op)) {
    const MemoryObject *mo = op.first;
    const ObjectState *os = op.second;
    // ObjectState *wos = state.addressSpace.getWriteable(mo, os);

    unsigned int taint_size = CE_size->getZExtValue();
    TaintSet ts;
    uint64_t offset = CE_addr->getZExtValue() - mo->address;
    for (unsigned i = 0; i < taint_size; ++i) {
      TaintSet *rt = os->readTaint(i + offset);
      if (rt) {
        mergeTaint(ts, *rt);
      }
    }

    executor.bindLocal(target, state, ConstantExpr::create(ts.size(),
                                                           Expr::Int32));
  } else {
    executor.terminateStateOnUserError(state,
        "Cannot resolve the address to get taint from");
    return;
  }
}

// i32 klee_get_taint(void* addr, size_t size, size_t idx)
void SpecialFunctionHandler::handleGetTaint(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments)
{
  if (arguments.size() != 3) {
    executor.terminateStateOnUserError(state,
        "Incorrect number of arguments to klee_get_taint_num(void*, size_t)");
    return;
  }

  ref<Expr> address = arguments[0];
  ref<Expr> size = arguments[1];
  ref<Expr> idx = arguments[2];

  klee::ConstantExpr *CE_size = dyn_cast<ConstantExpr>(size);
  if (!CE_size) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint size not supported");
    return;
  }
  klee::ConstantExpr *CE_addr = dyn_cast<ConstantExpr>(address);
  if (!CE_addr) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint address not supported");
    return;
  }
  klee::ConstantExpr *CE_idx = dyn_cast<ConstantExpr>(idx);
  if (!CE_idx) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint idx not supported");
    return;
  }

  ObjectPair op;
  if (state.addressSpace.resolveOne(CE_addr, op)) {
    const MemoryObject *mo = op.first;
    const ObjectState *os = op.second;
    // ObjectState *wos = state.addressSpace.getWriteable(mo, os);

    unsigned int taint_size = CE_size->getZExtValue();
    TaintSet ts;
    uint64_t offset = CE_addr->getZExtValue() - mo->address;
    for (unsigned i = 0; i < taint_size; ++i) {
      TaintSet *rt = os->readTaint(i + offset);
      if (rt) {
        mergeTaint(ts, *rt);
      }
    }

    assert(CE_idx->getZExtValue() < ts.size());
    std::vector<TaintTy> taints(ts.begin(), ts.end());
    executor.bindLocal(target, state, ConstantExpr::create(taints[CE_idx->getZExtValue()],
                                                           Expr::Int32));
  } else {
    executor.terminateStateOnUserError(state,
        "Cannot resolve the address to get taint from");
    return;
  }
}

// void klee_get_taint_internal(void* addr, size_t size)
void SpecialFunctionHandler::
handleGetTaintInternal(ExecutionState &state, KInstruction *target,
                       std::vector<ref<Expr>> &arguments)
{
  if (arguments.size() != 2) {
    executor.terminateStateOnUserError(state,
        "Incorrect number of arguments to klee_get_taint_internal(void*, size_t)");
    return;
  }

  ref<Expr> address = arguments[0];
  ref<Expr> size = arguments[1];

  klee::ConstantExpr *CE_size = dyn_cast<ConstantExpr>(size);
  if (!CE_size) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint size not supported");
    return;
  }
  klee::ConstantExpr *CE_addr = dyn_cast<ConstantExpr>(address);
  if (!CE_addr) {
    executor.terminateStateOnUserError(state,
        "Un-constant taint address not supported");
    return;
  }

  ObjectPair op;
  if (state.addressSpace.resolveOne(CE_addr, op)) {
    const MemoryObject *mo = op.first;
    const ObjectState *os = op.second;
    // ObjectState *wos = state.addressSpace.getWriteable(mo, os);

    unsigned int taint_size = CE_size->getZExtValue();
    TaintSet ts;
    uint64_t offset = CE_addr->getZExtValue() - mo->address;
    for (unsigned i = 0; i < taint_size; ++i) {
      TaintSet *rt = os->readTaint(i + offset);
      if (rt) {
        for (auto tt : *rt) {
          if (tt & 0x00ff0000) {
            continue;
          }
          addTaint(ts, tt);
        }
      }
    }

    mergeTaint(state.taintedOutcomes, ts);
  } else {
    executor.terminateStateOnUserError(state,
        "Cannot resolve the address to get taint from");
    return;
  }
}

// void klee_get_return_value(size_t)
void SpecialFunctionHandler::
handleGetReturnValue(ExecutionState &state, KInstruction *target,
                     std::vector<ref<Expr>> &arguments)
{
  if (arguments.size() != 1) {
    executor.terminateStateOnUserError(state,
      "Incorrect number of arguments to klee_get_return_value(size_t)");
    return;
  }

  ref<Expr> val = arguments[0];
  klee::ConstantExpr  *CE_val = dyn_cast<ConstantExpr>(val);
  if (!CE_val) {
    std::string err_msg;
    llvm::raw_string_ostream OS(err_msg);
    OS << "Un-constant return value not supported: ";
    val->print(OS);
    executor.terminateStateOnUserError(state, err_msg.c_str());
    return;
  }
  
  state.retVal = CE_val->getZExtValue();
  return;
}

void SpecialFunctionHandler::
handleOOB(ExecutionState &state, KInstruction *target,
          std::vector<ref<Expr>> &arguments)
{
  executor.terminateStateOnError(state, "Array OOB access",
                                 StateTerminationType::Assert);
}
const std::vector<PerryCustomHook> PerryCustomHook::perry_custom_hooks = {
  PerryCustomHook(PERRY_DMA_XFER_CPLT_HOOK, 0),
  PerryCustomHook(PERRY_GENERAL_HOOK, 1),
};

void SpecialFunctionHandler::
handlePerryCustomHook(ExecutionState &state,
                      KInstruction *target, std::vector<ref<Expr>> &arguments) {
  if (arguments.size() < 1) {
    executor.terminateStateOnUserError(state,
      "Incorrect number of arguments to perry_klee_hook(size_t)");
    return;
  }

  ref<Expr> val = arguments[0];
  klee::ConstantExpr  *CE_val = dyn_cast<ConstantExpr>(val);
  if (!CE_val) {
    std::string err_msg;
    llvm::raw_string_ostream OS(err_msg);
    OS << "Un-constant number not supported: ";
    val->print(OS);
    executor.terminateStateOnUserError(state, err_msg.c_str());
    return;
  }

  for (auto &hk : PerryCustomHook::perry_custom_hooks) {
    if (hk.index == CE_val->getZExtValue()) {
      std::vector<ref<PerryExpr>> cur_constraints;
      for (auto &CE : state.constraints) {
        cur_constraints.push_back(
          state.getPerryExpr(executor.perryExprManager, CE));
      }
      if (hk.index == PERRY_DMA_XFER_CPLT_HOOK_IDX) {
        if (arguments.size() > 1) {
          klee::ConstantExpr *cidx = dyn_cast<ConstantExpr>(arguments[1]);
          if (cidx) {
            std::string hn = hk.name + std::to_string(cidx->getZExtValue());
            state.executed_hooks.emplace_back(
              PerryHook(hn, cur_constraints));
            return;
          }
        }
      }
      state.executed_hooks.emplace_back(
        PerryHook(hk.name, cur_constraints));
      return;
    }
  }
}

void SpecialFunctionHandler::
handlePerryCustomHookWrapper(ExecutionState &state,
                             KInstruction *target,
                             std::vector<ref<Expr>> &arguments) {
  std::vector<ref<Expr>> new_args;
  new_args.push_back(ConstantExpr::alloc(1, 32));
  handlePerryCustomHook(state, target, new_args);
}
