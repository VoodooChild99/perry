#include "klee/Perry/PerryTrace.h"

using namespace klee;

bool PerryTrace::empty() const {
  return trace.empty();
}

void PerryTrace::emplace_back(PerryTraceItem &&PTI) {
  trace.emplace_back(std::move(PTI));
}

void PerryTrace::push_back(const PerryTraceItem &PTI) {
  trace.push_back(PTI);
}

size_t PerryTrace::size() const noexcept {
  return trace.size();
}

PerryTrace::perry_trace_iterator PerryTrace::begin() const {
  return trace.begin();
}

PerryTrace::perry_trace_iterator PerryTrace::end() const {
  return trace.end();
}

PerryTrace::perry_trace_iterator
PerryTrace::erase(PerryTrace::perry_trace_iterator it) {
  return trace.erase(it);
}

PerryTrace::PerryTrace(const PerryTrace &a)
  : trace(a.trace), ts(a.ts) {}