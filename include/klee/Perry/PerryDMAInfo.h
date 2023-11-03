#pragma once

#include "klee/Perry/PerryExpr.h"
#include "klee/Perry/PerryZ3Builder.h"

#include <unordered_map>
#include <unordered_set>

namespace klee {

struct PerryDMAInfo {
    struct SymbolInfo {
        std::string sym;
        int idx;

        SymbolInfo(const std::string &sym, int idx): sym(sym), idx(idx) {}

        SymbolInfo() = default;
    };
    std::unordered_map<std::string, SymbolInfo> src_symbol;
    std::unordered_map<std::string, SymbolInfo> dst_symbol;
    std::unordered_map<std::string, SymbolInfo> cnt_symbol;
    std::unordered_set<unsigned> src_reg_idx;
    std::unordered_set<unsigned> dst_reg_idx;
    std::unordered_set<unsigned> cnt_reg_idx;
};

extern PerryDMAInfo *perry_dma_info;

}