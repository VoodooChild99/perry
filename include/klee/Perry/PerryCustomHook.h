#pragma once

#include <string>
#include <vector>

namespace klee {

struct PerryCustomHook {
    std::string name;
    unsigned index;
    PerryCustomHook(const std::string &name, unsigned index)
        : name(name), index(index) {}
    
    static const std::vector<PerryCustomHook> perry_custom_hooks;
};

#define PERRY_DMA_XFER_CPLT_HOOK_IDX    0

#define PERRY_DMA_XFER_CPLT_HOOK    "perry_dma_hook"

}
