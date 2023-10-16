#pragma once

#include "klee/Perry/PerryExpr.h"

#include <set>

namespace klee {

struct PerryEthInfo {
    struct Field {
        int offset;
        int start_bit;
        int num_bits;
    };
    enum DescMemoryLayout {
        UNKNOWN,
        RINGBUF,
        ARRAY,
    };
    std::set<ref<PerryExpr>> last_seg_cs;
    std::set<ref<PerryExpr>> first_seg_cs;
    std::set<ref<PerryExpr>> avail_cs;
    int desc_struct_size = -1;
    int rx_desc_reg_offset = -1;
    int tx_desc_reg_offset = -1;
    Field desc_tx_buf_len;
    bool desc_rx_buf_len_stored_in_reg = false;
    union {
        Field f;
        int reg_offset = -1;
    } desc_rx_buf_len;
    Field desc_rx_frame_len;
    Field desc_buf;
    DescMemoryLayout mem_layout = UNKNOWN;
    Field desc_next_desc;
    std::set<ref<PerryExpr>> last_desc_cs;
};

extern PerryEthInfo *perry_eth_info;

}