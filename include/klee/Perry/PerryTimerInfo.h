#pragma once

#include "klee/Perry/PerryExpr.h"
#include "klee/Perry/PerryZ3Builder.h"

#include <set>

namespace klee {

struct PerryTimerInfo {
    int counter_reg_offset = -1;
    int period_reg_offset = -1;
};

extern PerryTimerInfo *perry_timer_info;

}