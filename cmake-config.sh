#!/bin/bash

cmake   -DLLVMCC=/usr/local/bin/clang \
        -DLLVMCXX=/usr/local/bin/clang++ \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_BUILD_TYPE=Release \
        -DENABLE_SOLVER_Z3=ON \
        -DLLVM_CONFIG_BINARY=/usr/local/bin/llvm-config \
        ../