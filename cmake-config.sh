#!/bin/bash

if [ "$DEBUG" = "1" ]; then
	cmake -DLLVMCC=/usr/local/bin/clang \
				-DLLVMCXX=/usr/local/bin/clang++ \
				-DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
				-DENABLE_SOLVER_Z3=ON \
				-DENABLE_SOLVER_STP=OFF \
				-DLLVM_CONFIG_BINARY=/usr/local/bin/llvm-config \
				-DCMAKE_BUILD_TYPE=Debug \
				../
elif [ "$ASAN" = "1" ]; then
	cmake -DLLVMCC=/usr/local/bin/clang \
				-DLLVMCXX=/usr/local/bin/clang++ \
				-DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
				-DENABLE_SOLVER_Z3=ON \
				-DENABLE_SOLVER_STP=OFF \
				-DLLVM_CONFIG_BINARY=/usr/local/bin/llvm-config \
				-DCMAKE_BUILD_TYPE=Debug \
				-DCMAKE_C_FLAGS="-O0 -g -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls" \
				-DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls" \
				../
else
	cmake -DLLVMCC=/usr/local/bin/clang \
				-DLLVMCXX=/usr/local/bin/clang++ \
				-DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
				-DENABLE_SOLVER_Z3=ON \
				-DENABLE_SOLVER_STP=OFF \
				-DLLVM_CONFIG_BINARY=/usr/local/bin/llvm-config \
				-DCMAKE_BUILD_TYPE=RelWithDebInfo \
				../
fi