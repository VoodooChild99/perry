#!/bin/bash

rm -rf build && mkdir build
cd build || exit 1

if [ -z $LLVM_CONFIG ]; then
	echo "[*] LLVM_CONFIG is not specified, default to llvm-config"
	LLVM_CONFIG=llvm-config
fi

LLVM_CONFIG_BIN=$(which $LLVM_CONFIG) || (echo "[x] Failed to locate $LLVM_CONFIG." && exit 1)

if [ "$DEBUG" = "1" ]; then
	cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
		  -DENABLE_SOLVER_Z3=ON \
		  -DENABLE_SOLVER_STP=OFF \
		  -DLLVM_CONFIG_BINARY=$LLVM_CONFIG_BIN \
		  -DCMAKE_BUILD_TYPE=Debug \
		  ../
elif [ "$ASAN" = "1" ]; then
	cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
				-DENABLE_SOLVER_Z3=ON \
				-DENABLE_SOLVER_STP=OFF \
				-DLLVM_CONFIG_BINARY=$LLVM_CONFIG_BIN \
				-DCMAKE_BUILD_TYPE=Debug \
				-DCMAKE_C_FLAGS="-O0 -g -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls" \
				-DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls" \
				../
else
	cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
				-DENABLE_SOLVER_Z3=ON \
				-DENABLE_SOLVER_STP=OFF \
				-DLLVM_CONFIG_BINARY=$LLVM_CONFIG_BIN \
				-DCMAKE_BUILD_TYPE=Release \
				../
fi