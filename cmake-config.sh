#!/bin/bash

rm -rf build && mkdir build
cd build || exit 1

if [ -z "$LLVM_CONFIG" ]; then
	echo "[*] LLVM_CONFIG is not specified, default to llvm-config"
	LLVM_CONFIG=llvm-config
fi

if [ -n "$Z3_INSTALL_PATH" ]; then
	echo "[*] Z3_INSTALL_PATH set to $Z3_INSTALL_PATH"
	Z3_CMAKE_FLAG="-DZ3_INSTALL_PATH=$Z3_INSTALL_PATH"
else
	Z3_CMAKE_FLAG=""
fi

LLVM_CONFIG_BIN=$(which $LLVM_CONFIG) || (echo "[x] Failed to locate $LLVM_CONFIG." && exit 1)

if [ "$DEBUG" = "1" ]; then
	cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
		  -DENABLE_SOLVER_Z3=ON \
		  -DENABLE_SOLVER_STP=OFF \
		  -DLLVM_CONFIG_BINARY=$LLVM_CONFIG_BIN \
		  -DCMAKE_BUILD_TYPE=Debug \
		  $Z3_CMAKE_FLAG \
		  ../
elif [ "$ASAN" = "1" ]; then
	cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
		  -DENABLE_SOLVER_Z3=ON \
		  -DENABLE_SOLVER_STP=OFF \
		  -DLLVM_CONFIG_BINARY=$LLVM_CONFIG_BIN \
		  -DCMAKE_BUILD_TYPE=Debug \
		  -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls" \
		  -DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls" \
		  $Z3_CMAKE_FLAG \
		  ../
else
	cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
		  -DENABLE_SOLVER_Z3=ON \
		  -DENABLE_SOLVER_STP=OFF \
		  -DLLVM_CONFIG_BINARY=$LLVM_CONFIG_BIN \
		  -DCMAKE_BUILD_TYPE=Release \
		  $Z3_CMAKE_FLAG \
		  ../
fi