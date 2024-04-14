FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

ENV TZ=Asia/Shanghai

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update

RUN apt-get -y --allow-downgrades --allow-remove-essential --allow-change-held-packages install apt-utils

# Set the locale
RUN apt-get -y --allow-downgrades --allow-remove-essential --allow-change-held-packages install locales
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Dependencies
RUN apt-get update
RUN apt-get -y --allow-downgrades --allow-remove-essential --allow-change-held-packages install \
    build-essential cmake curl file g++-multilib gcc-multilib git libcap-dev \
    libncurses5-dev libsqlite3-dev libtcmalloc-minimal4 python3-pip unzip \
    graphviz doxygen wget lsb-release software-properties-common gnupg \
    libtool autoconf python3-tabulate libglib2.0-dev libfdt-dev \
    libpixman-1-dev zlib1g-dev ninja-build libcapstone-dev libncurses5 \
    bluez psmisc
RUN pip3 install lit wllvm loguru tomlkit scapy

# Python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Set git Proxy
RUN if [ -n "$HTTPS_PROXY" ]; then \
        git config --global http.proxy "$HTTPS_PROXY" && \
        git config --global https.proxy "$HTTPS_PROXY" \
    ; fi

# Dependencies
RUN cd /root && \
    git clone https://github.com/gperftools/gperftools.git && \
    cd gperftools && git checkout gperftools-2.15 && \
    ./autogen.sh && ./configure && make -j$(nproc) && make install
RUN cd /root && \
    wget https://developer.arm.com/-/media/Files/downloads/gnu-rm/10.3-2021.10/gcc-arm-none-eabi-10.3-2021.10-x86_64-linux.tar.bz2 -O arm-gnu-toolchain-x86_64-arm-none-eabi.tar.bz2 && \
    tar -jxvf arm-gnu-toolchain-x86_64-arm-none-eabi.tar.bz2
ENV PATH ${PATH}:/root/gcc-arm-none-eabi-10.3-2021.10/bin

# LLVM 13
RUN cd /root && \
    wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 13 all

# Z3
RUN cd /root && \
    git clone https://github.com/Z3Prover/z3.git && \
    cd z3 && \
    git checkout z3-4.13.0 && \
    mkdir build && cd build && \
    cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release ../ && \
    make -j$(nproc) && make install

# AFL
RUN cd /root && \
    git clone https://github.com/google/AFL.git && \
    cd AFL && make -j$(nproc)

# QEMU-FUZZ
RUN cd /root && \
    git clone https://github.com/VoodooChild99/qemu-system-fuzzing.git && \
    cd qemu-system-fuzzing && chmod +x qemu-config.sh && \
    ./qemu-config.sh && cd build && make -j$(nproc)

# QEMU-EMULATION
COPY qemu-config.sh /root/qemu-config.sh
RUN cd /root && \
    git clone https://github.com/qemu/qemu.git && \
    cd qemu && git checkout v7.2.0 && \
    cp ../qemu-config.sh ./qemu-config.sh && \
    chmod +x qemu-config.sh && ./qemu-config.sh && \
    cd build && make -j$(nproc)

# Perry Artifacts
RUN cd /root && \
    git clone https://github.com/VoodooChild99/perry-experiments.git

# Perry Clang plugin
RUN cd /root && \
    git clone https://github.com/VoodooChild99/perry-clang-plugin && \
    cd perry-clang-plugin && \
    LLVM_CONFIG=llvm-config-13 ./cmake-config.sh && \
    cd build && make -j$(nproc)

# Perry
RUN cd /root && \
    git clone https://github.com/VoodooChild99/perry.git && \
    cd perry && git checkout master && \
    LLVM_CONFIG=llvm-config-13 Z3_INSTALL_PATH=/usr/local ./cmake-config.sh && \
    cd build && make -j$(nproc) && \
    cd ../synthesizer && pip install -r requirements.txt

# Drivers
RUN cd /root && \
    git clone https://github.com/VoodooChild99/perry-drivers.git HAL-Collection && \
    cd HAL-Collection && \
    PERRY_DIR=/root/perry PERRY_CLANG_PATH=/root/perry-clang-plugin/build/compiler LLVM_CONFIG=llvm-config-13 ./build_all.sh

# Unset git proxy
RUN if [ -n "$HTTPS_PROXY" ]; then \
        git config --global --unset http.proxy && \
        git config --global --unset https.proxy \
    ; fi