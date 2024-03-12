#!/bin/bash

QEMU_CONF_FLAGS=" \
    --target-list=arm-softmmu \
    --audio-drv-list= \
    --disable-install-blobs \
    --disable-alsa \
    --disable-auth-pam \
    --disable-bpf \
    --disable-brlapi \
    --disable-bzip2 \
    --disable-cap-ng \
    --disable-curl \
    --disable-coreaudio \
    --disable-curses \
    --disable-docs \
    --disable-dsound \
    --disable-dbus-display \
    --disable-gettext \
    --disable-gtk \
    --disable-guest-agent-msi \
    --disable-gcrypt \
    --disable-glusterfs \
    --disable-gnutls \
    --disable-hax \
    --disable-hvf \
    --disable-iconv \
    --disable-jack \
    --disable-kvm \
    --disable-l2tpv3 \
    --disable-libiscsi \
    --disable-libnfs \
    --disable-linux-aio \
    --disable-lzo \
    --disable-nettle \
    --disable-lzfse \
    --disable-oss \
    --disable-pa \
    --disable-rbd \
    --disable-sdl \
    --disable-sdl-image \
    --disable-seccomp \
    --disable-selinux \
    --disable-snappy \
    --disable-spice \
    --disable-spice-protocol \
    --disable-u2f \
    --disable-vde \
    --disable-virglrenderer \
    --disable-virtfs \
    --disable-vnc \
    --disable-vnc-jpeg \
    --disable-vnc-sasl \
    --disable-vte \
    --disable-xen \
    --disable-xen-pci-passthrough \
    --disable-zstd \
    --disable-user \
    --disable-linux-user \
    --disable-bsd-user \
    --disable-guest-agent \
    --disable-modules \
    --disable-rdma \
    --disable-pvrdma \
    --disable-vhost-net \
    --disable-vhost-crypto \
    --disable-vhost-kernel \
    --disable-vhost-user \
    --disable-vhost-vdpa \
    --disable-vhost-user-blk-server \
    --disable-live-block-migration \
    --disable-tpm \
    --disable-libssh \
    --disable-opengl \
    --disable-replication \
    --disable-bochs \
    --disable-cloop \
    --disable-dmg \
    --disable-qcow1 \
    --disable-vdi \
    --disable-vvfat \
    --disable-qed \
    --disable-parallels \
    --disable-slirp-smbd \
    --disable-gio \
    --disable-plugins \
    --enable-system \
    --disable-whpx \

"

if [ "$DEBUG" = "1" ]; then
    QEMU_CONF_FLAGS="
        $QEMU_CONF_FLAGS \
        --disable-strip \
        --enable-debug \
        --enable-debug-info \
        --enable-debug-stack-usage \
        --enable-debug-tcg \
        --enable-qom-cast-debug \
        --enable-debug-mutex \
        --enable-werror \
        --enable-trace-backends=log \
    "
else
    QEMU_CONF_FLAGS="
        $QEMU_CONF_FLAGS \
        --disable-debug-info \
        --disable-debug-tcg \
        --disable-qom-cast-debug \
        --disable-debug-mutex \
        --disable-stack-protector \
        --enable-trace-backends=nop \
    "
fi

if [ "$STATIC" = "1" ]; then
    QEMU_CONF_FLAGS="
        $QEMU_CONF_FLAGS \
        --static \
        --disable-pie \
    "
else
    QEMU_CONF_FLAGS="
        $QEMU_CONF_FLAGS \
        --enable-pie \
    "
fi

if [ "$PROFILING" = "1" ]; then
    QEMU_CONF_FLAGS="
        $QEMU_CONF_FLAGS \
        --enable-gprof \
        --enable-profiler \
    "
fi

if [ ! -d build ]; then
    mkdir build
fi
cd build || exit 1
../configure $QEMU_CONF_FLAGS || exit 1