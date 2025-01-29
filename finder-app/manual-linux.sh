#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-


if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

if [ ! -L ${OUTDIR} ]; then 
	mkdir -p ${OUTDIR}
fi



cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- defconfig
    make -j4 ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- all
fi

echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}/Image
echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
mkdir -p ${OUTDIR}/rootfs
mkdir -p ${OUTDIR}/rootfs/bin ${OUTDIR}/rootfs/dev ${OUTDIR}/rootfs/etc ${OUTDIR}/rootfs/home ${OUTDIR}/rootfs/lib ${OUTDIR}/rootfs/lib64 ${OUTDIR}/rootfs/proc
mkdir -p ${OUTDIR}/rootfs/sbin ${OUTDIR}/rootfs/sys ${OUTDIR}/rootfs/tmp ${OUTDIR}/rootfs/usr ${OUTDIR}/rootfs/var
mkdir -p ${OUTDIR}/rootfs/usr/bin ${OUTDIR}/rootfs/usr/lib ${OUTDIR}/rootfs/usr/sbin
mkdir -p ${OUTDIR}/rootfs/var/log
mkdir -p ${OUTDIR}/rootfs/home


cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
    git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # TODO:  Configure busybox
    make defconfig
else
    cd busybox
fi

# TODO: Make and install busybox
make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu-
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- install


echo "Library dependencies"
${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | grep "Shared library"

full_name=$( which ${CROSS_COMPILE}gcc )
path=${full_name%/*}/../aarch64-none-linux-gnu


# TODO: Add library dependencies to rootfs
cp -v ${path}/libc/lib/ld-linux-aarch64.so.1  ${OUTDIR}/rootfs/lib/
cp -v ${path}/libc/lib64/libm.so.6  ${OUTDIR}/rootfs/lib64/
cp -v ${path}/libc/lib64/libresolv.so.2 ${OUTDIR}/rootfs/lib64/
cp -v ${path}/libc/lib64/libc.so.6 ${OUTDIR}/rootfs/lib64/

# TODO: Make device nodes
cd ${OUTDIR}/rootfs
sudo mknod -m 666 dev/null c 1 3
sudo mknod -m 600 dev/console c 5 1

 

# TODO: Clean and build the writer utility
cd $FINDER_APP_DIR
make clean
make CROSS_COMPILE=${CROSS_COMPILE}
${CROSS_COMPILE}readelf -a writer | grep "program interpreter"
${CROSS_COMPILE}readelf -a writer | grep "Shared library"


# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs
cp finder-test.sh ${OUTDIR}/rootfs/home/
cp finder.sh ${OUTDIR}/rootfs/home/
cp writer ${OUTDIR}/rootfs/home/
cp autorun-qemu.sh ${OUTDIR}/rootfs/home/
mkdir -p ${OUTDIR}/rootfs/home/conf
cp  ./conf/* ${OUTDIR}/rootfs/home/conf

# TODO: Chown the root directory
cd ${OUTDIR}/rootfs/
sudo chown -R root:root *

# TODO: Create initramfs.cpio.gz
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
gzip -f ${OUTDIR}/initramfs.cpio

