#!/bin/sh

case $(uname -m) in
	i.86|x86_64)
		CFLAGS="$CFLAGS -DRACRYPT_USE_ASM"
		EXT_OBJS="src/digest/sha1_x86.o src/digest/sha2_x86.o src/cipher/aes_x86.o"
		;;

    aarch64)
        # https://developer.arm.com/documentation/101754/0622/armclang-Reference/armclang-Command-line-Options/-march
        FLAG_ARCH="-march=armv8-a+aes+crypto"
        CFLAGS="$CFLAGS -DRACRYPT_USE_ASM $FLAG_ARCH"
        EXT_OBJS="src/cipher/aes_arm64.o src/digest/sha1_arm64.o src/digest/sha2_arm64.o"
        ;;
esac

export CFLAGS
export EXT_OBJS

make -f makefile.unix $@

