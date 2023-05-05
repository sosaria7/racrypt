#!/bin/sh

case $(uname -m) in
	i.86|x86_64)
		CFLAGS="$CFLAGS -DRACRYPT_USE_ASM_X86"
		EXT_OBJS="src/digest/sha1_x86.o src/digest/sha2_x86.o src/cipher/aes_x86.o"
		;;
esac

export CFLAGS
export EXT_OBJS

make -f makefile.unix $@

