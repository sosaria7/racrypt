lib_LTLIBRARIES = libracrypt.la
libracrypt_la_CFLAGS = -O2 -Wall
libracrypt_la_LDFLAGS = -version-info 1:0:0
libracrypt_la_SOURCES = \
	bignumber.c	\
	gcd.c	\
	montexpmod.c	\
	prime.c	\
	rsa.c	\
	asn1.c

bin_PROGRAMS = racrypt_test
racrypt_test_CFLAGS = -O2 -Wall
racrypt_test_LDADD = libracrypt.la
racrypt_test_SOURCES = \
	test.c
