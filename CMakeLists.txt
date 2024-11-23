cmake_minimum_required(VERSION 3.10)
project(racrypt)

#set(CMAKE_BUILD_TYPE Debug)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g")
endif()


# 하위 폴더 추가
set(SOURCES
	src/com/bignumber.c
	src/com/gcd.c
	src/com/montexpmod.c
	src/com/prime.c
	src/com/random.c
	src/pk/asn1.c
	src/pk/rsa.c
	src/digest/md2.c
	src/digest/md4.c
	src/digest/md5.c
	src/digest/sha1.c
	src/digest/sha2.c
	src/digest/has160.c
	src/cipher/block_cipher.c
	src/cipher/des.c
	src/cipher/aes.c
	src/cipher/rc4.c
	src/cipher/seed.c
	src/cipher/aria.c
	src/cipher/blowfish.c
	)
	
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
    set(PLATFORM_SOURCES
		src/cipher/aes_x86.c
        src/digest/sha1_x86.c
        src/digest/sha2_x86.c
    )
	set(PLATFORM_DEFINES "-DRACRYPT_USE_ASM")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    set(PLATFORM_SOURCES
		src/cipher/aes_arm64.c
        src/digest/sha1_arm64.c
    )
	set(PLATFORM_DEFINES "-DRACRYPT_USE_ASM_AES -DRACRYPT_USE_ASM_SHA1")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+aes+crypto")
else()
    set(PLATFORM_SOURCES)
endif()

add_library(racrypt STATIC ${SOURCES} ${PLATFORM_SOURCES})
target_compile_definitions(racrypt PRIVATE ${PLATFORM_DEFINES})
target_include_directories(racrypt PRIVATE "${CMAKE_SOURCE_DIR}/src/include")

add_executable(racrypt_test src/test/bnprint.c src/test/test.c)
#target_link_libraries(racrypt_test PUBLIC racrypt)
target_link_libraries(racrypt_test PRIVATE racrypt)
target_include_directories(racrypt_test PRIVATE "${CMAKE_SOURCE_DIR}/src/include")
add_dependencies(racrypt_test racrypt)

