cmake_minimum_required(VERSION 3.10.0)
project(racrypt VERSION 0.1.0 LANGUAGES C)


#set(CMAKE_BUILD_TYPE Debug)
if(MSVC)
    enable_language(ASM_MASM)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
else()
	add_compile_options(-Wall -Wextra -Wpedantic)
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

message( "cpu: ${CMAKE_SYSTEM_PROCESSOR}" )

if(MSVC)
    if (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
        list(APPEND SOURCES
            src/cipher/aes_x86_64.asm
            src/digest/sha1_x86_64.asm
            src/digest/sha2_x86_64.asm)
        set_source_files_properties(
            src/cipher/aes_x86_64.asm
            src/digest/sha1_x86_64.asm
            src/digest/sha2_x86_64.asm
            PROPERTY LANGUAGE ASM_MASM)
        set(PLATFORM_DEFINES "-DRACRYPT_USE_ASM")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "X86")
        list(APPEND SOURCES
            src/cipher/aes_x86.asm
            src/digest/sha1_x86.asm
            src/digest/sha2_x86.asm)
        set_source_files_properties(
            src/cipher/aes_x86.asm
            src/digest/sha1_x86.asm
            src/digest/sha2_x86.asm
            PROPERTY LANGUAGE ASM_MASM)
       	set(PLATFORM_DEFINES "-DRACRYPT_USE_ASM")
    endif()
elseif(UNIX OR MINGW)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
        list(APPEND SOURCES
	    	src/cipher/aes_x86.c
            src/digest/sha1_x86.c
            src/digest/sha2_x86.c
        )
		set(PLATFORM_DEFINES "-DRACRYPT_USE_ASM")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
        list(APPEND SOURCES
	    	src/cipher/aes_arm64.c
            src/digest/sha1_arm64.c
            src/digest/sha2_arm64.c
        )
		set(PLATFORM_DEFINES "-DRACRYPT_USE_ASM")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+aes+crypto")
    endif()
endif()

set(PLATFORM_SOURCES)

add_library(racrypt STATIC ${SOURCES})
target_compile_definitions(racrypt PRIVATE ${PLATFORM_DEFINES})
target_include_directories(racrypt PRIVATE "${CMAKE_SOURCE_DIR}/src/include")

add_executable(racrypt_test src/test/bnprint.c src/test/test.c)
#target_link_libraries(racrypt_test PUBLIC racrypt)
target_link_libraries(racrypt_test PRIVATE racrypt)
target_include_directories(racrypt_test PRIVATE "${CMAKE_SOURCE_DIR}/src/include")
add_dependencies(racrypt_test racrypt)
