cmake_minimum_required(VERSION 3.10)
project(libecc C)
include_directories(include)

add_compile_options(-Wall -pedantic -fno-builtin -std=c99)

# 交叉编译时启用
# 设置库文件搜索根目 (交叉编译的链接库位于/usr/arm-linux-gnueabihf下)
#set(CMAKE_FIND_ROOT_PATH /usr/arm-linux-gnueabihf)
#set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
#set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
#set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
#set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
#set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)


FILE(GLOB FP src/fp/*.c)
FILE(GLOB CURVES src/curves/*.c)
FILE(GLOB NN src/nn/*.c)
FILE(GLOB SIG src/sig/*.c)
FILE(GLOB HASH src/hash/*.c)
FILE(GLOB UTILS src/utils/*.c)

MESSAGE("hash src")
MESSAGE("${HASH}")

# 椭圆曲线密码库
add_library(ecc
            ${FP}
            ${CURVES}
            ${HASH}
            ${NN}
            ${SIG}
            ${UTILS}
        )

# 椭圆曲线运算库
add_library(ec
            ${FP}
            ${CURVES}
            ${NN}
            ${UTILS})

# 有限域大整数运算库
add_library(arith
            ${FP}
            ${NN}
            ${UTILS})

