cmake_minimum_required(VERSION 3.5)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(GcAuthMgrEmu)
include("${VITASDK}/share/vita.cmake" REQUIRED)

add_compile_definitions(_DEBUG)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -nostdlib")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

add_executable(GcAuthMgrEmu
  main.c
  sha256.c
  sha1.c
  ../cmd56/cmd56.c
  ../cmd56/cmd56_sm.c
  ../cmd56/gc.c
  ../cmd56/vita.c
  ../cmd56/crypto/aes.c
  ../cmd56/crypto/aes_cmac.c
)

target_link_libraries(GcAuthMgrEmu
  taihenForKernel_stub
  SceIofilemgrForDriver_stub
  SceSdifForDriver_stub
  SceNpDrmForDriver_stub
  SceRtcForDriver_stub
  SceRegMgrForDriver_stub
  SceSblSsMgrForDriver_stub
  SceSysclibForDriver_stub
  SceDebugForDriver_stub
  SceThreadmgrForDriver_stub
)

vita_create_self(GcAuthMgrEmu.skprx GcAuthMgrEmu CONFIG exports.yml UNSAFE)