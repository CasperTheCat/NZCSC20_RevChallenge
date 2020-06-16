cmake_minimum_required(VERSION 3.7)
project(ProjectWhiteSpark)

set(CMAKE_CXX_STANDARD 17)

find_package(Threads REQUIRED)

find_package(OpenSSL REQUIRED)
#if (OPENMP_FOUND)
#    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
#    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
#    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
#endif()

if (UNIX)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -masm=intel")
    set (GCCENDFLAGS stdc++fs)
endif(UNIX)

set(headerFiles
    Public/Header/NetConn.h
    Public/Header/WatchInterface.h
    Public/Header/Watchdog.h
    Private/Header/Util.h
)


set(sourceFiles
    Public/Source/Fibre.cpp
    Private/Source/WatchInterface.cpp
    Private/Source/NetConn.cpp
    Private/Source/Watchdog.cpp
)

include_directories(
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/core
        ${CMAKE_SOURCE_DIR}/core/Fibre
        ${OPENSSL_INCLUDE_DIR}
)

add_executable(WSFibre ${sourceFiles})

target_link_libraries(WSFibre
    ${CMAKE_THREAD_LIBS_INIT}
    ${OPENSSL_LIBRARIES}
    ${GCCENDFLAGS}
)

#target_link_libraries(WSTrace
#    TerrainEngine
#    TaskEngine
#    ${CMAKE_THREAD_LIBS_INIT}
#)


