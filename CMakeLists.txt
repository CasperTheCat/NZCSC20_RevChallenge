cmake_minimum_required(VERSION 3.7)
project(ProjectWhiteSpark)

set(CMAKE_CXX_STANDARD 17)

#find_package( Threads )
#find_package(OpenMP)
#if (OPENMP_FOUND)
#    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
#    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
#    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
#endif()

#set(FRONT_END
#    main.cpp
#)

#include_directories(
#        ${CMAKE_SOURCE_DIR}
#        ${CMAKE_SOURCE_DIR}/core
#)

#add_executable(WSTrace ${FRONT_END})


#target_link_libraries(WSTrace
#    TerrainEngine
#    TaskEngine
#    ${CMAKE_THREAD_LIBS_INIT}
#)

## Add Lib
add_subdirectory(core/Fibre)
#add_subdirectory(core/Node)
