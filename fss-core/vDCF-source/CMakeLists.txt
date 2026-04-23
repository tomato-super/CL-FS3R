add_library(vdcf_core STATIC vdcf.cpp)

target_include_directories(vdcf_core PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fss-core
    ${CMAKE_SOURCE_DIR}/fss-core/DCF-source
    ${CMAKE_SOURCE_DIR}/fss-core/libPSI
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe/cryptoTools
    ${CMAKE_SOURCE_DIR}/secure-indices/core)

find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    target_link_libraries(vdcf_core PUBLIC OpenMP::OpenMP_CXX)
endif()
