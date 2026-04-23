add_library(vdpf_core STATIC vdpf.cpp)

target_include_directories(vdpf_core PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fss-core
    ${CMAKE_SOURCE_DIR}/fss-core/DPF-source
    ${CMAKE_SOURCE_DIR}/fss-core/libPSI
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe/cryptoTools
    ${CMAKE_SOURCE_DIR}/secure-indices/core)

find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    target_link_libraries(vdpf_core PUBLIC OpenMP::OpenMP_CXX)
endif()
