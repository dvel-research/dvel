#[[
Shared helper to build and expose the Rust core static library (`dvel_core`)
to C++ targets. This assumes the repository layout:
  - rust-core/
  - include/dvel_ffi.h
]]

if(TARGET dvel_core)
  return()
endif()

find_program(CARGO cargo REQUIRED)

# Resolve paths relative to the project that included this module.
get_filename_component(DVEL_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(DVEL_RUST_CORE_DIR "${DVEL_ROOT_DIR}/rust-core")
set(DVEL_RUST_TARGET_DIR "${DVEL_RUST_CORE_DIR}/target")
if(WIN32 AND NOT MINGW)
  set(DVEL_RUST_LIB "${DVEL_RUST_TARGET_DIR}/release/dvel_core.lib")
else()
  set(DVEL_RUST_LIB "${DVEL_RUST_TARGET_DIR}/release/libdvel_core.a")
endif()

add_custom_target(dvel_core_build ALL
  COMMAND "${CARGO}" build --release
  WORKING_DIRECTORY "${DVEL_RUST_CORE_DIR}"
  BYPRODUCTS "${DVEL_RUST_LIB}"
  COMMENT "Building Rust core static library (release)"
  VERBATIM
)

add_library(dvel_core STATIC IMPORTED GLOBAL)
set_property(TARGET dvel_core PROPERTY IMPORTED_LOCATION "${DVEL_RUST_LIB}")
add_dependencies(dvel_core dvel_core_build)

target_include_directories(dvel_core INTERFACE "${DVEL_ROOT_DIR}/include")
