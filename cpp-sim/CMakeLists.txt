cmake_minimum_required(VERSION 3.16)
project(dvel_cpp_sim)

set(CMAKE_CXX_STANDARD 17)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../cmake")
include(RustCore)

# Protocol testing simulations (experimental, not production)
add_executable(sim_baseline executables/protocol_tests/sim_baseline.cpp)
add_executable(sim_scenario executables/protocol_tests/sim_scenario.cpp)
add_executable(sim_sybil executables/protocol_tests/sim_sybil.cpp)
add_executable(sim_scheduler executables/protocol_tests/sim_scheduler.cpp)
add_executable(sim_metrics executables/protocol_tests/sim_metrics.cpp)

# Attack scenario simulations (security research)
add_executable(sim_attack_eclipse executables/attacks/sim_attack_eclipse.cpp)
add_executable(sim_attack_51percent executables/attacks/sim_attack_51percent.cpp)
add_executable(sim_attack_sybil_flood executables/attacks/sim_attack_sybil_flood.cpp)
add_executable(sim_attack_partition executables/attacks/sim_attack_partition.cpp)

# Production executable
add_executable(gov_ledger executables/gov_ledger.cpp)

# TFT Cinematic Hardware Visualizer
add_executable(sim_tft executables/sim_tft.cpp)

# Set include directories and link libraries for all targets
set(ALL_TARGETS
  sim_baseline sim_scenario sim_sybil sim_scheduler sim_metrics
  sim_attack_eclipse sim_attack_51percent sim_attack_sybil_flood sim_attack_partition
  gov_ledger
  sim_tft
)

foreach(target IN LISTS ALL_TARGETS)
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/core")
  if(WIN32)
    target_link_libraries(${target} PRIVATE dvel_core ws2_32 userenv ntdll bcrypt)
  else()
    target_link_libraries(${target} PRIVATE dvel_core dl pthread)
  endif()
endforeach()
