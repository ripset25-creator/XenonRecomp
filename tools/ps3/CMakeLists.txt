project("PS3Tools")

add_executable(instruction_coverage "instruction_coverage.cpp")
target_link_libraries(instruction_coverage PRIVATE XenonUtils)
