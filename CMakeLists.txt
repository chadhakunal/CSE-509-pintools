cmake_minimum_required(VERSION 3.10)

# Project name and version
project(CSE-509-PinTools VERSION 1.0 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Path to the Intel Pin toolkit
set(PIN_ROOT /home/sekar/Desktop/pin-kit)
set(PIN_INCLUDE_DIR ${PIN_ROOT}/source/include)
set(PIN_LIB_DIR ${PIN_ROOT}/intel64/lib)
set(PIN_XED_INCLUDE_DIR ${PIN_ROOT}/extras/xed-intel64/include)

# Include directories
include_directories(${PIN_INCLUDE_DIR} ${PIN_XED_INCLUDE_DIR})

# Add your source files
set(SOURCES
    src/instruction-count.cpp  # Add your source files here
)

# Define the executable
add_executable(CSE-509-PinTool ${SOURCES})

# Link against the Pin libraries
target_link_libraries(CSE-509-PinTool
    ${PIN_LIB_DIR}/libpin.a
)

# Additional flags for compatibility with Pin
target_compile_options(CSE-509-PinTool PRIVATE
    -DTARGET_IA32E -DHOST_IA32E  # Set architecture-specific flags
    -fno-stack-protector        # Required for Pin
    -fomit-frame-pointer
    -fno-asynchronous-unwind-tables
)

# Linker flags for Pin
target_link_options(CSE-509-PinTool PRIVATE
    -nostdlib
    -static
    -L${PIN_LIB_DIR}
    -L/lib/x86_64-linux-gnu  # Adjust as needed for your system
    -lc -ldl -lpthread
)

# Output directories
set_target_properties(CSE-509-PinTool PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)