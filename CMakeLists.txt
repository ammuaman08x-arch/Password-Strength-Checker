cmake_minimum_required(VERSION 3.14)
project(PasswordStrengthChecker LANGUAGES CXX)

# Ensure C++17 compliance
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Configure GLFW build options before loading it
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)

# Setup FetchContent for package management
include(FetchContent)

message(STATUS "Fetching GLFW...")
FetchContent_Declare(
    glfw
    GIT_REPOSITORY https://github.com/glfw/glfw.git
    GIT_TAG 3.3.8
)
FetchContent_MakeAvailable(glfw)

message(STATUS "Fetching Dear ImGui...")
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.90.5
)
FetchContent_GetProperties(imgui)
if(NOT imgui_POPULATED)
    FetchContent_Populate(imgui)
endif()

# Locate OpenGL which is standard on Windows
find_package(OpenGL REQUIRED)

# Build Dear ImGui static library
add_library(imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)

target_include_directories(imgui PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)

# Link GLFW and OpenGL to Dear ImGui
target_link_libraries(imgui PUBLIC glfw OpenGL::GL)

# Project main executable
add_executable(PasswordStrengthChecker
    src/main.cpp
    src/EntropyCalculator.cpp
    src/PatternDetector.cpp
    src/PasswordDictionary.cpp
    src/ReportGenerator.cpp
    src/PasswordChecker.cpp
)

# Include directories
target_include_directories(PasswordStrengthChecker PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link ImGui and standard libraries
target_link_libraries(PasswordStrengthChecker PRIVATE imgui)

# Post-build copy of assets to binary directory for self-contained offline runtime execution
add_custom_command(TARGET PasswordStrengthChecker POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_SOURCE_DIR}/assets
    $<TARGET_FILE_DIR:PasswordStrengthChecker>/assets
    COMMENT "Copying assets folder to target build output directory..."
)
