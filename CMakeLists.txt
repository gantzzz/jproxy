cmake_minimum_required(VERSION 3.22)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project(jproxy)

# Find and link libcurl
find_package(CURL REQUIRED)

set(CMAKE_OSX_ARCHITECTURES "x86_64")

# Find and link libjsoncpp
#find_package(jsoncpp REQUIRED)
include(FetchContent)
FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.10.5 # You can specify a specific version
)
FetchContent_MakeAvailable(json)

# Threads
find_package(Threads REQUIRED)

# Add the executable
add_executable(jproxy jproxy.cpp)

include_directories(${JSON_INC_PATH})


target_link_libraries(jproxy PRIVATE Threads::Threads nlohmann_json::nlohmann_json CURL::libcurl)

