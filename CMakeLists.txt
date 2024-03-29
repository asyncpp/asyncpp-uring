cmake_minimum_required(VERSION 3.13)

project(AsyncppUring)

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

if(HUNTER_ENABLED)
  # Workaround hunter hideing system libs
  set(HUNTER_LIBPATH $ENV{PKG_CONFIG_LIBDIR})
  unset(ENV{PKG_CONFIG_LIBDIR})
  pkg_search_module(URING REQUIRED NO_CMAKE_PATH liburing uring)
  set(ENV{PKG_CONFIG_LIBDIR} ${HUNTER_LIBPATH})
else()
  pkg_search_module(URING REQUIRED NO_CMAKE_PATH liburing uring)
endif()

option(ASYNCPP_BUILD_TEST "Enable test builds" ON)
option(ASYNCPP_WITH_ASAN "Enable asan for test builds" ON)
option(ASYNCPP_BUILD_EXAMPLES "Enable building example applications" ON)

if(TARGET asyncpp)
  message(STATUS "Using existing asyncpp target.")
else()
  message(STATUS "Missing asyncpp, using Fetch to import it.")
  include(cmake/Fetch_asyncpp.cmake)
endif()

try_run(OP_LAST OP_LAST_COMPILE_RESULT SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/detect-max-op.c)

add_library(asyncpp_uring INTERFACE)
target_link_libraries(asyncpp_uring INTERFACE asyncpp Threads::Threads
                                              ${URING_LIBRARIES})
target_include_directories(asyncpp_uring
                           INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(asyncpp_uring INTERFACE cxx_std_20)
if(OP_LAST_COMPILE_RESULT)
  target_compile_definitions(asyncpp_uring
                             INTERFACE ASYNCPP_URING_OP_LAST=${OP_LAST})
endif()
# mismatched-new-delete: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=109224
target_compile_options(asyncpp_uring INTERFACE -Wall -Wextra -Wpedantic)
# Clang10 does not know about likely/unlikely macros, however since those are
# only hints we just disable the warning
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION
                                              VERSION_LESS 12.0)
  target_compile_options(asyncpp_uring INTERFACE -Wno-error=unknown-attributes)
endif()
# G++10 does not know about Wmismatched-new-delete
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION
                                            VERSION_GREATER 11.0)
  target_compile_options(asyncpp_uring
                         INTERFACE -Wno-error=mismatched-new-delete)
endif()
if(ASYNCPP_BUILD_TEST)
  enable_testing()
  include(GoogleTest)

  if(HUNTER_ENABLED)
    hunter_add_package(GTest)
    find_package(GTest CONFIG REQUIRED)
    add_library(GTest::GTest ALIAS GTest::gtest)
    add_library(GTest::Main ALIAS GTest::gtest_main)
  else()
    find_package(GTest REQUIRED)
  endif()

  add_executable(
    asyncpp_uring-test
    ${CMAKE_CURRENT_SOURCE_DIR}/test/capability_set.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test/index_set.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test/io_service.cpp)
  target_link_libraries(asyncpp_uring-test PRIVATE asyncpp_uring GTest::GTest
                                                   GTest::Main)

  if(ASYNCPP_WITH_ASAN)
    message(STATUS "Building with asan enabled")
    target_compile_options(asyncpp_uring-test PRIVATE -fsanitize=address)
    target_link_libraries(asyncpp_uring-test PRIVATE asan)
  endif()
  target_compile_options(asyncpp_uring-test PRIVATE -Werror)

  gtest_discover_tests(asyncpp_uring-test)
endif()

if(ASYNCPP_BUILD_EXAMPLES)
  add_executable(uring-info ${CMAKE_CURRENT_SOURCE_DIR}/examples/uring-info.cpp)
  target_link_libraries(uring-info PRIVATE asyncpp_uring)
  target_compile_options(uring-info PRIVATE -Werror)

  add_executable(echo-server
                 ${CMAKE_CURRENT_SOURCE_DIR}/examples/echo-server.cpp)
  target_link_libraries(echo-server PRIVATE asyncpp_uring)
  target_compile_options(echo-server PRIVATE -Werror)

  add_executable(echo-client
                 ${CMAKE_CURRENT_SOURCE_DIR}/examples/echo-client.cpp)
  target_link_libraries(echo-client PRIVATE asyncpp_uring)
  target_compile_options(echo-client PRIVATE -Werror)

  if(ASYNCPP_WITH_ASAN)
    target_compile_options(uring-info PRIVATE -fsanitize=address)
    target_link_libraries(uring-info PRIVATE asan)
    target_compile_options(echo-server PRIVATE -fsanitize=address)
    target_link_libraries(echo-server PRIVATE asan)
    target_compile_options(echo-client PRIVATE -fsanitize=address)
    target_link_libraries(echo-client PRIVATE asan)
  endif()
endif()
