set(CMAKE_CXX_STANDARD 14)

add_executable(testsecuritymetric testsecuritymetric.cpp ../rm/librmcommon/sai.cpp)
target_include_directories(testsecuritymetric PRIVATE ../rm/librmcommon)
add_test(NAME testsecuritymetric COMMAND testsecuritymetric)
