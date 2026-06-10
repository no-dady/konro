set(CMAKE_CXX_STANDARD 14)

add_executable(testsecuritymetric testsecuritymetric.cpp ../rm/securitymonitor/sai.cpp)
target_include_directories(testsecuritymetric PRIVATE ../rm/securitymonitor)
