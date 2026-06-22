set(CMAKE_CXX_STANDARD 14)

add_executable(testsecuritypolicy testsecuritypolicy.cpp ../rm/policymanager/policies/secstate.cpp)
target_include_directories(testsecuritypolicy PRIVATE ../rm/policymanager/policies)
add_test(NAME testsecuritypolicy COMMAND testsecuritypolicy)
