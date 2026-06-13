set(CMAKE_CXX_STANDARD 14)

file(GLOB securitymonitor_SOURCES "*.cpp")
file(GLOB securitymonitor_HEADERS "*.h")

add_library(securitymonitor
    ${securitymonitor_SOURCES} ${securitymonitor_HEADERS}
)

target_link_libraries(securitymonitor rmcommon platformcontrol)
target_include_directories(securitymonitor INTERFACE .)
target_include_directories(securitymonitor PRIVATE
    ${PROJECT_SOURCE_DIR}/rm/platformcontrol
    ${PROJECT_SOURCE_DIR}/rm/platformcontrol/cgroup
    ${PROJECT_SOURCE_DIR}/rm/platformcontrol/cgroup/controllers
    ${PROJECT_SOURCE_DIR}/rm/platformcontrol/utilities
)
