# Include apt-pkg directly, as some files have #include <system.h>
include_directories(${PROJECT_BINARY_DIR}/include/apt-pkg)

add_definitions("-DAPT_PKG_EXPOSE_STRING_VIEW")

# Set the version of the library
execute_process(COMMAND awk -v ORS=. "/^\#define APT_PKG_M/ {print \$3}"
                COMMAND sed "s/\\.\$//"
                INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/contrib/macros.h
                OUTPUT_VARIABLE MAJOR OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND grep "^#define APT_PKG_RELEASE"
                COMMAND cut -d " " -f 3
                INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/contrib/macros.h
                OUTPUT_VARIABLE MINOR OUTPUT_STRIP_TRAILING_WHITESPACE)

message(STATUS "Building libapt-pkg ${MAJOR} (release ${MINOR})")
set(APT_PKG_MAJOR ${MAJOR} PARENT_SCOPE) # exporting for methods/CMakeLists.txt

# Definition of the C++ files used to build the library
file(GLOB_RECURSE library "*.cc")
file(GLOB_RECURSE headers "*.h")

# Create a library using the C++ files
add_library(apt-pkg SHARED ${library})
add_dependencies(apt-pkg apt-pkg-versionscript)
# Link the library and set the SONAME
target_include_directories(apt-pkg
                           PRIVATE ${ZLIB_INCLUDE_DIRS}
                                   ${BZIP2_INCLUDE_DIRS}
                                   ${LZMA_INCLUDE_DIRS}
                                   ${LZ4_INCLUDE_DIRS})
target_link_libraries(apt-pkg
                      PRIVATE -lutil -ldl -lresolv
                             ${CMAKE_THREAD_LIBS_INIT}
                             ${ZLIB_LIBRARIES}
                             ${BZIP2_LIBRARIES}
                             ${LZMA_LIBRARIES}
                             ${LZ4_LIBRARIES})
set_target_properties(apt-pkg PROPERTIES VERSION ${MAJOR}.${MINOR})
set_target_properties(apt-pkg PROPERTIES SOVERSION ${MAJOR})
add_version_script(apt-pkg)

# Install the library and the header files
install(TARGETS apt-pkg LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${headers} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/apt-pkg)
flatify(${PROJECT_BINARY_DIR}/include/apt-pkg/ "${headers}")