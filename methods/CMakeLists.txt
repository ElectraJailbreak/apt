# Create the executable targets
add_executable(file file.cc)
add_executable(copy copy.cc)
add_executable(store store.cc)
add_executable(gpgv gpgv.cc)
add_executable(cdrom cdrom.cc)
add_executable(http http.cc http_main.cc rfc2553emu.cc connect.cc basehttp.cc)
add_executable(ftp ftp.cc rfc2553emu.cc connect.cc)
add_executable(rred rred.cc)
add_executable(rsh rsh.cc)

# Link the executables against the libraries
target_link_libraries(file apt-pkg)
target_link_libraries(copy apt-pkg)
target_link_libraries(store apt-pkg)
target_link_libraries(gpgv apt-pkg)
target_link_libraries(cdrom apt-pkg)
target_link_libraries(http apt-pkg)
target_link_libraries(ftp apt-pkg)
target_link_libraries(rred apt-pkg)
target_link_libraries(rsh apt-pkg)

# Install the library
install(TARGETS file copy store gpgv cdrom http ftp rred rsh
        RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/apt/methods)

add_slaves(${CMAKE_INSTALL_LIBEXECDIR}/apt/methods store gzip lzma bzip2 xz)
add_slaves(${CMAKE_INSTALL_LIBEXECDIR}/apt/methods rsh ssh)
