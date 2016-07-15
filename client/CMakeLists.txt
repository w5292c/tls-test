set ( CLIENT_TOP "${CMAKE_SOURCE_DIR}/client/" )

set ( CLIENT_SRC_LIST
  ${CLIENT_TOP}/main.c
)

add_executable ( tls-test-client ${CLIENT_SRC_LIST} )
target_link_libraries ( tls-test-client )

install ( TARGETS tls-test-client DESTINATION bin )
