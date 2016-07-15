set ( SERVER_TOP "${CMAKE_SOURCE_DIR}/server/" )

set ( SERVER_SRC_LIST
  ${SERVER_TOP}/main.c
)

add_executable ( tls-test-server ${SERVER_SRC_LIST} )
target_link_libraries ( tls-test-server )

install ( TARGETS tls-test-server DESTINATION bin )
