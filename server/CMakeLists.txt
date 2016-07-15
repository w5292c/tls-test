find_package ( PkgConfig REQUIRED )

pkg_check_modules ( WOLFSSL       wolfssl        REQUIRED )

include_directories ( ${WOLFSSL_INCLUDE_DIRS} )
link_directories ( ${WOLFSSL_LIBRARY_DIRS} )

set ( SERVER_TOP "${CMAKE_SOURCE_DIR}/server/" )

set ( SERVER_SRC_LIST
  ${SERVER_TOP}/main.c
)

add_executable ( tls-test-server ${SERVER_SRC_LIST} )
target_link_libraries ( tls-test-server ${WOLFSSL_LIBRARIES} )

install ( TARGETS tls-test-server DESTINATION bin )
