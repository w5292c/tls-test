cmake_minimum_required ( VERSION 2.8 )

project ( tls-test C )

add_subdirectory ( data )
add_subdirectory ( client )
add_subdirectory ( server )

set ( CPACK_GENERATOR "DEB" )
set ( CPACK_PACKAGE_VERSION "0.1" )
set ( CPACK_PACKAGE_NAME "tls-test" )
set ( CPACK_PACKAGE_VENDOR "w5292c" )
set ( CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE 1 )
set ( CPACK_DEBIAN_PACKAGE_MAINTAINER "w5292c" )
set ( CPACK_PACKAGE_DESCRIPTION_SUMMARY "tls-test - Playing with TLS communication" )
set ( CPACK_DEBIAN_PACKAGE_DEPENDS "libc6" )

include ( CPack )
