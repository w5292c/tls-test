set ( DATA_TOP "${CMAKE_SOURCE_DIR}/data/" )

set ( DATA_SRC_LIST
  ${DATA_TOP}/server_priv.txt
  ${DATA_TOP}/server_pub.txt
)

install (
  FILES ${DATA_SRC_LIST}
  DESTINATION share/tls-test
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)
