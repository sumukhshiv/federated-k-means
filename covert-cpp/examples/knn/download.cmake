set (IRIS_DATA_URL "https://archive.ics.uci.edu/ml/machine-learning-databases/iris/iris.data")
file (DOWNLOAD
  ${IRIS_DATA_URL}
  ${CMAKE_CURRENT_BINARY_DIR}/iris.data
  STATUS DOWNLOAD_STATUS
)
list (GET DOWNLOAD_STATUS 0 DOWNLOAD_VALUE)
list (GET DOWNLOAD_STATUS 1 DOWNLOAD_MESSAGE)
if (NOT (${DOWNLOAD_VALUE} EQUAL 0))
  message (FATAL_ERROR "${IRIS_DATA_URL}: ${DOWNLOAD_MESSAGE}")
endif ()
