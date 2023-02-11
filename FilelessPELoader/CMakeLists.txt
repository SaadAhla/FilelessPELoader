set(CMAKE_SOURCE_DIR src)

add_executable(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/${PROJECT_NAME}.cpp)

if(CMAKE_GENERATOR MATCHES "Visual Studio")
	set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "${PROJECT_NAME}")
endif()