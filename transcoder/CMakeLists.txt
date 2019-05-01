cmake_minimum_required(VERSION 3.10)

set(FFMPEG_LIB_DIR "./ThirdParty/ffmpeg")
set(X264_LIB_DIR "./ThirdParty/x264")

include_directories(${FFMPEG_LIB_DIR})
#link_directories(${FFMPEG_LIB_DIR}/libavcodec ${FFMPEG_LIB_DIR}/libavformat  )

project (transcoder)

file(GLOB SOURCES
    *.c
)

option(USE_NVIDIA "complie nvidia" ON)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall  -static ")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++0x  -static")

link_directories( 
    ${X264_LIB_DIR} 
    ${FFMPEG_LIB_DIR}/libavcodec 
    ${FFMPEG_LIB_DIR}/libavfilter  
    ${FFMPEG_LIB_DIR}/libavformat  
    ${FFMPEG_LIB_DIR}/libavdevice  
    ${FFMPEG_LIB_DIR}/libavutil 
    ${FFMPEG_LIB_DIR}/libswscale  
    ${FFMPEG_LIB_DIR}/libswresample   
    ${FFMPEG_LIB_DIR}/libpostproc   
    /usr/lib/x86_64-linux-gnu 
    /usr/local/cuda/lib64
     /usr/local/lib
     /usr/lib )

add_executable(${PROJECT_NAME} ${SOURCES})
#SET(LIBS "${LIBS} -lswscale -lavdevice -lavformat -lavcodec -lavutil")

if(APPLE)
    target_link_libraries(${PROJECT_NAME}
    "-framework AudioToolbox" 
    "-framework VideoToolbox" 
    "-framework MediaToolbox" 
    "-framework CoreMedia" 
    "-framework CoreMediaIO" 
    "-framework CoreVideo" 
    "-framework CoreAudio" 
    "-framework CoreImage" 
    "-framework OpenGL" 
    "-framework AppKit" 
    "-framework QuartzCore"
    "-framework ImageCaptureCore"
    "-framework CoreFoundation"
    "-framework Security"
    "-framework SecurityFoundation"
    "-framework SecurityInterface"
    z  
    iconv 
    bz2 )
endif(APPLE)


set(USE_NVIDIA ON)

if(USE_NVIDIA)
find_package(CUDA 9.0 REQUIRED CUDA_64_BIT_DEVICE_CODE )
message(STATUS "Found CUDA ${CUDA_VERSION_STRING} at ${CUDA_TOOLKIT_ROOT_DIR} ${CUDA_LIBRARIES}   ")
target_link_libraries(${PROJECT_NAME} pthread dl z rt m gnutls  stdc++   gnutls  x264 x265 rtmp  avdevice avfilter postproc avformat avcodec mp3lame  swresample swscale avutil pthread z bz2 
libnppig_static.a
libnppicc_static.a
libnppc_static.a
libnppidei_static.a
libcublas_static.a
libcudart_static.a
culibos
)  
message(STATUS "Added libraries ")

else(USE_NVIDIA)
target_link_libraries(${PROJECT_NAME}  pthread dl z rt m gnutls pthread x264 x265 rtmp  avdevice avfilter postproc avformat avcodec mp3lame  swresample swscale avutil pthread z bz2 )  

endif(USE_NVIDIA)




#target_link_libraries(${PROJECT_NAME}  x264 swscale avdevice avformat avfilter avcodec avutil swresample postproc  pthread  m    )
