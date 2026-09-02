cmake_minimum_required(VERSION 3.22.1)
project(unirevlab_testtarget C)

add_library(unirevlab_fixture SHARED fixture.c)

find_library(log-lib log)
target_link_libraries(unirevlab_fixture ${log-lib})
