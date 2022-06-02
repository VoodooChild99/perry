#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
add_executable(perry
  main.cpp
)

set(KLEE_LIBS
  kleeCore
)

target_link_libraries(perry ${KLEE_LIBS})

install(TARGETS perry RUNTIME DESTINATION bin)

# The KLEE binary depends on the runtimes
add_dependencies(perry BuildKLEERuntimes)
