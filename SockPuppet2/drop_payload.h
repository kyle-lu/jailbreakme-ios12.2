#ifndef drop_payload_h
#define drop_payload_h

#include <unistd.h>

uint64_t proc_of_pid(pid_t pid);
uint64_t proc_of_name(const char *nm);
void setcsflags(uint64_t proc);
mach_port_t task_for_proc(uint64_t self_proc, uint64_t proc);
void drop_payload();

#endif
