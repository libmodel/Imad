//
//  jailbreakd.m
//  topanga
//
//  Created by Abraham Masri on 12/17/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include <dlfcn.h>
#include <copyfile.h>
#include <stdio.h>
#include <spawn.h>
#include <unistd.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>

#include "jailbreak.h"
#include "utilities.h"
#include "libjb.h"
#include "kutils.h"
#include "kcall.h"
#include "symbols.h"
#include "kmem.h"
#include "amfi_codesign.h"
#include "patchfinder64_11.h"

#include <errno.h>
#include <dirent.h>

NSMutableArray *processed_procs;

/*
 *  Purpose: scans for new procs (all procs AFTER ours)
 */
void *start_scanning() {
    
    if(processed_procs == nil)
        processed_procs = [[NSMutableArray alloc] init];
    
    uint64_t task_self = task_self_addr();
    
    // un-modified struct that starts from our task
    uint64_t original_struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    uint64_t forward_struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    // uh..
    while(1) {
        
        // go backwards first
        while (forward_struct_task != -1) {
            uint64_t bsd_info = rk64(forward_struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
            
            // check if we already processed this proc
            if([processed_procs containsObject:@(bsd_info)])
                continue;

            uint32_t csflags = kread_uint32(bsd_info  + 0x2a8 /* csflags */);
            csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
            kwrite_uint32(bsd_info  + 0x2a8 /* csflags */, csflags);
            
//            printf("[INFO]: processed pid: %x\n", rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID)));

            [processed_procs addObject:@(bsd_info)];
            forward_struct_task = rk64(forward_struct_task + koffset(KSTRUCT_OFFSET_TASK_NEXT));
        }
        
        printf("reached the end of the struct. doing it again..\n");
        forward_struct_task = original_struct_task;
    }
    

}

/*
 *  Purpose: Any initialization required is done here
 */
void start_jailbreakd(void) {
    
    printf("[*]: welcome to jailbreakd\n");
    sleep(1);
    
    printf("[INFO]: scanning for new procs in a separate thread\n");
    pthread_t tid;
    pthread_create(&tid, NULL, start_scanning, NULL);
    printf("[INFO]: scanner is running!\n");
}
