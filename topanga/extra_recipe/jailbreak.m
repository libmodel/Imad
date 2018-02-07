//
//  jailbreak.m
//  topanga
//
//  Created by Abraham Masri @cheesecakeufo on 15/12/2017.
//  Copyright © 2017 Abraham Masri @cheesecakeufo. All rights reserved.
//

#include "jailbreak.h"
#include "libjb.h"
#include "kutils.h"
#include "kcall.h"
#include "symbols.h"
#include "kmem.h"
#include "utilities.h"
#include "amfi_codesign.h"
#include "patchfinder64_11.h"

#include <errno.h>
#include <dirent.h>

uint64_t trust_cache = 0;
uint64_t amficache = 0;

uint64_t containermanagerd_proc = 0;
uint64_t contaienrmanagerd_cred = 0;
uint64_t kern_ucred = 0;
uint64_t kernel_trust = 0;

struct trust_mem mem;

// thanks to unthredera1n
const uint8_t sandbox_original[] = {0x78, 0x08, 0x14, 0x20, 0x04, 0x0f, 0x04, 0xd0};

/*
 * Purpose: iterates over the procs and finds our proc
 */
uint64_t get_proc_for_pid(pid_t target_pid, int spawned) {
    
    uint64_t task_self = task_self_addr();

    uint64_t original_struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    // go backwards first
    while (original_struct_task != -1) {
        uint64_t bsd_info = rk64(original_struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        
        // get the process pid
        uint32_t pid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
        
        if(pid == target_pid) {
            return bsd_info;
        }

        if(spawned) // spawned binaries will exist AFTER our task
            original_struct_task = rk64(original_struct_task + koffset(KSTRUCT_OFFSET_TASK_NEXT));
        else
            original_struct_task = rk64(original_struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
        
    }

    printf("[INFO]: no proc was found for pid: %d\n", target_pid);
    
    return -1; // we failed :/
}

/*
 * Purpose: iterates over the procs and finds a pid with given name
 */
pid_t get_pid_for_name(char *name, int spawned) {
    
    uint64_t task_self = task_self_addr();
    uint64_t struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    
    while (struct_task != 0) {
        uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        
        if (((bsd_info & 0xffffffffffffffff) != 0xffffffffffffffff)) {

            char comm[MAXCOMLEN+1];
            kread(bsd_info + 0x268 /* KSTRUCT_OFFSET_PROC_COMM (is this iPhone X offset??) */, comm, 17);

            if(strcmp(name, comm) == 0) {

                // get the process pid
                uint32_t pid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
                return (pid_t)pid;
            }
        }
        
        if(spawned) // spawned binaries will exist AFTER our task
            struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_NEXT));
        else
            struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
        
        if(struct_task == -1)
            return -1;
    }
    return -1; // we failed :/
}


/*
 *  Purpose: scans a list of procs for a given name.
 *  Since we might have multiple processes with the same name
 */
NSMutableArray *get_pids_list_for_name(char *name) {
    
    NSMutableArray *pids_list = [[NSMutableArray alloc] init];
    
    uint64_t task_self = task_self_addr();
    
    uint64_t struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    while (struct_task != 0) {
        uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        
        if (((bsd_info & 0xffffffffffffffff) != 0xffffffffffffffff)) {
            
            char comm[MAXCOMLEN+1];
            kread(bsd_info + 0x268 /* KSTRUCT_OFFSET_PROC_COMM */, comm, 17);
            
            if(strcmp(name, comm) == 0) {
                
                // get the process pid
                pid_t pid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
                printf("[INFO]: found pid for: %s (%d)\n", name, pid);
                
                if(![pids_list containsObject:@(pid)])
                    [pids_list addObject:@(pid)];
            }
        } else
            break;
        
        if((struct_task & 0xFFFFFFF000000000) == 0 || struct_task == -1) {
            break;
        }
        
        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_NEXT));
    }
    
    return pids_list;
}

uint64_t our_proc = 0;
uint64_t our_cred = 0;

void set_uid0 () {
    
    kern_return_t ret = KERN_SUCCESS;
    
    if(our_proc == 0)
        our_proc = get_proc_for_pid(getpid(), false);
    
    if(our_proc == -1) {
        printf("[ERROR]: no our proc. wut\n");
        ret = KERN_FAILURE;
        return;
    }
    
    extern uint64_t kernel_task;
    
    kern_ucred = kread_uint64(kernel_task + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    
    if(our_cred == 0)
        our_cred = kread_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    
    kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, kern_ucred);
    
    uint64_t offsetof_p_csflags = 0x2a8;
    
    uint32_t csflags = kread_uint32(our_proc + offsetof_p_csflags);
    kwrite_uint32(our_proc + offsetof_p_csflags, (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD));
    
    setuid(0);
    
}

void set_cred_back () {
    kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, our_cred);
}

/*
 *  Purpose: mounts rootFS as read/write
 */
kern_return_t mount_rootfs() {
    
    kern_return_t ret = KERN_SUCCESS;
    
    NSLog(@"kaslr_slide: %llx\n", kaslr_slide);
    NSLog(@"passing kernel_base: %llx\n", kernel_base);
    
    int rv = init_kernel(kernel_base, NULL);
    
    if(rv != 0) {
        NSLog(@"[ERROR]: could not initialize kernel\n");
        ret = KERN_FAILURE;
        return ret;
    }
    
    NSLog(@"[INFO]: sucessfully initialized kernel\n");
    
    uint64_t rootvnode = find_rootvnode();
    NSLog(@"_rootvnode: %llx (%llx)\n", rootvnode, rootvnode - kaslr_slide);
    
    if(rootvnode == 0) {
        ret = KERN_FAILURE;
        return ret;
    }
    
    uint64_t rootfs_vnode = kread_uint64(rootvnode);
    NSLog(@"rootfs_vnode: %llx\n", rootfs_vnode);
    
    uint64_t v_mount = kread_uint64(rootfs_vnode + 0xd8);
    NSLog(@"v_mount: %llx (%llx)\n", v_mount, v_mount - kaslr_slide);
    
    uint32_t v_flag = kread_uint32(v_mount + 0x71);
    NSLog(@"v_flag: %x (%llx)\n", v_flag, v_flag - kaslr_slide);

    kwrite_uint32(v_mount + 0x71, v_flag & ~(1 << 6));
    

    set_uid0();
    printf("our uid: %d\n", getuid());
    char *nmz = strdup("/dev/disk0s1s1");
    rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz);
    
    if(rv == -1) {
        printf("[ERROR]: could not mount '/': %d\n", rv);
    } else {
        printf("[INFO]: successfully mounted '/'\n");
    }
    
    // NOSUID
    uint32_t mnt_flags = kread_uint32(v_mount + 0x70);
    printf("[INFO]: mnt_flags: %x (%llx)\n", mnt_flags, mnt_flags - kaslr_slide);

    kwrite_uint32(v_mount + 0x70, mnt_flags & ~(MNT_ROOTFS >> 6));

    mnt_flags = kread_uint32(v_mount + 0x70);
    printf("[INFO]: mnt_flags (after kwrite): %x (%llx)\n", mnt_flags, mnt_flags - kaslr_slide);


    return ret;
}

/*
 *  Purpose: removes to.panga
 *  you need to run uicache manually after this or multiple reboots to trigger it
 */
kern_return_t remove_topanga() {

    NSMutableArray *bootstrap_files_list = [[NSMutableArray alloc] initWithObjects:
                                                          @"/bin/bash",
                                                          @"/bin/dd",
                                                          @"/bin/ln",
                                                          @"/bin/sed",
                                                          @"/bin/vdir",
                                                          @"/bin/bunzip2",
                                                          @"/bin/dir",
                                                          @"/bin/ls",
                                                          @"/bin/sh",
                                                          @"/bin/zcat",
                                                          @"/bin/bzcat",
                                                          @"/bin/echo",
                                                          @"/bin/mkdir",
                                                          @"/bin/sleep",
                                                          @"/bin/zcmp",
                                                          @"/bin/bzip2",
                                                          @"/bin/egrep",
                                                          @"/bin/mknod",
                                                          @"/bin/stty",
                                                          @"/bin/zdiff",
                                                          @"/bin/bzip2recover",
                                                          @"/bin/false",
                                                          @"/bin/mktemp",
                                                          @"/bin/su",
                                                          @"/bin/zegrep",
                                                          @"/bin/cat",
                                                          @"/bin/fgrep",
                                                          @"/bin/mv",
                                                          @"/bin/sync",
                                                          @"/bin/zfgrep",
                                                          @"/bin/chgrp",
                                                          @"/bin/grep",
                                                          @"/bin/pwd",
                                                          @"/bin/tar",
                                                          @"/bin/zforce",
                                                          @"/bin/chmod",
                                                          @"/bin/gunzip",
                                                          @"/bin/readlink",
                                                          @"/bin/touch",
                                                          @"/bin/zgrep",
                                                          @"/bin/chown",
                                                          @"/bin/gzexe",
                                                          @"/bin/rm",
                                                          @"/bin/true",
                                                          @"/bin/zless",
                                                          @"/bin/cp",
                                                          @"/bin/gzip",
                                                          @"/bin/rmdir",
                                                          @"/bin/uname",
                                                          @"/bin/zmore",
                                                          @"/bin/date",
                                                          @"/bin/kill",
                                                          @"/bin/run-parts",
                                                          @"/bin/uncompress",
                                                          @"/bin/znew",
                                                          @"/Library/LaunchDaemons/0.reload.plist",
                                                          @"/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
                                                          @"/Library/LaunchDaemons/dropbear.plist",
                                                          @"/Library/MobileSubstrate/DynamicLibraries/patcyh.dylib",
                                                          @"/Library/MobileSubstrate/DynamicLibraries/patcyh.plist",
                                                          @"/private/etc/alternatives/README",
                                                          @"/private/etc/apt/sources.list.d/cydia.list",
                                                          @"/private/etc/apt/sources.list.d/saurik.list",
                                                          @"/private/etc/apt/trustdb.gpg",
                                                          @"/private/etc/apt/trusted.gpg",
                                                          @"/private/etc/apt/trusted.gpg.d/bigboss.gpg",
                                                          @"/private/etc/apt/trusted.gpg.d/modmyi.gpg",
                                                          @"/private/etc/apt/trusted.gpg.d/saurik.gpg",
                                                          @"/private/etc/apt/trusted.gpg.d/zodttd.gpg",
                                                          @"/private/etc/dpkg/origins/debian",
                                                          @"/private/etc/pam.d/chkpasswd",
                                                          @"/private/etc/pam.d/sshd",
                                                          @"/private/etc/pam.d/other",
                                                          @"/private/etc/pam.d/su",
                                                          @"/private/etc/pam.d/samba",
                                                          @"/private/etc/pam.d/sudo",
                                                          @"/private/etc/pam.d/login",
                                                          @"/private/etc/pam.d/passwd",
                                                          @"/private/etc/profile",
                                                          @"/private/etc/profile.d/terminal.sh",
                                                          @"/private/var/lib/dpkg/available",
                                                          @"/private/var/lib/dpkg/info/readline.list",
                                                          @"/private/var/lib/dpkg/info/uikittools.list",
                                                          @"/private/var/lib/dpkg/info/debianutils.list",
                                                          @"/private/var/lib/dpkg/info/profile.d.list",
                                                          @"/private/var/lib/dpkg/info/lzma.list",
                                                          @"/private/var/lib/dpkg/info/dpkg.list",
                                                          @"/private/var/lib/dpkg/info/base.extrainst_",
                                                          @"/private/var/lib/dpkg/info/bzip2.list",
                                                          @"/private/var/lib/dpkg/info/ncurses.preinst",
                                                          @"/private/var/lib/dpkg/info/firmware-sbin.preinst",
                                                          @"/private/var/lib/dpkg/info/apt7-key.list",
                                                          @"/private/var/lib/dpkg/info/shell-cmds.list",
                                                          @"/private/var/lib/dpkg/info/ncurses.prerm",
                                                          @"/private/var/lib/dpkg/info/pam.preinst",
                                                          @"/private/var/lib/dpkg/info/pam-modules.list",
                                                          @"/private/var/lib/dpkg/info/com.saurik.patcyh.list",
                                                          @"/private/var/lib/dpkg/info/coreutils-bin.list",
                                                          @"/private/var/lib/dpkg/info/grep.list",
                                                          @"/private/var/lib/dpkg/info/cydia.preinst",
                                                          @"/private/var/lib/dpkg/info/cydia.postinst",
                                                          @"/private/var/lib/dpkg/info/cydia-lproj.list",
                                                          @"/private/var/lib/dpkg/info/system-cmds.list",
                                                          @"/private/var/lib/dpkg/info/gnupg.list",
                                                          @"/private/var/lib/dpkg/info/cydia.list",
                                                          @"/private/var/lib/dpkg/info/firmware-sbin.list",
                                                          @"/private/var/lib/dpkg/info/sed.list",
                                                          @"/private/var/lib/dpkg/info/tar.list",
                                                          @"/private/var/lib/dpkg/info/firmware-sbin.extrainst_",
                                                          @"/private/var/lib/dpkg/info/findutils.list",
                                                          @"/private/var/lib/dpkg/info/com.saurik.patcyh.postrm",
                                                          @"/private/var/lib/dpkg/info/apt7-lib.list",
                                                          @"/private/var/lib/dpkg/info/pam.list",
                                                          @"/private/var/lib/dpkg/info/com.saurik.patcyh.extrainst_",
                                                          @"/private/var/lib/dpkg/info/uikittools.extrainst_",
                                                          @"/private/var/lib/dpkg/info/bash.list",
                                                          @"/private/var/lib/dpkg/info/diffutils.list",
                                                          @"/private/var/lib/dpkg/info/darwintools.list",
                                                          @"/private/var/lib/dpkg/info/ncurses.list",
                                                          @"/private/var/lib/dpkg/info/org.thebigboss.repo.icons.list",
                                                          @"/private/var/lib/dpkg/info/ldid.list",
                                                          @"/private/var/lib/dpkg/info/firmware-sbin.postrm",
                                                          @"/private/var/lib/dpkg/info/pam-modules.preinst",
                                                          @"/private/var/lib/dpkg/info/base.list",
                                                          @"/private/var/lib/dpkg/info/gzip.list",
                                                          @"/private/var/lib/dpkg/status",
                                                          @"/private/var/run/utmp",
                                                          @"/sbin/reboot",
                                                          @"/sbin/halt",
                                                          @"/sbin/dmesg",
                                                          @"/sbin/dynamic_pager",
                                                          @"/sbin/nologin",
                                                          @"/usr/bin/lzmainfo",
                                                          @"/usr/bin/iomfsetgamma",
                                                          @"/usr/bin/chsh",
                                                          @"/usr/bin/gpgv",
                                                          @"/usr/bin/toe",
                                                          @"/usr/bin/cmp",
                                                          @"/usr/bin/locate",
                                                          @"/usr/bin/cfversion",
                                                          @"/usr/bin/gpg-zip",
                                                          @"/usr/bin/dselect",
                                                          @"/usr/bin/infotocap",
                                                          @"/usr/bin/ncursesw5-config",
                                                          @"/usr/bin/dpkg-deb",
                                                          @"/usr/bin/diff3",
                                                          @"/usr/bin/sw_vers",
                                                          @"/usr/bin/gpg",
                                                          @"/usr/bin/df",
                                                          @"/usr/bin/renice",
                                                          @"/usr/bin/captoinfo",
                                                          @"/usr/bin/dpkg-name",
                                                          @"/usr/bin/bashbug",
                                                          @"/usr/bin/dpkg-split",
                                                          @"/usr/bin/chfn",
                                                          @"/usr/bin/tset",
                                                          @"/usr/bin/unlzma",
                                                          @"/usr/bin/uicache",
                                                          @"/usr/bin/reset",
                                                          @"/usr/bin/pagesize",
                                                          @"/usr/bin/gpgsplit",
                                                          @"/usr/bin/diff",
                                                          @"/usr/bin/uiopen",
                                                          @"/usr/bin/dpkg-trigger",
                                                          @"/usr/bin/updatedb",
                                                          @"/usr/bin/ncurses5-config",
                                                          @"/usr/bin/script",
                                                          @"/usr/bin/ldrestart",
                                                          @"/usr/bin/time",
                                                          @"/usr/bin/sbdidlaunch",
                                                          @"/usr/bin/clear",
                                                          @"/usr/bin/tic",
                                                          @"/usr/bin/getconf",
                                                          @"/usr/bin/killall",
                                                          @"/usr/bin/lzless",
                                                          @"/usr/bin/dpkg-query",
                                                          @"/usr/bin/infocmp",
                                                          @"/usr/bin/lzcmp",
                                                          @"/usr/bin/arch",
                                                          @"/usr/bin/xargs",
                                                          @"/usr/bin/getty",
                                                          @"/usr/bin/lzcat",
                                                          @"/usr/bin/ldid",
                                                          @"/usr/bin/uiduid",
                                                          @"/usr/bin/dirname",
                                                          @"/usr/bin/lzdiff",
                                                          @"/usr/bin/find",
                                                          @"/usr/bin/lzmadec",
                                                          @"/usr/bin/lzgrep",
                                                          @"/usr/bin/sdiff",
                                                          @"/usr/bin/lzmore",
                                                          @"/usr/bin/tput",
                                                          @"/usr/bin/lzfgrep",
                                                          @"/usr/bin/hostinfo",
                                                          @"/usr/bin/tar",
                                                          @"/usr/bin/lzma",
                                                          @"/usr/bin/sbreload",
                                                          @"/usr/bin/login",
                                                          @"/usr/bin/which",
                                                          @"/usr/bin/gssc",
                                                          @"/usr/bin/apt-key",
                                                          @"/usr/bin/lzegrep",
                                                          @"/usr/bin/passwd",
                                                          @"/usr/bin/dpkg",
                                                          @"/usr/include/termcap.h",
                                                          @"/usr/include/cursesp.h",
                                                          @"/usr/include/cursesf.h",
                                                          @"/usr/include/etip.h",
                                                          @"/usr/include/form.h",
                                                          @"/usr/include/cursesw.h",
                                                          @"/usr/include/nc_tparm.h",
                                                          @"/usr/include/readline/readline.h",
                                                          @"/usr/include/readline/keymaps.h",
                                                          @"/usr/include/readline/tilde.h",
                                                          @"/usr/include/readline/rlconf.h",
                                                          @"/usr/include/readline/chardefs.h",
                                                          @"/usr/include/readline/history.h",
                                                          @"/usr/include/readline/rlstdc.h",
                                                          @"/usr/include/readline/rltypedefs.h",
                                                          @"/usr/include/unctrl.h",
                                                          @"/usr/include/cursesapp.h",
                                                          @"/usr/include/pam/pam_appl.h",
                                                          @"/usr/include/pam/pam_modules.h",
                                                          @"/usr/include/pam/_pam_types.h",
                                                          @"/usr/include/pam/_pam_macros.h",
                                                          @"/usr/include/pam/_pam_compat.h",
                                                          @"/usr/include/pam/pam_mod_misc.h",
                                                          @"/usr/include/pam/_pam_aconf.h",
                                                          @"/usr/include/term.h",
                                                          @"/usr/include/cursslk.h",
                                                          @"/usr/include/panel.h",
                                                          @"/usr/include/ncurses.h",
                                                          @"/usr/include/tic.h",
                                                          @"/usr/include/eti.h",
                                                          @"/usr/include/ncurses_dll.h",
                                                          @"/usr/include/term_entry.h",
                                                          @"/usr/include/menu.h",
                                                          @"/usr/include/lzmadec.h",
                                                          @"/usr/include/cursesm.h",
                                                          @"/usr/include/ncursesw",
                                                          @"/usr/include/ncursesw/termcap.h",
                                                          @"/usr/include/ncursesw/cursesp.h",
                                                          @"/usr/include/ncursesw/cursesf.h",
                                                          @"/usr/include/ncursesw/etip.h",
                                                          @"/usr/include/ncursesw/form.h",
                                                          @"/usr/include/ncursesw/cursesw.h",
                                                          @"/usr/include/ncursesw/nc_tparm.h",
                                                          @"/usr/include/ncursesw/unctrl.h",
                                                          @"/usr/include/ncursesw/cursesapp.h",
                                                          @"/usr/include/ncursesw/term.h",
                                                          @"/usr/include/ncursesw/cursslk.h",
                                                          @"/usr/include/ncursesw/panel.h",
                                                          @"/usr/include/ncursesw/ncurses.h",
                                                          @"/usr/include/ncursesw/tic.h",
                                                          @"/usr/include/ncursesw/eti.h",
                                                          @"/usr/include/ncursesw/ncurses_dll.h",
                                                          @"/usr/include/ncursesw/term_entry.h",
                                                          @"/usr/include/ncursesw/menu.h",
                                                          @"/usr/include/ncursesw/cursesm.h",
                                                          @"/usr/include/ncursesw/curses.h",
                                                          @"/usr/include/curses.h",
                                                          @"/usr/lib/libhistory.5.dylib",
                                                          @"/usr/lib/libapt-pkg.dylib.4.6",
                                                          @"/usr/lib/libpam.dylib",
                                                          @"/usr/lib/libpamc.1.dylib",
                                                          @"/usr/lib/libapt-pkg.dylib.4.6.0",
                                                          @"/usr/lib/libpanelw.5.dylib",
                                                          @"/usr/lib/libhistory.5.2.dylib",
                                                          @"/usr/lib/libreadline.6.dylib",
                                                          @"/usr/lib/libpanel.dylib",
                                                          @"/usr/lib/libapt-inst.dylib.1.1",
                                                          @"/usr/lib/libcurses.dylib",
                                                          @"/usr/lib/liblzmadec.0.dylib",
                                                          @"/usr/lib/libhistory.6.dylib",
                                                          @"/usr/lib/libformw.dylib",
                                                          @"/usr/lib/libncursesw.dylib",
                                                          @"/usr/lib/libapt-inst.dylib",
                                                          @"/usr/lib/libncurses.5.dylib",
                                                          @"/usr/lib/libapt-pkg.dylib",
                                                          @"/usr/lib/libreadline.5.dylib",
                                                          @"/usr/lib/libhistory.6.0.dylib",
                                                          @"/usr/lib/libform.5.dylib",
                                                          @"/usr/lib/libpanelw.dylib",
                                                          @"/usr/lib/pam/pam_wheel.so",
                                                          @"/usr/lib/pam/pam_securetty.so",
                                                          @"/usr/lib/pam/pam_deny.so",
                                                          @"/usr/lib/pam/pam_rootok.so",
                                                          @"/usr/lib/pam/pam_uwtmp.so",
                                                          @"/usr/lib/pam/pam_launchd.so",
                                                          @"/usr/lib/pam/pam_unix.so",
                                                          @"/usr/lib/pam/pam_permit.so",
                                                          @"/usr/lib/pam/pam_nologin.so",
                                                          @"/usr/lib/libmenuw.dylib",
                                                          @"/usr/lib/libform.dylib",
                                                          @"/usr/lib/terminfo",
                                                          @"/usr/lib/libpam.1.0.dylib",
                                                          @"/usr/lib/libmenu.5.dylib",
                                                          @"/usr/lib/libpatcyh.dylib",
                                                          @"/usr/lib/libreadline.6.0.dylib",
                                                          @"/usr/lib/liblzmadec.dylib",
                                                          @"/usr/lib/apt/methods",
                                                          @"/usr/lib/apt/methods/gpgv",
                                                          @"/usr/lib/apt/methods/https",
                                                          @"/usr/lib/apt/methods/ftp",
                                                          @"/usr/lib/apt/methods/cdrom",
                                                          @"/usr/lib/apt/methods/file",
                                                          @"/usr/lib/apt/methods/rsh",
                                                          @"/usr/lib/apt/methods/gzip",
                                                          @"/usr/lib/apt/methods/ssh",
                                                          @"/usr/lib/apt/methods/http",
                                                          @"/usr/lib/apt/methods/copy",
                                                          @"/usr/lib/apt/methods/rred",
                                                          @"/usr/lib/apt/methods/lzma",
                                                          @"/usr/lib/apt/methods/bzip2",
                                                          @"/usr/lib/libncurses.dylib",
                                                          @"/usr/lib/libhistory.dylib",
                                                          @"/usr/lib/libpamc.dylib",
                                                          @"/usr/lib/libformw.5.dylib",
                                                          @"/usr/lib/libapt-inst.dylib.1.1.0",
                                                          @"/usr/lib/libpanel.5.dylib",
                                                          @"/usr/lib/liblzmadec.0.0.0.dylib",
                                                          @"/usr/lib/_ncurses",
                                                          @"/usr/lib/libpam_misc.1.dylib",
                                                          @"/usr/lib/libreadline.5.2.dylib",
                                                          @"/usr/lib/libpam_misc.dylib",
                                                          @"/usr/lib/libreadline.dylib",
                                                          @"/usr/lib/libmenuw.5.dylib",
                                                          @"/usr/lib/libpam.1.dylib",
                                                          @"/usr/lib/libmenu.dylib",
                                                          @"/usr/lib/liblzmadec.la",
                                                          @"/usr/lib/dpkg/methods/apt/install",
                                                          @"/usr/lib/dpkg/methods/apt/names",
                                                          @"/usr/lib/dpkg/methods/apt/update",
                                                          @"/usr/lib/dpkg/methods/apt/desc.apt",
                                                          @"/usr/lib/dpkg/methods/apt/setup",
                                                          @"/usr/lib/libncursesw.5.dylib",
                                                          @"/usr/libexec/cydia/setnsfpn",
                                                          @"/usr/libexec/cydia/cfversion",
                                                          @"/usr/libexec/cydia/free.sh",
                                                          @"/usr/libexec/cydia/move.sh",
                                                          @"/usr/libexec/cydia/du",
                                                          @"/usr/libexec/cydia/asuser",
                                                          @"/usr/libexec/cydia/finish.sh",
                                                          @"/usr/libexec/cydia/firmware.sh",
                                                          @"/usr/libexec/cydia/startup",
                                                          @"/usr/libexec/cydia/cydo",
                                                          @"/usr/libexec/frcode",
                                                          @"/usr/libexec/bigram",
                                                          @"/usr/libexec/code",
                                                          @"/usr/libexec/reload",
                                                          @"/usr/libexec/gnupg/gpgkeys_hkp",
                                                          @"/usr/libexec/gnupg/gpgkeys_finger",
                                                          @"/usr/libexec/gnupg/gpgkeys_curl",
                                                          @"/usr/libexec/rmt",
                                                          @"/usr/local/bin/dropbear",
                                                          @"/usr/local/bin/dropbearkey",
                                                          @"/usr/local/bin/dropbearconvert",
                                                          @"/usr/sbin/accton",
                                                          @"/usr/sbin/vifs",
                                                          @"/usr/sbin/ac",
                                                          @"/usr/sbin/update",
                                                          @"/usr/sbin/pwd_mkdb",
                                                          @"/usr/sbin/sysctl",
                                                          @"/usr/sbin/zdump",
                                                          @"/usr/sbin/startupfiletool",
                                                          @"/usr/sbin/iostat",
                                                          @"/usr/sbin/mkfile",
                                                          @"/usr/sbin/zic",
                                                          @"/usr/sbin/vipw",
                                                          @"/usr/share/bigboss/icons/planetiphones.png",
                                                          @"/usr/share/bigboss/icons/bigboss.png",
                                                          @"/usr/share/bigboss/icons/touchrev.png",
                                                          @"/usr/share/tabset/vt300",
                                                          @"/usr/share/tabset/std",
                                                          @"/usr/share/tabset/vt100",
                                                          @"/usr/share/tabset/stdcrt",
                                                          @"/usr/share/terminfo/61",
                                                          @"/usr/share/terminfo/67",
                                                          @"/usr/share/terminfo/r/rxvt-xpm",
                                                          @"/usr/share/terminfo/r/rxvt-16color",
                                                          @"/usr/share/terminfo/r/rxvt-cygwin-native",
                                                          @"/usr/share/terminfo/r/rxvt-88color",
                                                          @"/usr/share/terminfo/r/rxvt-cygwin",
                                                          @"/usr/share/terminfo/r/rxvt",
                                                          @"/usr/share/terminfo/r/rxvt-color",
                                                          @"/usr/share/terminfo/r/rxvt-256color",
                                                          @"/usr/share/terminfo/r/rxvt-basic",
                                                          @"/usr/share/terminfo/r/rxvt+pcfkeys",
                                                          @"/usr/share/terminfo/u/unknown",
                                                          @"/usr/share/terminfo/45",
                                                          @"/usr/share/terminfo/73",
                                                          @"/usr/share/terminfo/g/gnome+pcfkeys",
                                                          @"/usr/share/terminfo/g/gnome-rh72",
                                                          @"/usr/share/terminfo/g/gnome-rh80",
                                                          @"/usr/share/terminfo/g/gnome-fc5",
                                                          @"/usr/share/terminfo/g/gnome",
                                                          @"/usr/share/terminfo/g/gnome-2007",
                                                          @"/usr/share/terminfo/g/gnome-2008",
                                                          @"/usr/share/terminfo/g/gnome-256color",
                                                          @"/usr/share/terminfo/g/gnome-rh90",
                                                          @"/usr/share/terminfo/g/gnome-rh62",
                                                          @"/usr/share/terminfo/s",
                                                          @"/usr/share/terminfo/s/screen-16color",
                                                          @"/usr/share/terminfo/s/sun-17",
                                                          @"/usr/share/terminfo/s/sun",
                                                          @"/usr/share/terminfo/s/screen-16color-bce-s",
                                                          @"/usr/share/terminfo/s/screen-256color-bce",
                                                          @"/usr/share/terminfo/s/sun-cgsix",
                                                          @"/usr/share/terminfo/s/screen.rxvt",
                                                          @"/usr/share/terminfo/s/sun-type4",
                                                          @"/usr/share/terminfo/s/sun-e-s",
                                                          @"/usr/share/terminfo/s/sun-cmd",
                                                          @"/usr/share/terminfo/s/screen.xterm-r6",
                                                          @"/usr/share/terminfo/s/sun-c",
                                                          @"/usr/share/terminfo/s/screen-w",
                                                          @"/usr/share/terminfo/s/screen.xterm-xfree86",
                                                          @"/usr/share/terminfo/s/sun-ss5",
                                                          @"/usr/share/terminfo/s/sun-e",
                                                          @"/usr/share/terminfo/s/sun-nic",
                                                          @"/usr/share/terminfo/s/sun-34",
                                                          @"/usr/share/terminfo/s/screen-16color-s",
                                                          @"/usr/share/terminfo/s/screen.linux",
                                                          @"/usr/share/terminfo/s/sun-12",
                                                          @"/usr/share/terminfo/s/screen-256color-bce-s",
                                                          @"/usr/share/terminfo/s/sun-24",
                                                          @"/usr/share/terminfo/s/sun-48",
                                                          @"/usr/share/terminfo/s/screen",
                                                          @"/usr/share/terminfo/s/sun-il",
                                                          @"/usr/share/terminfo/s/screen-bce",
                                                          @"/usr/share/terminfo/s/screen-256color-s",
                                                          @"/usr/share/terminfo/s/screen.mlterm",
                                                          @"/usr/share/terminfo/s/screen-s",
                                                          @"/usr/share/terminfo/s/screen.teraterm",
                                                          @"/usr/share/terminfo/s/screen-16color-bce",
                                                          @"/usr/share/terminfo/s/sun-s",
                                                          @"/usr/share/terminfo/s/sun-1",
                                                          @"/usr/share/terminfo/s/sun-color",
                                                          @"/usr/share/terminfo/s/screen.xterm-new",
                                                          @"/usr/share/terminfo/s/screen-256color",
                                                          @"/usr/share/terminfo/s/screen+fkeys",
                                                          @"/usr/share/terminfo/s/sun-s-e",
                                                          @"/usr/share/terminfo/75",
                                                          @"/usr/share/terminfo/A",
                                                          @"/usr/share/terminfo/A/ansi+idl1",
                                                          @"/usr/share/terminfo/A/ansi+idc",
                                                          @"/usr/share/terminfo/A/apple-soroc",
                                                          @"/usr/share/terminfo/A/apple-videx2",
                                                          @"/usr/share/terminfo/A/apple-vm80",
                                                          @"/usr/share/terminfo/A/apple-videx3",
                                                          @"/usr/share/terminfo/A/ansi-mono",
                                                          @"/usr/share/terminfo/A/ansi+pp",
                                                          @"/usr/share/terminfo/A/ansi+idl",
                                                          @"/usr/share/terminfo/A/ansi+csr",
                                                          @"/usr/share/terminfo/A/ansi-generic",
                                                          @"/usr/share/terminfo/A/ansi+sgr",
                                                          @"/usr/share/terminfo/A/ansi+cup",
                                                          @"/usr/share/terminfo/A/ansi-emx",
                                                          @"/usr/share/terminfo/A/ansi+sgrbold",
                                                          @"/usr/share/terminfo/A/ansi+sgrul",
                                                          @"/usr/share/terminfo/A/ansi+sgrso",
                                                          @"/usr/share/terminfo/A/ansi",
                                                          @"/usr/share/terminfo/A/ansi-color-2-emx",
                                                          @"/usr/share/terminfo/A/ansi-color-3-emx",
                                                          @"/usr/share/terminfo/A/ansi-mtabs",
                                                          @"/usr/share/terminfo/A/ansi+sgrdim",
                                                          @"/usr/share/terminfo/A/apple-uterm-vb",
                                                          @"/usr/share/terminfo/A/apple-ae",
                                                          @"/usr/share/terminfo/A/ansi+erase",
                                                          @"/usr/share/terminfo/A/apple-uterm",
                                                          @"/usr/share/terminfo/A/ansi+rep",
                                                          @"/usr/share/terminfo/A/ansi+tabs",
                                                          @"/usr/share/terminfo/A/ansi+local1",
                                                          @"/usr/share/terminfo/A/ansi+rca",
                                                          @"/usr/share/terminfo/A/ansi-mini",
                                                          @"/usr/share/terminfo/A/ansi+enq",
                                                          @"/usr/share/terminfo/A/ansi-nt",
                                                          @"/usr/share/terminfo/A/ansi-mr",
                                                          @"/usr/share/terminfo/A/ansi.sys",
                                                          @"/usr/share/terminfo/A/ansi.sys-old",
                                                          @"/usr/share/terminfo/A/apple-videx",
                                                          @"/usr/share/terminfo/A/ansi.sysk",
                                                          @"/usr/share/terminfo/A/apple-80",
                                                          @"/usr/share/terminfo/A/Apple_Terminal",
                                                          @"/usr/share/terminfo/A/ansi+inittabs",
                                                          @"/usr/share/terminfo/A/ansi+local",
                                                          @"/usr/share/terminfo/A/ansi-m",
                                                          @"/usr/share/terminfo/A/ansi+arrows",
                                                          @"/usr/share/terminfo/72",
                                                          @"/usr/share/terminfo/6b",
                                                          @"/usr/share/terminfo/65",
                                                          @"/usr/share/terminfo/6d",
                                                          @"/usr/share/terminfo/6c",
                                                          @"/usr/share/terminfo/63",
                                                          @"/usr/share/terminfo/64",
                                                          @"/usr/share/terminfo/m",
                                                          @"/usr/share/terminfo/m/mach-color",
                                                          @"/usr/share/terminfo/m/mach",
                                                          @"/usr/share/terminfo/m/mach-bold",
                                                          @"/usr/share/terminfo/41",
                                                          @"/usr/share/terminfo/c",
                                                          @"/usr/share/terminfo/c/cons25-koi8r-m",
                                                          @"/usr/share/terminfo/c/cons25-m",
                                                          @"/usr/share/terminfo/c/cons25-iso-m",
                                                          @"/usr/share/terminfo/c/cons25-koi8-r",
                                                          @"/usr/share/terminfo/c/cons25-iso8859",
                                                          @"/usr/share/terminfo/c/cons25",
                                                          @"/usr/share/terminfo/c/cygwin",
                                                          @"/usr/share/terminfo/70",
                                                          @"/usr/share/terminfo/d",
                                                          @"/usr/share/terminfo/d/dumb",
                                                          @"/usr/share/terminfo/v",
                                                          @"/usr/share/terminfo/v/vt102",
                                                          @"/usr/share/terminfo/v/vt100-putty",
                                                          @"/usr/share/terminfo/v/vt100-nav-w",
                                                          @"/usr/share/terminfo/v/vt100-s",
                                                          @"/usr/share/terminfo/v/vt102-w",
                                                          @"/usr/share/terminfo/v/vt102-nsgr",
                                                          @"/usr/share/terminfo/v/vt100+",
                                                          @"/usr/share/terminfo/v/vt220+keypad",
                                                          @"/usr/share/terminfo/v/vt220",
                                                          @"/usr/share/terminfo/v/vt100-vb",
                                                          @"/usr/share/terminfo/v/vt220-nam",
                                                          @"/usr/share/terminfo/v/vt100+enq",
                                                          @"/usr/share/terminfo/v/vt220-w",
                                                          @"/usr/share/terminfo/v/vt102+enq",
                                                          @"/usr/share/terminfo/v/vt100-s-top",
                                                          @"/usr/share/terminfo/v/vt220-8bit",
                                                          @"/usr/share/terminfo/v/vt100-nam-w",
                                                          @"/usr/share/terminfo/v/vt220-js",
                                                          @"/usr/share/terminfo/v/vt100+fnkeys",
                                                          @"/usr/share/terminfo/v/vt100-w",
                                                          @"/usr/share/terminfo/v/vt52",
                                                          @"/usr/share/terminfo/v/vt100",
                                                          @"/usr/share/terminfo/v/vt100-w-nav",
                                                          @"/usr/share/terminfo/v/vt100-bot-s",
                                                          @"/usr/share/terminfo/v/vt100-w-nam",
                                                          @"/usr/share/terminfo/v/vt100+pfkeys",
                                                          @"/usr/share/terminfo/v/vt100-top-s",
                                                          @"/usr/share/terminfo/v/vt100-nav",
                                                          @"/usr/share/terminfo/v/vt100-nam",
                                                          @"/usr/share/terminfo/v/vt100-bm-o",
                                                          @"/usr/share/terminfo/v/vt220-8",
                                                          @"/usr/share/terminfo/v/vt220-old",
                                                          @"/usr/share/terminfo/v/vt100+keypad",
                                                          @"/usr/share/terminfo/v/vt100-am",
                                                          @"/usr/share/terminfo/v/vt100-s-bot",
                                                          @"/usr/share/terminfo/v/vt100-w-am",
                                                          @"/usr/share/terminfo/v/vt100-bm",
                                                          @"/usr/share/terminfo/x",
                                                          @"/usr/share/terminfo/x/xterm-256color",
                                                          @"/usr/share/terminfo/x/xterm+r6f2",
                                                          @"/usr/share/terminfo/x/xterm-color",
                                                          @"/usr/share/terminfo/x/xterm-16color",
                                                          @"/usr/share/terminfo/x/xterm-xf86-v40",
                                                          @"/usr/share/terminfo/x/xterm+88color",
                                                          @"/usr/share/terminfo/x/xterm+pce2",
                                                          @"/usr/share/terminfo/x/xterm+app",
                                                          @"/usr/share/terminfo/x/xterm-8bit",
                                                          @"/usr/share/terminfo/x/xterm-xi",
                                                          @"/usr/share/terminfo/x/xterm+pcc0",
                                                          @"/usr/share/terminfo/x/xterm+pcf2",
                                                          @"/usr/share/terminfo/x/xterm",
                                                          @"/usr/share/terminfo/x/xterm+noapp",
                                                          @"/usr/share/terminfo/x/xterm-basic",
                                                          @"/usr/share/terminfo/x/xterm+pcc1",
                                                          @"/usr/share/terminfo/x/xterm-r6",
                                                          @"/usr/share/terminfo/x/xterm-88color",
                                                          @"/usr/share/terminfo/x/xterm-xf86-v333",
                                                          @"/usr/share/terminfo/x/xterm-xfree86",
                                                          @"/usr/share/terminfo/x/xterm-vt220",
                                                          @"/usr/share/terminfo/x/xterm-hp",
                                                          @"/usr/share/terminfo/x/xterm-new",
                                                          @"/usr/share/terminfo/x/xterm-noapp",
                                                          @"/usr/share/terminfo/x/xterm+pc+edit",
                                                          @"/usr/share/terminfo/x/xterm-1003",
                                                          @"/usr/share/terminfo/x/xterm+sl-twm",
                                                          @"/usr/share/terminfo/x/xterm-pcolor",
                                                          @"/usr/share/terminfo/x/xterm-1002",
                                                          @"/usr/share/terminfo/x/xterm-sco",
                                                          @"/usr/share/terminfo/x/xterm+vt+edit",
                                                          @"/usr/share/terminfo/x/xterm-xf86-v43",
                                                          @"/usr/share/terminfo/x/xterm-xf86-v44",
                                                          @"/usr/share/terminfo/x/xterm+pcc3",
                                                          @"/usr/share/terminfo/x/xterm-24",
                                                          @"/usr/share/terminfo/x/xterm-old",
                                                          @"/usr/share/terminfo/x/xterm+pcf0",
                                                          @"/usr/share/terminfo/x/xterm+256color",
                                                          @"/usr/share/terminfo/x/xterm-r5",
                                                          @"/usr/share/terminfo/x/xterm+pcc2",
                                                          @"/usr/share/terminfo/x/xterm+pcfkeys",
                                                          @"/usr/share/terminfo/x/xterm+sl",
                                                          @"/usr/share/terminfo/x/xterm+edit",
                                                          @"/usr/share/terminfo/x/xterm-sun",
                                                          @"/usr/share/terminfo/x/xterm-bold",
                                                          @"/usr/share/terminfo/x/xterm-nic",
                                                          @"/usr/share/terminfo/x/xterm-vt52",
                                                          @"/usr/share/terminfo/x/xterm-xf86-v32",
                                                          @"/usr/share/terminfo/x/xterm-xf86-v33",
                                                          @"/usr/share/terminfo/E",
                                                          @"/usr/share/terminfo/E/Eterm-88color",
                                                          @"/usr/share/terminfo/E/eterm",
                                                          @"/usr/share/terminfo/E/Eterm-256color",
                                                          @"/usr/share/terminfo/E/Eterm-color",
                                                          @"/usr/share/terminfo/76",
                                                          @"/usr/share/terminfo/k",
                                                          @"/usr/share/terminfo/k/konsole-vt100",
                                                          @"/usr/share/terminfo/k/konsole-base",
                                                          @"/usr/share/terminfo/k/konsole-vt420pc",
                                                          @"/usr/share/terminfo/k/konsole",
                                                          @"/usr/share/terminfo/k/konsole-solaris",
                                                          @"/usr/share/terminfo/k/konsole-linux",
                                                          @"/usr/share/terminfo/k/konsole-16color",
                                                          @"/usr/share/terminfo/k/konsole+pcfkeys",
                                                          @"/usr/share/terminfo/k/konsole-xf3x",
                                                          @"/usr/share/terminfo/k/konsole-256color",
                                                          @"/usr/share/terminfo/k/konsole-xf4x",
                                                          @"/usr/share/terminfo/l",
                                                          @"/usr/share/terminfo/l/linux-lat",
                                                          @"/usr/share/terminfo/l/linux-koi8r",
                                                          @"/usr/share/terminfo/l/linux-vt",
                                                          @"/usr/share/terminfo/l/linux-basic",
                                                          @"/usr/share/terminfo/l/linux",
                                                          @"/usr/share/terminfo/l/linux-c-nc",
                                                          @"/usr/share/terminfo/l/linux-c",
                                                          @"/usr/share/terminfo/l/linux-m",
                                                          @"/usr/share/terminfo/l/linux-nic",
                                                          @"/usr/share/terminfo/l/linux-koi8",
                                                          @"/usr/share/terminfo/78",
                                                          @"/usr/share/terminfo/p",
                                                          @"/usr/share/terminfo/p/pcansi-43-m",
                                                          @"/usr/share/terminfo/p/putty-vt100",
                                                          @"/usr/share/terminfo/p/putty",
                                                          @"/usr/share/terminfo/p/pcansi-43",
                                                          @"/usr/share/terminfo/p/pcansi-33",
                                                          @"/usr/share/terminfo/p/pcansi-25-m",
                                                          @"/usr/share/terminfo/p/pcansi-m",
                                                          @"/usr/share/terminfo/p/putty-256color",
                                                          @"/usr/share/terminfo/p/pcansi-mono",
                                                          @"/usr/share/terminfo/p/pcansi",
                                                          @"/usr/share/terminfo/p/pcansi-25",
                                                          @"/usr/share/terminfo/p/pcansi-33-m",
                                                          @"/usr/share/dict",
                                                          @"/usr/share/gnupg",
                                                          @"/usr/share/gnupg/options.skel",
                                                          @"/usr/share/dpkg",
                                                          @"/usr/share/dpkg/ostable",
                                                          @"/usr/share/dpkg/triplettable",
                                                          @"/usr/share/dpkg/cputable",
                                                          @"/usr/share/dpkg/origins",
                                                          @"/usr/bin/gtar",
                                                          @"/usr/bin/dselect",
                                                          @"/usr/bin/cycc",
                                                          @"/usr/bin/dpkg-statoverride",
                                                          @"/usr/bin/dpkg-deb",
                                                          @"/usr/bin/dpkg-divert",
                                                          @"/usr/bin/cynject",
                                                          @"/usr/bin/update-alternatives",
                                                          @"/usr/bin/dpkg-split",
                                                          @"/usr/bin/uicache",
                                                          @"/usr/bin/dpkg-trigger",
                                                          @"/usr/bin/dpkg-maintscript-helper",
                                                          @"/usr/bin/env",
                                                          @"/usr/bin/gnutar",
                                                          @"/usr/bin/cycript",
                                                          @"/usr/bin/dpkg-query",
                                                          @"/usr/bin/apt",
                                                          @"/usr/bin/apt-get",
                                                          @"/usr/bin/dpkg",
                                                          @"/usr/libexec/cydia",
                                                          @"/usr/libexec/cydia/setnsfpn",
                                                          @"/usr/libexec/cydia/du",
                                                          @"/usr/libexec/cydia/cydo",
                                                          @"/usr/libexec/MSUnrestrictProcess",
                                                          @"/usr/libexec/substrate",
                                                          @"/usr/include/substrate.h",
                                                          @"/usr/include/dpkg",
                                                          @"/usr/include/dpkg/progress.h",
                                                          @"/usr/include/dpkg/error.h",
                                                          @"/usr/include/dpkg/dpkg.h",
                                                          @"/usr/include/dpkg/tarfn.h",
                                                          @"/usr/include/dpkg/varbuf.h",
                                                          @"/usr/include/dpkg/debug.h",
                                                          @"/usr/include/dpkg/version.h",
                                                          @"/usr/include/dpkg/atomic-file.h",
                                                          @"/usr/include/dpkg/namevalue.h",
                                                          @"/usr/include/dpkg/path.h",
                                                          @"/usr/include/dpkg/deb-version.h",
                                                          @"/usr/include/dpkg/pkg.h",
                                                          @"/usr/include/dpkg/file.h",
                                                          @"/usr/include/dpkg/subproc.h",
                                                          @"/usr/include/dpkg/color.h",
                                                          @"/usr/include/dpkg/trigdeferred.h",
                                                          @"/usr/include/dpkg/pkg-format.h",
                                                          @"/usr/include/dpkg/options.h",
                                                          @"/usr/include/dpkg/progname.h",
                                                          @"/usr/include/dpkg/parsedump.h",
                                                          @"/usr/include/dpkg/fdio.h",
                                                          @"/usr/include/dpkg/ehandle.h",
                                                          @"/usr/include/dpkg/buffer.h",
                                                          @"/usr/include/dpkg/macros.h",
                                                          @"/usr/include/dpkg/report.h",
                                                          @"/usr/include/dpkg/c-ctype.h",
                                                          @"/usr/include/dpkg/pkg-show.h",
                                                          @"/usr/include/dpkg/compress.h",
                                                          @"/usr/include/dpkg/pkg-array.h",
                                                          @"/usr/include/dpkg/pkg-list.h",
                                                          @"/usr/include/dpkg/triglib.h",
                                                          @"/usr/include/dpkg/pkg-spec.h",
                                                          @"/usr/include/dpkg/ar.h",
                                                          @"/usr/include/dpkg/command.h",
                                                          @"/usr/include/dpkg/program.h",
                                                          @"/usr/include/dpkg/dpkg-db.h",
                                                          @"/usr/include/dpkg/treewalk.h",
                                                          @"/usr/include/dpkg/glob.h",
                                                          @"/usr/include/dpkg/dir.h",
                                                          @"/usr/include/dpkg/pkg-queue.h",
                                                          @"/usr/include/dpkg/arch.h",
                                                          @"/usr/include/dpkg/string.h",
                                                          @"/usr/sbin/start-stop-daemon",
                                                          @"/usr/local/bin",
                                                          @"/usr/local/bin/wget",
                                                          @"/usr/local/bin/dbclient",
                                                          @"/usr/local/bin/filemon",
                                                          @"/usr/local/bin/dropbear",
                                                          @"/usr/local/bin/procexp",
                                                          @"/usr/local/bin/jtool",
                                                          @"/usr/local/bin/dropbearkey",
                                                          @"/usr/local/bin/dropbearconvert",
                                                          @"/usr/local/lib",
                                                          @"/usr/local/lib/zsh",
                                                          @"/usr/local/lib/zsh/5.0.8",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/termcap.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/zleparameter.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/example.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/tcp.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/newuser.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/deltochar.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/complete.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/mapfile.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/stat.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/compctl.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/zselect.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/parameter.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/datetime.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/socket.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/terminfo.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/clone.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/regex.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/attr.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/curses.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/files.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/system.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/zpty.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/zle.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/mathfunc.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/zutil.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/complist.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/zftp.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/cap.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/computil.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/zprof.so",
                                                          @"/usr/local/lib/zsh/5.0.8/zsh/langinfo.so",
                                                          @"/usr/lib/pkgconfig",
                                                          @"/usr/lib/pkgconfig/libdpkg.pc",
                                                          @"/usr/lib/cycript0.9",
                                                          @"/usr/lib/cycript0.9/org",
                                                          @"/usr/lib/cycript0.9/org/cycript",
                                                          @"/usr/lib/cycript0.9/org/cycript/NSLog.cy",
                                                          @"/usr/lib/cycript0.9/com",
                                                          @"/usr/lib/cycript0.9/com/saurik",
                                                          @"/usr/lib/cycript0.9/com/saurik/substrate",
                                                          @"/usr/lib/cycript0.9/com/saurik/substrate/MS.cy",
                                                          @"/usr/lib/libcycript.dylib",
                                                          @"/usr/lib/libcycript.jar",
                                                          @"/usr/lib/libapt-inst.dylib",
                                                          @"/usr/lib/libapt-pkg.dylib",
                                                          @"/usr/lib/libdpkg.a",
                                                          @"/usr/lib/libcrypto.1.0.0.dylib",
                                                          @"/usr/lib/libssl.1.0.0.dylib",
                                                          @"/usr/lib/apt/methods/gpgv",
                                                          @"/usr/lib/apt/methods/https",
                                                          @"/usr/lib/apt/methods/ftp",
                                                          @"/usr/lib/apt/methods/cdrom",
                                                          @"/usr/lib/apt/methods/file",
                                                          @"/usr/lib/apt/methods/rsh",
                                                          @"/usr/lib/apt/methods/gzip",
                                                          @"/usr/lib/apt/methods/xz",
                                                          @"/usr/lib/apt/methods/ssh",
                                                          @"/usr/lib/apt/methods/http",
                                                          @"/usr/lib/apt/methods/copy",
                                                          @"/usr/lib/apt/methods/rred",
                                                          @"/usr/lib/apt/methods/lzma",
                                                          @"/usr/lib/apt/methods/bzip2",
                                                          @"/usr/lib/apt/methods/store",
                                                          @"/usr/lib/apt/methods/mirror",
                                                          @"/usr/lib/libcycript.db",
                                                          @"/usr/lib/libcurl.4.dylib",
                                                          @"/usr/lib/libcycript.0.dylib",
                                                          @"/usr/lib/libcycript.cy",
                                                          @"/usr/lib/libsubstrate.dylib",
                                                          @"/usr/lib/libdpkg.la",
                                                          @"/usr/lib/libsubstrate.0.dylib",
                                                          @"/usr/lib/dpkg",
                                                          @"/usr/share/dpkg",
                                                          @"/usr/share/dpkg/architecture.mk",
                                                          @"/usr/share/dpkg/buildflags.mk",
                                                          @"/usr/share/dpkg/default.mk",
                                                          @"/usr/share/dpkg/ostable",
                                                          @"/usr/share/dpkg/pkg-info.mk",
                                                          @"/usr/share/dpkg/vendor.mk",
                                                          @"/usr/share/dpkg/triplettable",
                                                          @"/usr/share/dpkg/cputable",
                                                          @"/usr/share/dpkg/abitable",
                                                          @"/bin/cat",
                                                          @"/bin/launchctl",
                                                          @"/bin/pwd",
                                                          @"/bin/sed",
                                                          @"/bin/sleep",
                                                          @"/bin/stty",
                                                          @"/bin/date",
                                                          @"/bin/bzip2_64",
                                                          @"/bin/bash",
                                                          @"/bin/kill",
                                                          @"/bin/sh",
                                                          @"/bin/dd",
                                                          @"/bin/mkdir",
                                                          @"/bin/hostname",
                                                          @"/bin/rmdir",
                                                          @"/bin/mv",
                                                          @"/bin/ln",
                                                          @"/bin/ls",
                                                          @"/bin/cp",
                                                          @"/bin/chown",
                                                          @"/bin/zsh",
                                                          @"/bin/chmod",
                                                          @"/bin/rm",
                                                          @"/bin/bzip2",
                                                          @"/etc/zshrc",
                                                          @"/etc/dropbear",
                                                          @"/etc/profile",
                                                          @"/etc/alternatives",
                                                          @"/etc/alternatives/README",
                                                          @"/etc/dpkg",
                                                          @"/etc/dpkg/dselect.cfg.d",
                                                          @"/etc/dpkg/dpkg.cfg.d",
                                                          @"/var/lib/dpkg",
                                                          @"/var/lib/dpkg/updates",
                                                          @"/var/lib/dpkg/info",
                                                          @"/var/lib/dpkg/parts",
                                                          @"/var/lib/dpkg/alternatives",
                                                          @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                                                          @"/Library/MobileSubstrate/DynamicLibraries/NoPlaceLikeHome.dylib",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/Libraries",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/Libraries/SubstrateLauncher.dylib",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/Libraries/SubstrateBootstrap.dylib",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/Libraries/SubstrateLoader.dylib",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/Libraries/SubstrateInjection.dylib",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/Headers",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/Headers/CydiaSubstrate.h",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/Commands",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/Commands/cycc",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/Commands/cynject",
                                                          @"/Library/Frameworks/CydiaSubstrate.framework/Info.plist",
                                                          @"/Library/test_inject_springboard.cy",
                                                          @"/Applications/Cydia.app/installing@2x.png",
                                                          @"/Applications/Cydia.app/iOS7-Default-736h-Portrait@3x.png",
                                                          @"/Applications/Cydia.app/install@2x.png",
                                                          @"/Applications/Cydia.app/folder@2x.png",
                                                          @"/Applications/Cydia.app/install7s@3x.png",
                                                          @"/Applications/Cydia.app/Icon7-Small@2x.png",
                                                          @"/Applications/Cydia.app/Cydia",
                                                          @"/Applications/Cydia.app/search@2x.png",
                                                          @"/Applications/Cydia.app/home-Selected.png",
                                                          @"/Applications/Cydia.app/icon.png",
                                                          @"/Applications/Cydia.app/Sections",
                                                          @"/Applications/Cydia.app/Sections/Terminal_Support.png",
                                                          @"/Applications/Cydia.app/Sections/Addons.png",
                                                          @"/Applications/Cydia.app/Sections/Widgets.png",
                                                          @"/Applications/Cydia.app/Sections/Carrier_Bundles.png",
                                                          @"/Applications/Cydia.app/Sections/Administration.png",
                                                          @"/Applications/Cydia.app/Sections/Data_Storage.png",
                                                          @"/Applications/Cydia.app/Sections/Messaging.png",
                                                          @"/Applications/Cydia.app/Sections/Wallpaper.png",
                                                          @"/Applications/Cydia.app/Sections/Themes.png",
                                                          @"/Applications/Cydia.app/Sections/Networking.png",
                                                          @"/Applications/Cydia.app/Sections/Ringtones.png",
                                                          @"/Applications/Cydia.app/Sections/Toys.png",
                                                          @"/Applications/Cydia.app/Sections/Games.png",
                                                          @"/Applications/Cydia.app/Sections/Books.png",
                                                          @"/Applications/Cydia.app/Sections/Multimedia.png",
                                                          @"/Applications/Cydia.app/Sections/Tweaks.png",
                                                          @"/Applications/Cydia.app/Sections/Archiving.png",
                                                          @"/Applications/Cydia.app/Sections/Java.png",
                                                          @"/Applications/Cydia.app/Sections/Keyboards.png",
                                                          @"/Applications/Cydia.app/Sections/Entertainment.png",
                                                          @"/Applications/Cydia.app/Sections/System.png",
                                                          @"/Applications/Cydia.app/Sections/Localization.png",
                                                          @"/Applications/Cydia.app/Sections/X_Window.png",
                                                          @"/Applications/Cydia.app/Sections/Text_Editors.png",
                                                          @"/Applications/Cydia.app/Sections/Fonts.png",
                                                          @"/Applications/Cydia.app/Sections/Utilities.png",
                                                          @"/Applications/Cydia.app/Sections/Productivity.png",
                                                          @"/Applications/Cydia.app/Sections/Development.png",
                                                          @"/Applications/Cydia.app/Sections/Dictionaries.png",
                                                          @"/Applications/Cydia.app/Sections/Education.png",
                                                          @"/Applications/Cydia.app/Sections/Packaging.png",
                                                          @"/Applications/Cydia.app/Sections/Site-Specific_Apps.png",
                                                          @"/Applications/Cydia.app/Sections/Health_and_Fitness.png",
                                                          @"/Applications/Cydia.app/Sections/Security.png",
                                                          @"/Applications/Cydia.app/Sections/Soundboards.png",
                                                          @"/Applications/Cydia.app/Sections/Scripting.png",
                                                          @"/Applications/Cydia.app/Sections/Planet-iPhones Mods.png",
                                                          @"/Applications/Cydia.app/Sections/Navigation.png",
                                                          @"/Applications/Cydia.app/Sections/Social.png",
                                                          @"/Applications/Cydia.app/Sections/Repositories.png",
                                                          @"/Applications/Cydia.app/home@2x.png",
                                                          @"/Applications/Cydia.app/Default-Portrait@2x.png",
                                                          @"/Applications/Cydia.app/search7.png",
                                                          @"/Applications/Cydia.app/search7@3x.png",
                                                          @"/Applications/Cydia.app/home7@2x.png",
                                                          @"/Applications/Cydia.app/home7@3x.png",
                                                          @"/Applications/Cydia.app/search7@2x.png",
                                                          @"/Applications/Cydia.app/install.png",
                                                          @"/Applications/Cydia.app/compose.png",
                                                          @"/Applications/Cydia.app/iOS7-Default-Portrait@2x.png",
                                                          @"/Applications/Cydia.app/installing.png",
                                                          @"/Applications/Cydia.app/iconClassic.png",
                                                          @"/Applications/Cydia.app/changes7s.png",
                                                          @"/Applications/Cydia.app/Icon7-Small@3x.png",
                                                          @"/Applications/Cydia.app/Default-Landscape@2x.png",
                                                          @"/Applications/Cydia.app/install7s@2x.png",
                                                          @"/Applications/Cydia.app/iOS7-Default-Portrait.png",
                                                          @"/Applications/Cydia.app/Icon-Small.png",
                                                          @"/Applications/Cydia.app/Default-Portrait.png",
                                                          @"/Applications/Cydia.app/home7s.png",
                                                          @"/Applications/Cydia.app/search7s@3x.png",
                                                          @"/Applications/Cydia.app/Icon-60@3x.png",
                                                          @"/Applications/Cydia.app/removing.png",
                                                          @"/Applications/Cydia.app/Default@2x.png",
                                                          @"/Applications/Cydia.app/changes7@3x.png",
                                                          @"/Applications/Cydia.app/iOS7-Default-Landscape@2x.png",
                                                          @"/Applications/Cydia.app/removing@2x.png",
                                                          @"/Applications/Cydia.app/Sections.plist",
                                                          @"/Applications/Cydia.app/Icon-60.png",
                                                          @"/Applications/Cydia.app/home7s@2x.png",
                                                          @"/Applications/Cydia.app/uicache",
                                                          @"/Applications/Cydia.app/unknown.png",
                                                          @"/Applications/Cydia.app/home-Selected@2x.png",
                                                          @"/Applications/Cydia.app/Icon-Small-40@2x.png",
                                                          @"/Applications/Cydia.app/home.png",
                                                          @"/Applications/Cydia.app/Icon-76@2x~ipad.png",
                                                          @"/Applications/Cydia.app/home7s@3x.png",
                                                          @"/Applications/Cydia.app/Icon-Small-50@2x.png",
                                                          @"/Applications/Cydia.app/menes",
                                                          @"/Applications/Cydia.app/menes/menes.js",
                                                          @"/Applications/Cydia.app/install7s.png",
                                                          @"/Applications/Cydia.app/icon-72.png",
                                                          @"/Applications/Cydia.app/Default-Landscape.png",
                                                          @"/Applications/Cydia.app/changes7@2x.png",
                                                          @"/Applications/Cydia.app/icon-72@2x.png",
                                                          @"/Applications/Cydia.app/Icon-60@2x.png",
                                                          @"/Applications/Cydia.app/search7s@2x.png",
                                                          @"/Applications/Cydia.app/search.png",
                                                          @"/Applications/Cydia.app/manage.png",
                                                          @"/Applications/Cydia.app/icon@2x.png",
                                                          @"/Applications/Cydia.app/configure.png",
                                                          @"/Applications/Cydia.app/folder.png",
                                                          @"/Applications/Cydia.app/iOS7-Default-667h@2x.png",
                                                          @"/Applications/Cydia.app/Icon-76~ipad.png",
                                                          @"/Applications/Cydia.app/changes7s@2x.png",
                                                          @"/Applications/Cydia.app/Default-568h@2x.png",
                                                          @"/Applications/Cydia.app/Assets.car",
                                                          @"/Applications/Cydia.app/manage7s@3x.png",
                                                          @"/Applications/Cydia.app/Purposes",
                                                          @"/Applications/Cydia.app/Purposes/x.png",
                                                          @"/Applications/Cydia.app/Purposes/daemon.png",
                                                          @"/Applications/Cydia.app/Purposes/library.png",
                                                          @"/Applications/Cydia.app/Purposes/commercial.png",
                                                          @"/Applications/Cydia.app/Purposes/console.png",
                                                          @"/Applications/Cydia.app/Purposes/uikit.png",
                                                          @"/Applications/Cydia.app/Purposes/extension.png",
                                                          @"/Applications/Cydia.app/manage7.png",
                                                          @"/Applications/Cydia.app/changes@2x.png",
                                                          @"/Applications/Cydia.app/manage7s@2x.png",
                                                          @"/Applications/Cydia.app/changes7s@3x.png",
                                                          @"/Applications/Cydia.app/search7s.png",
                                                          @"/Applications/Cydia.app/manage7s.png",
                                                          @"/Applications/Cydia.app/manage@2x.png",
                                                          @"/Applications/Cydia.app/chevron@2x.png",
                                                          @"/Applications/Cydia.app/Sources",
                                                          @"/Applications/Cydia.app/Sources/apt.bigboss.us.com.png",
                                                          @"/Applications/Cydia.app/installed.png",
                                                          @"/Applications/Cydia.app/changes.png",
                                                          @"/Applications/Cydia.app/iOS7-Default-736h-Landscape@3x.png",
                                                          @"/Applications/Cydia.app/Icon-Small-50.png",
                                                          @"/Applications/Cydia.app/install7.png",
                                                          @"/Applications/Cydia.app/install7@3x.png",
                                                          @"/Applications/Cydia.app/manage7@3x.png",
                                                          @"/Applications/Cydia.app/manage7@2x.png",
                                                          @"/Applications/Cydia.app/install7@2x.png",
                                                          @"/Applications/Cydia.app/Default.png",
                                                          @"/Applications/Cydia.app/iOS7-Default-Landscape.png",
                                                          @"/Applications/Cydia.app/changes7.png",
                                                          @"/Applications/Cydia.app/error.html",
                                                          @"/Applications/Cydia.app/iOS7-Default@2x.png",
                                                          @"/Applications/Cydia.app/Icon7-Small.png",
                                                          @"/Applications/Cydia.app/Icon-Small-40.png",
                                                          @"/Applications/Cydia.app/localize.js",
                                                          @"/Applications/Cydia.app/Icon-Small@2x.png",
                                                          @"/Applications/Cydia.app/installed@2x.png",
                                                          @"/Applications/Cydia.app/reload.png",
                                                          @"/Applications/Cydia.app/store",
                                                          @"/Applications/Cydia.app/iOS7-Default-568h@2x.png",
                                                          @"/Applications/Cydia.app/home7.png",
                                                          @"/usr/local/lib/libluajit.a",
                                                          @"/var/tweak/com.r333d.jjjj",
                                                          @"/var/tweak/com.r333d.jjjj/lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ui",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ui/textbox.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ui/filtertable.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ui/searchbar.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ui/cell.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ui/scroll.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ui/table.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ui/gesture.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ui/button.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/init.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/page",
                                                          @"/var/tweak/com.r333d.jjjj/lua/page/repos.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/page/installed.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/page/browse.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/res",
                                                          @"/var/tweak/com.r333d.jjjj/lua/res/globe.png",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ns",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ns/websocket.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ns/http.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/ns/target.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/main.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/depiction.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/objc.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/screenshot.png",
                                                          @"/var/tweak/com.r333d.jjjj/lua/deb.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/config.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/constants.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/README.md",
                                                          @"/var/tweak/com.r333d.jjjj/lua/object.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/util.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/repo.lua",
                                                          @"/var/tweak/com.r333d.jjjj/lua/cdef",
                                                          @"/var/tweak/com.r333d.jjjj/lua/cdef/init.lua",
                                                          @"/Applications/jjjj.app",
                                                          @"/Applications/jjjj.app/iOS7-Default-736h-Portrait@3x.png",
                                                          @"/Applications/jjjj.app/entitlements.xml",
                                                          @"/Applications/jjjj.app/jjjj.exe",
                                                          @"/Applications/jjjj.app/iOS7-Default-Portrait@2x.png",
                                                          @"/Applications/jjjj.app/iOS7-Default-Portrait.png",
                                                          @"/Applications/jjjj.app/iOS7-Default-Landscape@2x.png",
                                                          @"/Applications/jjjj.app/Icon@2x.png",
                                                          @"/Applications/jjjj.app/iOS7-Default-667h@2x.png",
                                                          @"/Applications/jjjj.app/iOS7-Default-736h-Landscape@3x.png",
                                                          @"/Applications/jjjj.app/iOS7-Default-Landscape.png",
                                                          @"/Applications/jjjj.app/iOS7-Default@2x.png",
                                                          @"/Applications/jjjj.app/Info.plist",
                                                          @"/Applications/jjjj.app/setuid",
                                                          @"/Applications/jjjj.app/iOS7-Default-568h@2x.png",
                                                          nil];


    for (NSString *file_name in bootstrap_files_list) {
        
        if([[NSFileManager defaultManager] fileExistsAtPath:file_name]) {
            
            // if the return value is -1, it's most likely a directory. We don't want to remove dirs
            printf("removing: %s. status: %d\n", [file_name UTF8String], remove([file_name UTF8String]));
        }
    }

    setuid(501);
    return KERN_SUCCESS;
}

/*
 *  Purpose: unpacks bootstrap (Cydia and binaries)
 */
kern_return_t unpack_bootstrap() {
    

    
    kern_return_t ret = KERN_SUCCESS;

    char path[4096];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    char *pt = realpath(path, NULL);
    
    NSString *execpath = [[NSString stringWithUTF8String:pt] stringByDeletingLastPathComponent];

    NSString *bootstrap_path = [execpath stringByAppendingPathComponent:@"bootstrap.tar"];
    NSString *bootstrap_2_path = [execpath stringByAppendingPathComponent:@"bootstrap_2.tar"];
    
    BOOL should_install_jjjj = !([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/jjjj.app"]);
    if(should_install_jjjj != YES) {

        chdir("/");
        FILE *bootstrap = fopen([bootstrap_path UTF8String], "r");
        untar(bootstrap, "/");
        fclose(bootstrap);

        // temp (install latest Cydia)
        chdir("/");
        FILE *bootstrap_2 = fopen([bootstrap_2_path UTF8String], "r");
        untar(bootstrap_2, "/");
        fclose(bootstrap_2);

        
        pid_t cfprefsd_pid = get_pid_for_name("cfprefsd", false);
        kill(cfprefsd_pid, SIGSTOP);
        
        // Show hidden apps
        NSMutableDictionary* md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
        [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
        [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];

        // NO to Cydia stashing
        open("/.cydia_no_stash", O_RDWR | O_CREAT);

        chmod("/private", 0777);
        chmod("/private/var", 0777);
        chmod("/private/var/tmp", 0777);
        chmod("/private/var/mobile", 0777);
        chmod("/private/var/mobile/Library", 0777);
        chmod("/private/var/mobile/Library/Caches/", 0777);
        chmod("/private/var/mobile/Library/Preferences", 0777);
        

        printf("[INFO]: killing backboardd\n");
        kill(cfprefsd_pid, SIGKILL);
        
        unlink("/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist");
    }

    printf("[INFO]: finished installing bootstrap and friends\n");

    
    // "fix" containermanagerd
    containermanagerd_proc = get_proc_for_pid(get_pid_for_name("containermanager", false), false);
    
    if(containermanagerd_proc == -1) {
        printf("[ERROR]: no containermanagerd. wut\n");
        ret = KERN_FAILURE;
        return ret;
    }
    
    printf("[INFO]: got containermanagerd's proc: %llx\n", containermanagerd_proc);
    
    // fix containermanagerd
    contaienrmanagerd_cred = kread_uint64(containermanagerd_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    printf("[INFO]: got containermanagerd's ucred: %llx\n", contaienrmanagerd_cred);

    extern uint64_t kernel_task;
    kern_ucred = kread_uint64(kernel_task + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    kwrite_uint64(containermanagerd_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, kern_ucred);
    
    trust_cache = find_trustcache();
    amficache = find_amficache();
    
    printf("trust_cache = 0x%llx\n", trust_cache);
    printf("amficache = 0x%llx\n", amficache);
    
    extern mach_port_t tfp0;
    mem.next = kread_uint64(trust_cache);
    *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;
    
    
    // jjjj
    {
        
        NSString *jjjj_path = [execpath stringByAppendingPathComponent:@"jjjj.tar"];
        chdir("/");
        FILE *jjjj_2 = fopen([jjjj_path UTF8String], "r");
        untar(jjjj_2, "/");
        fclose(jjjj_2);
        
        // run uicache
        ret = run_path("/usr/bin/uicache", (char **)&(const char*[]){"/usr/bin/uicache", NULL}, true);
    }

    printf("[INFO]: grabbing hashes..\n");
    int rv = grab_hashes("/Applications/jjjj.app", kread, amficache, mem.next);
    rv = grab_hashes("/Library", kread, amficache, mem.next);
    //rv = grab_hashes("/System", kread, amficache, mem.next); // takes a while..
    rv = grab_hashes("/bin", kread, amficache, mem.next);
    rv = grab_hashes("/usr", kread, amficache, mem.next);
    rv = grab_hashes("/usr/lib", kread, amficache, mem.next);
    rv = grab_hashes("/usr/lib/apt", kread, amficache, mem.next);
    rv = grab_hashes("/usr/lib/apt/methods", kread, amficache, mem.next);
    rv = grab_hashes("/usr/libexec/cydia", kread, amficache, mem.next);
    rv = grab_hashes("/usr/local/lib/", kread, amficache, mem.next);
    
    printf("rv = %d, numhash = %d\n", rv, numhash);
    
    trust_path(NULL);
    
    if(should_install_jjjj == YES) {
        // run uicache
        ret = run_path("/usr/bin/uicache", (char **)&(const char*[]){"/usr/bin/uicache", NULL}, true);
    }

    
    
//    ret = run_path("/usr/bin/cycript", (char **)&(const char*[]){"/usr/bin/cycript", "-p", [[NSString stringWithFormat:@"%d", get_pid_for_name("SpringBoard")] UTF8String], "/Library/test_inject_springboard.cy", NULL}, true);

//    ret = run_path("/usr/lib/apt/methods/http", (char **)&(const char*[]){"/usr/lib/apt/methods/http", NULL}, true);exit(0);/Volumes/empty/FUCKING64/apt7-lib/apt_1/build/include
    
//    ret = run_path("dpkg-deb", (char **)&(const char*[]){"dpkg-deb", NULL}, true);
//    ret = run_path("/usr/bin/env", (char **)&(const char*[]){"/usr/bin/env", NULL}, true);
//    ret = run_path("/usr/lib/apt/methods/https", (char **)&(const char*[]){"/usr/lib/apt/methods/https", NULL}, true);exit(0);
    
    // TODO: move to a separate thread (or maybe jailbreakd)?
    ret = run_path("/usr/local/bin/dropbear", (char **)&(const char*[]){
        "/usr/local/bin/dropbear",
        "-F", /* Don't fork into background */
        "-E", /* Log to standard error rather than syslog */
        "-m", /* No message of the day */
        "-R", /* Create hostkeys as required */
        "-p", /* Listen on specified address and TCP port */
        "2222", /* Just like Yalu/Saïgon */
        NULL}, false /* this is a daemon, we don't need to wait */);
    
    
    // alternative to launchctl (thanks to @xerub)
//    {
//        for (NSString *dir_path in [[NSArray alloc] initWithObjects:@"/Library/LaunchDaemons",
//                                                                    @"/System/Library/LaunchDaemons",
//                                                                    @"/System/Library/NanoLaunchDaemons", nil]) {
//            for (NSString *daemon in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir_path error:nil]) {
//
//                NSString *full_path = [dir_path stringByAppendingPathComponent:daemon];
//                printf("[INFO]: attempting to load: %s\n", [full_path UTF8String]);
//
//                ret = run_path(pt, (char **)&(const char*[]){pt, "launchctl", [full_path UTF8String], NULL}, true);
//            }
//        }
//    }
    
    // we probably don't want to do this for now..
    if (containermanagerd_proc) {
        kwrite_uint64(containermanagerd_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, contaienrmanagerd_cred);
        printf("[INFO]: gave containermanager its original creds\n");
    }

    
    // keep this if you want to close to.panga
    set_cred_back();
    
    return ret;
}

/*
 *  Purpose: injects csflags
 */
kern_return_t empower_proc(uint64_t proc) {
    
    uint32_t csflags = kread_uint32(proc  + 0x2a8 /* csflags */);
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
    kwrite_uint32(proc  + 0x2a8 /* csflags */, csflags);
    
    return KERN_SUCCESS;
}

/*
 *  Purpose: write the ucreds
 */
kern_return_t set_creds(uint64_t proc) {
    
    // kernel creds too :)
    kwrite_uint64(proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, kern_ucred);
    
    return KERN_SUCCESS;
}

kern_return_t trust_path(char const *path) {
    
    kern_return_t ret = KERN_SUCCESS;
    extern mach_port_t tfp0;
    
#define USE_LIBJB
#ifdef USE_LIBJB
    

    size_t length = (sizeof(mem) + numhash * 20 + 0xFFFF) & ~0xFFFF;
    
    if(kernel_trust == 0) {
        ret = mach_vm_allocate(tfp0, (mach_vm_address_t *)&kernel_trust, length, VM_FLAGS_ANYWHERE);
        if(ret != KERN_SUCCESS) {
            printf("[ERROR]: failed to allocate memory\n");
            exit(0);
        }
    }
    printf("[INFO]: alloced: 0x%zx => 0x%llx\n", length, kernel_trust);
    
    mem.count = numhash;
    kwrite(kernel_trust, &mem, sizeof(mem));
    kwrite(kernel_trust + sizeof(mem), allhash, numhash * 20);
    kwrite_uint64(trust_cache, kernel_trust);
    printf("[INFO]: wrote trust cache\n");
    
#else
    
    struct topanga_trust_mem topanga_mem;
    topanga_mem.next = kread_uint64(trust_cache);
    *(uint64_t *)&topanga_mem.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&topanga_mem.uuid[8] = 0xabadbabeabadbabe;
    
    uint8_t *amfi_hash = amfi_grab_hashes(path);
    memmove(topanga_mem.hash[0], amfi_hash, 20);
    topanga_mem.count += 1;
    
    if(kernel_task == 0) {
        ret = mach_vm_allocate(tfp0, (mach_vm_address_t *)&kernel_trust, sizeof(topanga_mem), VM_FLAGS_ANYWHERE);
        if(ret != KERN_SUCCESS) {
            printf("[ERROR]: failed to allocate memory\n");
            exit(0);
        }
    }
    

    kwrite(kernel_trust, &topanga_mem, sizeof(topanga_mem));
    kwrite_uint64(trust_cache, kernel_trust);
    printf("[INFO]: wrote trust cache\n");
    sleep(1);
    
#endif
    
    return ret;
}

kern_return_t run_path(const char *path, char *const __argv[ __restrict], boolean_t wait_for_pid) {
    
    kern_return_t ret = KERN_SUCCESS;
    extern mach_port_t tfp0;
    
    // mark as executable
    chmod(path, 0755);
    
    printf("[INFO]: requested to spawn: %s\n", path);
    
    pid_t pd;
    
    int err;
    posix_spawn_file_actions_t child_fd_actions;
    if ((err = posix_spawn_file_actions_init (&child_fd_actions)))
        (void)(perror ("posix_spawn_file_actions_init")), exit(ret);
    
    printf("[INFO]: done: posix_spawn_file_actions_init\n");
    if ((err = posix_spawn_file_actions_addopen (&child_fd_actions, 1, "/var/mobile/run_path_logs",
                                                 O_WRONLY | O_CREAT | O_TRUNC, 0644)))
        (void)(perror ("posix_spawn_file_actions_addopen")), exit(ret);
    
    printf("[INFO]: done: posix_spawn_file_actions_addopen\n");
    if ((err = posix_spawn_file_actions_adddup2 (&child_fd_actions, 1, 2)))
        (void)(perror ("posix_spawn_file_actions_adddup2")), exit(ret);
    printf("[INFO]: done: posix_spawn_file_actions_adddup2\n");
    
    if((err = posix_spawn(&pd, path, &child_fd_actions, NULL, __argv, NULL))) {
        printf("[ERROR]: posix spawn error: %d\n", err);
    }
    
    printf("[INFO]: %s's pid: %d\n", path, pd);
    uint64_t proc = get_proc_for_pid(pd, true);
    
    printf("[INFO]: proc: %llx\n", proc);
    
    if(proc == 0xffffffffffffffff) {
        ret = KERN_FAILURE;
        return ret;
    }

//    uint32_t csflags = kread_uint32(proc  + 0x2a8 /* csflags */);
//    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
//    kwrite_uint32(proc  + 0x2a8 /* csflags */, csflags);
//
//    printf("[INFO]: adding 'task_for_pid-allow' entitlement to: %s\n", path);
//    entitle_proc(proc, TASK_FOR_PID_ENT);
//
    
    printf("[INFO]: empowered!\n");
    
    if(wait_for_pid)
        waitpid(pd, NULL, 0);
    
    NSString *fileContents = [NSString stringWithContentsOfFile:@"/var/mobile/run_path_logs" encoding:NSUTF8StringEncoding error:nil];
    printf("[INFO]: contents of file: %s\n", strdup([fileContents UTF8String]));
    
    return ret;
}

/*
 *  Purpose: adds (for now, overwrites) a given entitlement to a process
 *  TODO: imrpove this (boolean, lists, etc..)
 */
kern_return_t entitle_proc(uint64_t proc, char *entitlement) {
    
    kern_return_t ret = KERN_SUCCESS;
 
    uint64_t proc_cred = kread_uint64(proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    
    uint64_t proc_mac_policy_list = kread_uint64(kread_uint64(proc_cred + sandbox_original[0]) + sandbox_original[1]);
    printf("[INFO]: proc's policy list: %016llx\n", proc_mac_policy_list);
    
    uint64_t proc_policy = kread_uint64(proc_mac_policy_list + sandbox_original[3]);
    printf("[INFO]: item buffer: %016llx\n", proc_policy);
    
    int max = kread_uint32(proc_mac_policy_list + sandbox_original[2]);
    printf("[INFO]: max: %u\n", max);
    
    char* policy_str = (char*) malloc(CHAR_MAX);
    uint64_t policy_str_address = kread_uint64(kread_uint64(proc_policy) + 0x10);
    kread(policy_str_address, policy_str, CHAR_MAX);
    printf("[INFO] old entitlement(length: %lu): %s\n", strlen(policy_str), policy_str);
    
    
    // TODO: DO SOMETHING BETTER THAN THIS
    // we're overwriting existing ents atm.. BAD
    uint64_t new_str = kalloc_uint64(strlen(entitlement));
    kwrite(new_str, entitlement, strlen(entitlement));
    
    kwrite_uint64(kread_uint64(proc_policy) + 0x10, new_str);
    
    bzero(policy_str, CHAR_MAX);
    kread(kread_uint64(kread_uint64(proc_policy) + 0x10), policy_str, CHAR_MAX);
    printf("[INFO] new entitlement(length: %lu): %s\n", strlen(policy_str), policy_str);
    
    kwrite_uint64(kread_uint64(kern_ucred + 0x78) + 0x8, proc_mac_policy_list);
    
    return ret;
}

/*
 
trust cache (iOS 10.x/iPad Air):
 
(0): search for string 'amfi_prevent_old_entitled_platform'
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CD8 loc_FFFFFFF0064F8CD8                    ; CODE XREF: sub_FFFFFFF0064F8ADC+1D8↑j
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CD8                 ADRP            X0, #aAmfiPreventOld@PAGE ; "amfi_prevent_old_entitled_platform_bina"...
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CDC (1)             ADD             X0, X0, #aAmfiPreventOld@PAGEOFF ; "amfi_prevent_old_entitled_platform_bina"...
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CE0                 MOV             W2, #4
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CE4                 ADD             X1, SP, #0x50+var_34
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CE8                 BL              sub_FFFFFFF0064FAA60
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CEC (2)             CBZ             W0, loc_FFFFFFF0064F8D00 (3)
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CF0                 LDR             W8, [SP,#0x50+var_34]
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CF4                 CBZ             W8, loc_FFFFFFF0064F8D00
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CF8                 MOV             W8, #1
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CFC                 STRB            W8

com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8D00 loc_FFFFFFF0064F8D00 (3)                    ; CODE XREF: sub_FFFFFFF0064F8ADC+A0↑j
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8D00                                 ; sub_FFFFFFF0064F8ADC+210↑j ...
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8D00                 BL              sub_FFFFFFF0064F6508 (4)
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8D04                 BL              sub_FFFFFFF0064FAA00

com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508 sub_FFFFFFF0064F6508 (4)                  ; CODE XREF: sub_FFFFFFF0064F8ADC:loc_FFFFFFF0064F8D00↓p
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508 var_s0          =  0
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508                 STP             X29, X30, [SP,#-0x10+var_s0]!
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F650C                 MOV             X29, SP
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6510                 ADRP            X8, #qword_FFFFFFF00761B328@PAGE (5) the address of the QWORD is trust cache
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6514                 STR             XZR, [X8,#qword_FFFFFFF00761B328@PAGEOFF]
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6518                 BL              sub_FFFFFFF0064FAA00
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F651C                 ADRP            X8, #qword_FFFFFFF00761B320@PAGE
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6520                 STR             X0, [X8,#qword_FFFFFFF00761B320@PAGEOFF]
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6524                 LDP             X29, X30, [SP+var_s0],#0x10
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6528                 RET
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6528 ; End of function sub_FFFFFFF0064F6508
 
 
 
trust cache (iOS 11.x / iPhone X):
 
(0): com.apple.driver.AppleMobileFileIntegrity:__bss there will be a list of qwords
(1): check the ref(s) to each one (choose the first ref ADRP)
(2): if the func is like this then and your QWORD is the first one in the func then it's the correct one!

com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508 sub_FFFFFFF0064F6508                    ; CODE XREF: sub_FFFFFFF0064F8ADC:loc_FFFFFFF0064F8D00↓p
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508 var_s0          =  0
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508                 STP             X29, X30, [SP,#-0x10+var_s0]!
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F650C                 MOV             X29, SP
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6510                 ADRP            X8, #qword_FFFFFFF00761B328@PAGE <-----
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6514                 STR             XZR, [X8,#qword_FFFFFFF00761B328@PAGEOFF]
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6518                 BL              sub_FFFFFFF0064FAA00
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F651C                 ADRP            X8, #qword_FFFFFFF00761B320@PAGE
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6520                 STR             X0, [X8,#qword_FFFFFFF00761B320@PAGEOFF]
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6524                 LDP             X29, X30, [SP+var_s0],#0x10
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6528                 RET
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6528 ; End of function sub_FFFFFFF0064F6508
 
 */


