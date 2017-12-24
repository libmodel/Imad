#import <UIKit/UIKit.h>
#import "AppDelegate.h"

#include "libjb.h"

int main(int argc, char * argv[]) {
    
    
    
    // TODO: move to a separate binary, I guess..
    if (argc > 2 && !strcmp(argv[1], "launchctl")) {
        printf("wait...\n");
        sleep(3);
//        int launchctl_load_cmd(const char *filename, int do_load, int opt_force, int opt_write);
        int rv = launchctl_load_cmd(argv[2], 1, 0, 0);
        printf("subrv = %d\n", rv);
        return rv;
    }
    
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
