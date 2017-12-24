#import "ViewController.h"
#include <stdio.h>
#include <sys/sysctl.h>

#include "async_wake.h"
#include "patchfinder64_11.h"
#include "symbols.h"
#include "jailbreak.h"

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UILabel *deviceModelLabel;
@property (weak, nonatomic) IBOutlet UIImageView *jjjjImage;

@property (weak, nonatomic) IBOutlet UIButton *jailbreakButton;

@end

@implementation ViewController

- (void)addGradient {
    
    UIView *view = [[UIView alloc] initWithFrame:CGRectMake(0, 0, self.view.frame.size.width, self.view.frame.size.height)];
    CAGradientLayer *gradient = [CAGradientLayer layer];
    
    gradient.frame = view.bounds;
    
    gradient.colors = @[(id)[UIColor colorWithRed:0 green:0 blue:0 alpha:1.0].CGColor, (id)[UIColor colorWithRed:0.20 green:0.09 blue:0.31 alpha:1.0].CGColor];
    
    [view.layer insertSublayer:gradient atIndex:0];
    [self.view insertSubview:view atIndex:0];
    
}

kern_return_t ret = KERN_SUCCESS;

- (void) kill_backboardd {
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        
        pid_t backboardd_pid = get_pid_for_name("backboardd", false);
        printf("[INFO]: killing backboardd\n");
        kill(backboardd_pid, SIGKILL);
    });
    
}

- (void) show_post_jailbreak {
    
    
    [UIView animateWithDuration:0.3 animations:^() {
        self.jjjjImage.alpha = 0;
    }];
    [self.jailbreakButton setTitle:@"finished" forState:UIControlStateNormal];
    
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        
        printf("[INFO]: calling post_jailbreak..\n");

        dispatch_async(dispatch_get_main_queue(), ^{
           
            extern void start_jailbreakd(void);
            start_jailbreakd();
//            [self kill_backboardd];
        });
    });
    
}

- (void) show_unpack_bootstrap {

    [UIView animateWithDuration:0.3 animations:^() {
        self.jjjjImage.alpha = 0.6;
    }];
    [self.jailbreakButton setTitle:@"installing jjjj.." forState:UIControlStateNormal];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        
        unpack_bootstrap();
        
        dispatch_async(dispatch_get_main_queue(), ^{
            
            [self show_post_jailbreak];
        });
        
    });
    
}

- (IBAction)jailbreak_tapped:(id)sender {
    
    [self.jailbreakButton setBackgroundColor:[UIColor clearColor]];
    [self.jailbreakButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [self.jailbreakButton setTitle:@"jailbreaking.." forState:UIControlStateNormal];
    self.jailbreakButton.titleLabel.font = [UIFont systemFontOfSize:20];
    [self.jailbreakButton setEnabled:NO];
    
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^(void){
        
        ret = go();
        
        dispatch_async(dispatch_get_main_queue(), ^{
            
            if(ret != KERN_SUCCESS) {
                [self.jailbreakButton setTitle:@"failed. reboot" forState:UIControlStateNormal];
                return;
                
            }
            
            [self show_unpack_bootstrap];
            
            
        });
    });
    
}


- (void)viewDidLoad {
    [super viewDidLoad];
    [self addGradient];
    
    
    
//    NSMutableArray *axx = [[NSMutableArray alloc] init];
//    pid_t axx_pid = 572;
//    [axx addObject:@(axx_pid)];
//    
//    for(int i =0; i<[axx count]; i++) {
//        
//        pid_t processed_pid = (pid_t) [[axx objectAtIndex:i] intValue];
//        printf("pid: %d\n\n", processed_pid);
//    }
//    
// 
//    return;
    size_t len = 0;
    char *model = malloc(len * sizeof(char));
    sysctlbyname("hw.model", NULL, &len, NULL, 0);
    if (len) {
        sysctlbyname("hw.model", model, &len, NULL, 0);
        printf("[INFO]: model internal name: %s\n", model);
    }
    
    [self.deviceModelLabel setText:[NSString stringWithFormat:@"%s", model]];
    
    
}


@end
