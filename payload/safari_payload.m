#import <UIKit/UIKit.h>

__attribute__((constructor))
void load() {
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"pwn" message:nil preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
        exit(0);
    }];
    [alert addAction:defaultAction];
    [[[[UIApplication sharedApplication] keyWindow] rootViewController] presentViewController:alert animated:YES completion:nil];
}
