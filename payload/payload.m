#import <UIKit/UIKit.h>
#import <os/log.h>

__attribute__((constructor))
void load() {
  os_log_error(OS_LOG_DEFAULT, "payload loaded\n");

  dispatch_async(dispatch_get_main_queue(), ^{
	  UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"pwn" message:nil preferredStyle:UIAlertControllerStyleAlert];
	  UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil];
	  [alert addAction:defaultAction];
	  [[[[UIApplication sharedApplication] keyWindow] rootViewController] presentViewController:alert animated:YES completion:nil];
  });
}
