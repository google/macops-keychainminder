/// Copyright 2015 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "KeychainMinderAgent.h"

#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>

@interface KeychainMinderAgent()

@property (nonatomic, strong) NSXPCListener *listener;
@property (nonatomic, strong) NSMutableData *passwordData;

@end

@implementation KeychainMinderAgent

- (id)init {
  self = [super init];
  if (self) {
    // Set up our XPC listener to handle requests on our Mach service.
    _listener = [[NSXPCListener alloc] initWithMachServiceName:kKeychainMinderAgentServiceName];
    _listener.delegate = self;
  }
  return self;
}

- (void)run {
  // Tell the XPC listener to start processing requests.
  [self.listener resume];
  
  // Run the run loop forever.
  [[NSRunLoop currentRunLoop] run];
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConn {
  pid_t pid = newConn.processIdentifier;
  
  MOLCodesignChecker *selfCS = [[MOLCodesignChecker alloc] initWithSelf];
  MOLCodesignChecker *remoteCS = [[MOLCodesignChecker alloc] initWithPID:pid];

  // Add an exemption for authorizationhost.bundle connections. This is needed so the authorization
  // plugin use this XPC service.
  NSString *const ahReqString = @"identifier \"com.apple.authorizationhost\" and anchor apple";
  SecRequirementRef ahRequirements = NULL;
  SecRequirementCreateWithString((__bridge CFStringRef _Nonnull)ahReqString,
                                 kSecCSDefaultFlags, &ahRequirements);

   // Only allow connections that are signed with the same CS or match the SecRequirementRef
  if ([remoteCS signingInformationMatches:selfCS] ||
      [remoteCS validateWithRequirement:ahRequirements]) {
    newConn.exportedInterface = [NSXPCInterface interfaceWithProtocol:
                                       @protocol(KeychainMinderAgentProtocol)];
    newConn.exportedObject = self;
    [newConn resume];
    return YES;
  }
  return NO;
}

- (void)setPassword:(NSData *)inPassword withReply:(void (^)(BOOL))reply {
  _passwordData = inPassword.mutableCopy;
  reply(_passwordData != nil);
}

- (void)getPasswordWithReply:(void (^)(NSData *))reply {
  reply(_passwordData);
  [_passwordData resetBytesInRange:NSMakeRange(0, _passwordData.length)];
  // The connection has completed it's task of handing off the login password to
  // the KeychainMinderGUI. Kill the agent.
  exit(0);
}

@end
