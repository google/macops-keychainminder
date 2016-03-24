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

#import <XCTest/XCTest.h>

#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>

#import "KMCallbackEngine.h"
#import "AuthorizationTypes.h"
#import "KeychainMinderAgentProtocol.h"

AuthorizationResult GlobalResult;

KMCallbackEngine *callbackEngine = nil;

OSStatus KMSetResult(AuthorizationEngineRef inEngine, AuthorizationResult inResult) {
  GlobalResult = inResult;
  return errAuthorizationSuccess;
}

OSStatus KMDidDeactivate(AuthorizationEngineRef inEngine) {
  return errAuthorizationSuccess;
}

OSStatus KMGetContextValue(AuthorizationEngineRef inEngine,
                           AuthorizationString inKey,
                           AuthorizationContextFlags *outContextFlags,
                           const AuthorizationValue **outValue) {
  return [callbackEngine getContextValue:inEngine
                                  forKey:inKey
                                outFlags:outContextFlags
                                outValue:outValue];
}

OSStatus KMGetHintValue(AuthorizationEngineRef inEngine,
                        AuthorizationString inKey,
                        const AuthorizationValue **outValue) {
  return [callbackEngine getHintValue:inEngine
                               forKey:inKey
                             outValue:outValue];
}

@interface KeychainMinderTests : XCTestCase

@end

@implementation KeychainMinderTests

//
// Basic test to run through the plugin's funtions to ensure AuthorizationSuccess.
//
- (void)testKMPluginCoreAuthorizationSuccess {
  callbackEngine = [[KMCallbackEngine alloc] init];
  [callbackEngine setUsername:@"bur"];
  [callbackEngine setPassword:@"tomtom"];
  [callbackEngine setUid:501];
  [callbackEngine setGid:20];
  [callbackEngine setAuthorizeRight:@"authenticate"];
  [callbackEngine setClientPath:@"/System/Library/CoreServices/loginwindow.app"];
  [callbackEngine setSuggestedUser:@"bur"];

  AuthorizationCallbacks *callbacks =
  (AuthorizationCallbacks *)malloc(sizeof(AuthorizationCallbacks));
  callbacks->version = kAuthorizationCallbacksVersion;
  callbacks->SetResult = &KMSetResult;
  callbacks->DidDeactivate = &KMDidDeactivate;
  callbacks->GetContextValue = &KMGetContextValue;
  callbacks->GetHintValue = &KMGetHintValue;

  AuthorizationPluginRef plugin;
  const AuthorizationPluginInterface *pluginInterface;
  AuthorizationPluginCreate(callbacks, &plugin, &pluginInterface);
  PluginRecord *pluginRecord = (PluginRecord *)plugin;
  XCTAssertTrue(pluginRecord->magic == kPluginMagic);
  XCTAssertTrue(pluginRecord->callbacks != NULL);
  XCTAssertTrue(pluginRecord->callbacks->version >= kAuthorizationCallbacksVersion);

  NSArray *mechIDs = @[ @"check" ];

  for (NSString *mechID in mechIDs) {
    GlobalResult = -1;
    AuthorizationEngineRef engine;
    AuthorizationMechanismRef mechanism;
    pluginInterface->MechanismCreate(plugin, engine, [mechID UTF8String], &mechanism);
    MechanismRecord *mechanismRecord = (MechanismRecord *)mechanism;
    XCTAssertTrue(mechanismRecord->magic == kMechanismMagic);
    XCTAssertTrue(mechanismRecord->pluginRecord != NULL);
    pluginInterface->MechanismInvoke(mechanism);
    XCTAssertTrue(GlobalResult == kAuthorizationResultAllow);
    pluginInterface->MechanismDeactivate(mechanism);
    pluginInterface->MechanismDestroy(mechanism);
  }

  pluginInterface->PluginDestroy(plugin);
  free(callbacks);
}

- (void)testRequirementsBytes {
  unsigned char xctestReqBytes[44] = {
    0xFA, 0xDE, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x10, 0x63, 0x6F, 0x6D, 0x2E, 0x61, 0x70,
    0x70, 0x6C, 0x65, 0x2E, 0x78, 0x63, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00, 0x03
  };
  NSData *xctestReqData = [[NSData alloc] initWithBytes:xctestReqBytes length:44];
  SecRequirementRef xctestRequirements = nil;
  SecRequirementCreateWithData((__bridge CFDataRef)xctestReqData,
                               kSecCSDefaultFlags, &xctestRequirements);
  MOLCodesignChecker *selfCS = [[MOLCodesignChecker alloc] initWithSelf];
  XCTAssertTrue([selfCS validateWithRequirement:xctestRequirements]);

}

- (void)testRequirementsBase64 {
  NSString *xctestReqBase64 = @"+t4MAAAAACwAAAABAAAABgAAAAIAAAAQY29tLmFwcGxlLnhjdGVzdAAAAAM=";
  NSData *xctestReqData = [[NSData alloc] initWithBase64EncodedString:xctestReqBase64 options:0];
  SecRequirementRef xctestRequirements = nil;
  SecRequirementCreateWithData((__bridge CFDataRef)xctestReqData,
                               kSecCSDefaultFlags, &xctestRequirements);
  MOLCodesignChecker *selfCS = [[MOLCodesignChecker alloc] initWithSelf];
  XCTAssertTrue([selfCS validateWithRequirement:xctestRequirements]);
}

- (void)testRequirementsString {
  NSString *xctestReqString = @"identifier \"com.apple.xctest\" and anchor apple";
  SecRequirementRef xctestRequirements = nil;
  SecRequirementCreateWithString((__bridge CFStringRef _Nonnull)xctestReqString,
                                 kSecCSDefaultFlags, &xctestRequirements);
  MOLCodesignChecker *selfCS = [[MOLCodesignChecker alloc] initWithSelf];
  XCTAssertTrue([selfCS validateWithRequirement:xctestRequirements]);
}


// Used to debug the XPC Connection. In KeychainMinderAgent.m be sure to change the requirement
// string to com.apple.xctest.
- (void)testXPCConnection {
  NSData *passwordData = [NSKeyedArchiver archivedDataWithRootObject:@"TOMTOM"];

  NSXPCConnection *connectionToService =
  [[NSXPCConnection alloc] initWithMachServiceName:kKeychainMinderAgentServiceName
                                           options:NSXPCConnectionPrivileged];
  connectionToService.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:
                                               @protocol(KeychainMinderAgentProtocol)];
  [connectionToService resume];

  id remoteObject = [connectionToService remoteObjectProxyWithErrorHandler:^(NSError *error) {
    NSLog(@"%@", [error debugDescription]);
  }];

  [remoteObject setPassword:passwordData withReply:^(BOOL reply) {
    XCTAssertTrue(reply);
  }];
}

@end