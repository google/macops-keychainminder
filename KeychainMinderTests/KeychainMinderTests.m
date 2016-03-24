//
//  KeychainMinderTests.m
//  KeychainMinderTests
//
//  Created by bur on 3/16/16.
//  Copyright © 2016 Google Inc. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "KMCallbackEngine.h"
#import "Common.h"

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

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

// Basic test to run through the plugin's funtions to ensure AuthorizationSuccess.
- (void)testKMPluginCoreAuthorizationSuccess {
  callbackEngine = [[KMCallbackEngine alloc] init];
  [callbackEngine setUsername:@"bur"];
  [callbackEngine setPassword:@"tomtom"];
  [callbackEngine setUid:501];
  [callbackEngine setGid:20];
  [callbackEngine setAuthorizeRight:@"system.login.console"];
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

  NSArray *mechIDs = @[ @"run" ];

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

@end
