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

#include "Common.h"

#import <Foundation/Foundation.h>
#import <Security/AuthorizationPlugin.h>

#include "KeychainMinderAgentProtocol.h"

#pragma mark Utility Functions

NSString *GetStringFromContext(MechanismRecord *mechanism, AuthorizationString key) {
  const AuthorizationValue *value;
  AuthorizationContextFlags flags;
  OSStatus err = mechanism->pluginRecord->callbacks->GetContextValue(
      mechanism->engineRef, key, &flags, &value);
  if (err == errSecSuccess && value->length > 0) {
    NSString *s = [[NSString alloc] initWithBytes:value->data
                                           length:value->length
                                         encoding:NSUTF8StringEncoding];
    return [s stringByReplacingOccurrencesOfString:@"\0" withString:@""];
  }
  return nil;
}

NSString *GetStringFromHint(MechanismRecord *mechanism, AuthorizationString key) {
  const AuthorizationValue *value;
  OSStatus err = mechanism->pluginRecord->callbacks->GetHintValue(mechanism->engineRef, key,
                                                                  &value);
  if (err == errSecSuccess && value->length > 0) {
    NSString *s = [[NSString alloc] initWithBytes:value->data
                                           length:value->length
                                         encoding:NSUTF8StringEncoding];
    return [s stringByReplacingOccurrencesOfString:@"\0" withString:@""];
  }
  return nil;
}

uid_t GetUIDFromContex(MechanismRecord *mechanism) {
  uid_t uid = -2;
  const AuthorizationValue *value;
  AuthorizationContextFlags flags;
  if (mechanism->pluginRecord->callbacks->GetContextValue(mechanism->engineRef,
                                                          kAuthorizationEnvironmentUID,
                                                          &flags,
                                                          &value) == errAuthorizationSuccess) {
    if ((value->length == sizeof(uid_t)) && (value->data != NULL)) {
      uid = *(const uid_t *)value->data;
    }
  }
  return uid;
}

gid_t GetGIDFromContex(MechanismRecord *mechanism) {
  gid_t gid = -2;
  const AuthorizationValue *value;
  AuthorizationContextFlags flags;
  if (mechanism->pluginRecord->callbacks->GetContextValue(mechanism->engineRef,
                                                          kAuthorizationEnvironmentGID,
                                                          &flags,
                                                          &value) == errAuthorizationSuccess) {
    if ((value->length == sizeof(gid_t)) && (value->data != NULL)) {
      gid = *(const gid_t *)value->data;
    }
  }
  return gid;
}

OSStatus AllowLogin(MechanismRecord *mechanism) {
  return mechanism->pluginRecord->callbacks->SetResult(mechanism->engineRef,
                                                       kAuthorizationResultAllow);
}

#pragma mark Mechanism Functions

OSStatus MechanismCreate(
    AuthorizationPluginRef inPlugin,
    AuthorizationEngineRef inEngine,
    AuthorizationMechanismId mechanismId,
    AuthorizationMechanismRef *outMechanism) {
  MechanismRecord *mechanism = (MechanismRecord *)malloc(sizeof(MechanismRecord));
  if (mechanism == NULL) return errSecMemoryError;
  mechanism->magic = kMechanismMagic;
  mechanism->engineRef = inEngine;
  mechanism->pluginRecord = (PluginRecord *)inPlugin;
  *outMechanism = mechanism;
  return errSecSuccess;
}

OSStatus MechanismDestroy(AuthorizationMechanismRef inMechanism) {
  free(inMechanism);
  return errSecSuccess;
}

OSStatus MechanismInvoke(AuthorizationMechanismRef inMechanism) {
  MechanismRecord *mechanism = (MechanismRecord *)inMechanism;
  @autoreleasepool {
    uid_t uid = GetUIDFromContex(mechanism);
    gid_t gid = GetGIDFromContex(mechanism);

    // Make sure this is not a hidden user.
    if (uid < 501) {
      return AllowLogin(mechanism);
    }

    NSString *username = GetStringFromContext(mechanism, kAuthorizationEnvironmentUsername);
    NSString *password = GetStringFromContext(mechanism, kAuthorizationEnvironmentPassword);
    NSString *sesOwner = GetStringFromHint(mechanism, kAuthorizationEnvironmentSuggestedUser);

    // Make sure we have username and password data.
    if (!username && !password) {
      return AllowLogin(mechanism);
    }

    // Make sure the auth user is the sesion owner.
    if (![username isEqualToString:sesOwner]) {
      return AllowLogin(mechanism);
    }

    BOOL keychainPasswordValid = YES;

    // Switch the per thread EUID/EGID to the target user so SecKeychain* knows who to affect,
    // validate the login keychain password, then switch back to the previous user.
    // Using pthread as to not disrupt all of authorizationhost.
    if (pthread_setugid_np(uid, gid) == 0) {
      SecKeychainSetUserInteractionAllowed(NO);
      keychainPasswordValid = ValidateLoginKeychainPassword(password);
      // Revert back to the default ids
      pthread_setugid_np(KAUTH_UID_NONE, KAUTH_GID_NONE);
    } else {
      return AllowLogin(mechanism);
    }

    // Remove the current user, so they aren't duplicated in a second if
    // the password wasn't valid.
    NSMutableArray *users = GetUsers();
    [users removeObject:username];

    if (!keychainPasswordValid) {
      NSData *passwordData = [NSKeyedArchiver archivedDataWithRootObject:password];

      NSXPCConnection *connectionToService =
      [[NSXPCConnection alloc] initWithMachServiceName:kKeychainMinderAgentMachServiceName
                                               options:NSXPCConnectionPrivileged];
      connectionToService.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:
                                                   @protocol(KeychainMinderAgentProtocol)];
      [connectionToService resume];

      id remoteObject = [connectionToService
                         remoteObjectProxyWithErrorHandler:^(NSError *error) {
                           NSLog(@"%@", [error debugDescription]);
                         }];
      [remoteObject setPassword:passwordData withReply:^(BOOL reply) {
        NSLog(@"KeychainMinderAgent %@", reply ? @"Sucess" : @"Fail");
      }];

      [users addObject:username];
    }

    SetUsers(users);
  }

  return AllowLogin(mechanism);
}

OSStatus MechanismDeactivate(AuthorizationMechanismRef inMechanism) {
  MechanismRecord *mechanism = (MechanismRecord *)inMechanism;
  return mechanism->pluginRecord->callbacks->DidDeactivate(mechanism->engineRef);
}

#pragma mark Plugin Functions

OSStatus PluginDestroy(AuthorizationPluginRef inPlugin) {
  free(inPlugin);
  return errSecSuccess;
}

OSStatus AuthorizationPluginCreate(
    const AuthorizationCallbacks *callbacks,
    AuthorizationPluginRef *outPlugin,
    const AuthorizationPluginInterface **outPluginInterface) {
  PluginRecord *plugin = (PluginRecord *)malloc(sizeof(PluginRecord));
  if (plugin == NULL) return errSecMemoryError;
  plugin->magic = kPluginMagic;
  plugin->callbacks = callbacks;
  *outPlugin = plugin;

  static AuthorizationPluginInterface pluginInterface = {
    kAuthorizationPluginInterfaceVersion,
    &PluginDestroy,
    &MechanismCreate,
    &MechanismInvoke,
    &MechanismDeactivate,
    &MechanismDestroy
  };
  *outPluginInterface = &pluginInterface;

  return errSecSuccess;
}
