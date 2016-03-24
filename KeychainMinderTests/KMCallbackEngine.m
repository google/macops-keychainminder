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

#import "KMCallbackEngine.h"

@interface KMCallbackEngine()
@property (nonatomic, strong) NSMutableDictionary *context;
@property (nonatomic, strong) NSMutableDictionary *hint;
@end

@implementation KMCallbackEngine
- (id)init {
  if ([super init]) {
    _context = [[NSMutableDictionary alloc] init];
    _hint = [[NSMutableDictionary alloc] init];
  }
  return self;
}

- (OSStatus)getContextValue:(AuthorizationEngineRef)inEngine
                     forKey:(AuthorizationString)inKey
                   outFlags:(AuthorizationContextFlags *)outContextFlags
                   outValue:(const AuthorizationValue **)outValue {
  NSString *key = [NSString stringWithCString:inKey encoding:NSUTF8StringEncoding];

  if ([_context[key] isKindOfClass:[NSString class]]) {
    const AuthorizationValue value = { (UInt32)[_context[key] length],
      (void *)[_context[key] UTF8String] };
    (*outValue) = &value;
  }

  else if ([key isEqualToString:@kAuthorizationEnvironmentAuthenticationAuthority]) {
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:(NSDictionary *)_context[key]
                                                              format:NSPropertyListXMLFormat_v1_0
                                                             options:0
                                                               error:nil];
    const AuthorizationValue value = { (UInt32)[data length], (void *)[data bytes] };
    (*outValue) = &value;
  }

  else if ([key isEqualToString:@kAuthorizationEnvironmentUID] ||
           [key isEqualToString:@kAuthorizationEnvironmentGID]) {
    const AuthorizationValue value = { (UInt32)[_context[key] length],
      (void *)[_context[key] bytes] };
    (*outValue) = &value;
  }

  else {
    const AuthorizationValue value = { (UInt32)0, NULL };
    (*outValue) = &value;
  }

  return _context[key] ? errAuthorizationSuccess : errAuthorizationInternal;
}

- (OSStatus)getHintValue:(AuthorizationEngineRef)inEngine
                  forKey:(AuthorizationString)inKey
                outValue:(const AuthorizationValue **)outValue {
  NSString *key = [NSString stringWithCString:inKey encoding:NSUTF8StringEncoding];

  if ([_hint[key] isKindOfClass:[NSString class]]) {
    const AuthorizationValue value = { (UInt32)[_hint[key] length],
      (void *)[_hint[key] UTF8String] };
    (*outValue) = &value;
  }

  else {
    const AuthorizationValue value = { (UInt32)0, NULL };
    (*outValue) = &value;
  }

  return _hint[key] ? errAuthorizationSuccess : errAuthorizationInternal;
}

- (void)setUsername:(NSString *)username {
  _context[@kAuthorizationEnvironmentUsername] = username;
}

- (void)setPassword:(NSString *)password {
  _context[@kAuthorizationEnvironmentPassword] = password;
}

- (void)setAuthenticationAuthority:(NSDictionary *)authenticationAuthority {
  _context[@kAuthorizationEnvironmentAuthenticationAuthority] = authenticationAuthority;
}

- (void)setUid:(uid_t)uid {
  NSData *data = [NSData dataWithBytes:&uid length:sizeof(uid_t)];
  _context[@kAuthorizationEnvironmentUID] = data;
}

- (void)setGid:(gid_t)gid {
  NSData *data = [NSData dataWithBytes:&gid length:sizeof(gid_t)];
  _context[@kAuthorizationEnvironmentGID] = data;
}

- (void)setTokenName:(NSString *)tokenName {
  _hint[@kAuthorizationEnvironmentTokenName] = tokenName;
}

- (void)setAuthorizeRight:(NSString *)authorizeRight {
  _hint[@kAuthorizationEnvironmentAuthorizeRight] = authorizeRight;
}

- (void)setSuggestedUser:(NSString *)suggestedUser {
  _hint[@kAuthorizationEnvironmentSuggestedUser] = suggestedUser;
}

- (void)setClientPath:(NSString *)clientPath {
  _hint[@kAuthorizationEnvironmentClientPath] = clientPath;
}

@end
