//
//  KMCallbackEngine.h
//  KeychainMinder
//
//  Created by bur on 3/16/16.
//  Copyright © 2016 Google Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Common.h"

@interface KMCallbackEngine : NSObject

// Contex
@property (strong, nonatomic) NSString *username;
@property (strong, nonatomic) NSString *password;
@property (strong, nonatomic) NSDictionary *authenticationAuthority;
@property (nonatomic) uid_t uid;
@property (nonatomic) gid_t gid;

// Hint
@property (strong, nonatomic) NSString *tokenName;
@property (strong, nonatomic) NSString *authorizeRight;
@property (strong, nonatomic) NSString *suggestedUser;
@property (strong, nonatomic) NSString *clientPath;

- (OSStatus)getContextValue:(AuthorizationEngineRef)inEngine
                     forKey:(AuthorizationString)inKey
                   outFlags:(AuthorizationContextFlags *)outContextFlags
                   outValue:(const AuthorizationValue **)outValue;

- (OSStatus)getHintValue:(AuthorizationEngineRef)inEngine
                  forKey:(AuthorizationString)inKey
                outValue:(const AuthorizationValue **)outValue;

@end
