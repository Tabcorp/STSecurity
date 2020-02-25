//
//  STSecurityKeychainAccess.m
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#if ! (defined(__has_feature) && __has_feature(objc_arc))
# error "STSecurity must be compiled with ARC enabled"
#endif

@import Security;

#import <STSecurity/STSecurity.h>

#import "STSecurityKeychainAccess+Internal.h"


NSString * const STSecurityKeychainAccessErrorDomain = @"STSecurityKeychainError";


@implementation STSecurityKeychainReadingOptions
@synthesize localAuthContext = _localAuthContext;
@synthesize prompt = _prompt;
@end

@implementation STSecurityKeychainWritingOptions
@synthesize overwriteExisting = _overwriteExisting;
@synthesize accessibility = _accessibility;
@synthesize accessControl = _accessControl;
@synthesize localAuthContext = _localAuthContext;
@synthesize prompt = _prompt;
@end


@implementation STSecurityKeychainAccess

#pragma mark - Password - Presence

+ (BOOL)isKeychainPasswordProtectedForUsername:(NSString *)username service:(NSString *)service {

	LAContext *localAuthenticationContext = [[LAContext alloc] init];
	if([localAuthenticationContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil]) {
		return NO;
	}

	NSData *impossibleCredential = [@"" dataUsingEncoding:NSUTF8StringEncoding];
	[localAuthenticationContext setCredential:impossibleCredential type:LACredentialTypeApplicationPassword];

	CFTypeRef accessControlRef = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenUnlocked, kSecAccessControlApplicationPassword, NULL);

	NSDictionary *query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
		(__bridge id)kSecAttrService: service,
		(__bridge id)kSecAttrAccount: username,
		(__bridge id)kSecAttrAccessControl: (__bridge id)accessControlRef,
		(__bridge id)kSecUseAuthenticationContext: localAuthenticationContext
	};

	CFRelease(accessControlRef);
	accessControlRef = NULL;

	OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
	return err == errSecAuthFailed;
}


+ (BOOL)containsPasswordForUsername:(NSString *)username service:(NSString *)service withReadingOptions:(id<STSecurityKeychainReadingOptions>)readingOptions {
	return [self containsPasswordForUsername:username service:service withReadingOptions:readingOptions error:NULL];
}

+ (BOOL)containsPasswordForUsername:(NSString *)username service:(NSString *)service withReadingOptions:(id<STSecurityKeychainReadingOptions>)readingOptions error:(NSError *__autoreleasing *)error {

	if (error) {
		*error = nil;
	}

	if (![username length] || ![service length]) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}
	NSDictionary *attributes = nil;
	{
		NSMutableDictionary *query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: service,
			(__bridge id)kSecAttrAccount: username,
			(__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue,
			(__bridge id)kSecUseAuthenticationUI: (__bridge id)kSecUseAuthenticationUIFail,
		}.mutableCopy;
		
		// In the case where we are password protected but no local auth was passed in.  Return early with error.
		if([self isKeychainPasswordProtectedForUsername:username service:service] && !readingOptions.localAuthContext) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecAuthFailed userInfo:nil];
			}
			return NO;
		} else if(readingOptions.localAuthContext) {
			query[(__bridge id)kSecUseAuthenticationContext] = readingOptions.localAuthContext;
			CFTypeRef accessControlRef = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenUnlocked, kSecAccessControlApplicationPassword, NULL);
			query[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControlRef;

			CFRelease(accessControlRef);
		}

		CFDictionaryRef result = NULL;
		OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
		if (err == errSecItemNotFound) {
		} else if (err == errSecSuccess) {
			attributes = (__bridge_transfer NSDictionary *)result;
		} else if (err == errSecInteractionNotAllowed) {
			attributes = (__bridge_transfer NSDictionary *)result ?: @{};
		} else {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return NO;
		}
	}

	return !!attributes;
}

#pragma mark - Password - Insertion

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service {
	return [self setPassword:password forUsername:username service:service withReadingOptions:nil withWritingOptions:nil  error:NULL];
}

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error {
	return [self setPassword:password forUsername:username service:service withReadingOptions:nil withWritingOptions:nil error:error];
}

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service overwriteExisting:(BOOL)overwriteExisting {
	return [self setPassword:password forUsername:username service:service overwriteExisting:overwriteExisting error:NULL];
}

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service overwriteExisting:(BOOL)overwriteExisting error:(NSError * __autoreleasing *)error {
	STSecurityKeychainWritingOptions * const options = [[STSecurityKeychainWritingOptions alloc] init];
	options.overwriteExisting = overwriteExisting;
	return [self setPassword:password forUsername:username service:service withReadingOptions:nil withWritingOptions:options error:error];
}

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service withReadingOptions:(id<STSecurityKeychainReadingOptions>)readingOptions withWritingOptions:(id<STSecurityKeychainWritingOptions>)writingOptions error:(NSError *__autoreleasing *)error {
    NSData * const passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    return [self setSecret:passwordData forKey:username service:service withReadingOptions:readingOptions withWritingOptions:writingOptions error:error];
}

+ (BOOL)setSecret:(NSData *)data forKey:(NSString *)key service:(NSString *)service withReadingOptions:(id<STSecurityKeychainReadingOptions>)readingOptions withWritingOptions:(id<STSecurityKeychainWritingOptions>)writingOptions error:(NSError *__autoreleasing *)error {
    if (error) {
        *error = nil;
    }

    if (![key length] || ![service length]) {
        if (error) {
            *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
        }
        return NO;
    }

    if (![data length]) {
        if (error) {
            *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
        }
        return NO;
    }

    BOOL shouldUpdate = NO;
    NSData *persistentRef = nil;

    {
        NSMutableDictionary * const query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: service,
            (__bridge id)kSecAttrAccount: key,
            (__bridge id)kSecReturnPersistentRef: (__bridge id)kCFBooleanTrue,
            (__bridge id)kSecUseAuthenticationUI: (__bridge id)kSecUseAuthenticationUIAllow,
        }.mutableCopy;

        // In the case where we are password protected but no local auth was passed in.  Return early with error.
        if([self isKeychainPasswordProtectedForUsername:key service:service] && !readingOptions.localAuthContext) {
            if (error) {
                *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecAuthFailed userInfo:nil];
            }
            return NO;
        } else if(readingOptions.localAuthContext) {
            query[(__bridge id)kSecUseAuthenticationContext] = readingOptions.localAuthContext;
            CFTypeRef accessControlRef = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenUnlocked, kSecAccessControlApplicationPassword, NULL);
            query[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControlRef;

            CFRelease(accessControlRef);
        }

        CFDataRef result = NULL;
        OSStatus const err = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
        if (err == errSecInteractionNotAllowed) {
            shouldUpdate = YES;
        }
        if (err == errSecSuccess) {
            shouldUpdate = YES;
            persistentRef = (__bridge_transfer NSData *)result;
        }
    }
    if (shouldUpdate && !writingOptions.overwriteExisting) {
        if (error) {
            // lying about error.code but pretty close
            *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecDuplicateItem userInfo:nil];
        }
        return NO;
    }

    CFTypeRef const accessibilityRef = STSecurityKeychainItemAccessibilityToCFType(writingOptions.accessibility);
    if (!accessibilityRef) {
        if (error) {
            *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
        }
        return NO;
    }

    CFTypeRef accessControlRef = SecAccessControlCreateWithFlags(NULL, accessibilityRef, (SecAccessControlCreateFlags)writingOptions.accessControl, NULL);

    if (!accessControlRef) {
        if (error) {
            *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
        }
        return NO;
    }

    NSMutableDictionary * const attributes = @{
        (__bridge id)kSecValueData: data,
    }.mutableCopy;
    if (accessControlRef) {
        attributes[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControlRef;
    }

    if (accessControlRef) {
        CFRelease(accessControlRef);
        accessControlRef = NULL;
    }

    if (writingOptions.localAuthContext != nil) {
        attributes[(__bridge id)kSecUseAuthenticationContext] = writingOptions.localAuthContext;
    }

    if (shouldUpdate) {
        NSMutableDictionary * const query = @{}.mutableCopy;
        if (persistentRef) {
            query[(__bridge id)kSecValuePersistentRef] = persistentRef;

            // Needs access if we are updating and encrypted
            if(readingOptions.localAuthContext) {
                query[(__bridge id)kSecUseAuthenticationContext] = readingOptions.localAuthContext;
                CFTypeRef accessControlRef = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenUnlocked, kSecAccessControlApplicationPassword, NULL);
                query[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControlRef;

                CFRelease(accessControlRef);
            }


        } else {
            query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
            query[(__bridge id)kSecAttrService] = service;
            query[(__bridge id)kSecAttrAccount] = key;
        }
        if (writingOptions.prompt.length) {
            query[(__bridge id)kSecUseOperationPrompt] = writingOptions.prompt;
        }



        {
            OSStatus const err = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
            if (err == errSecSuccess) {
                return YES;
            }
        }

        {
            OSStatus const err = SecItemDelete((__bridge CFDictionaryRef)query);
            if (err == errSecSuccess) {
            } else if (err == errSecItemNotFound) {
            } else {
                if (error) {
                    *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
                }
                return NO;
            }
        }
    }

    if (writingOptions.prompt.length) {
        attributes[(__bridge id)kSecUseOperationPrompt] = writingOptions.prompt;
    }
    attributes[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    attributes[(__bridge id)kSecAttrService] = service;
    attributes[(__bridge id)kSecAttrAccount] = key;
    OSStatus const err = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
    if (err != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
        }
        return NO;
    }

    return YES;
}


#pragma mark - Password - Retrieval

+ (NSString *)passwordForUsername:(NSString *)username service:(NSString *)service {
	return [self passwordForUsername:username service:service withReadingOptions:nil error:NULL];
}

+ (NSString *)passwordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error {
	return [self passwordForUsername:username service:service withReadingOptions:nil error:error];
}

+ (NSString *)passwordForUsername:(NSString *)username service:(NSString *)service withReadingOptions:(id<STSecurityKeychainReadingOptions>)readingOptions error:(NSError *__autoreleasing *)error {
    NSData * const passwordData = [self secretForKey:username service:service withReadingOptions:readingOptions error:error];
    return [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding];
}

+ (NSData *)secretForKey:(NSString *)key service:(NSString *)service withReadingOptions:(id<STSecurityKeychainReadingOptions>)readingOptions error:(NSError *__autoreleasing *)error {
    if (error) {
        *error = nil;
    }

    if (![key length] || ![service length]) {
        if (error) {
            *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
        }
        return nil;
    }

    NSMutableDictionary * const query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
    }.mutableCopy;

    if (readingOptions.prompt.length) {
        query[(__bridge id)kSecUseOperationPrompt] = readingOptions.prompt;
    }

    // In the case where we are password protected but no local auth was passed in.  Return early with error.
    if([self isKeychainPasswordProtectedForUsername:key service:service] && !readingOptions.localAuthContext) {
        if (error) {
            *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecAuthFailed userInfo:nil];
        }
        return nil;
    } else if(readingOptions.localAuthContext) {
        query[(__bridge id)kSecUseAuthenticationContext] = readingOptions.localAuthContext;
        CFTypeRef accessControlRef = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenUnlocked, kSecAccessControlApplicationPassword, NULL);
        query[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControlRef;

        CFRelease(accessControlRef);
    }

    CFDataRef result = NULL;
    OSStatus const err = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (err != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
        }
        return nil;
    }
    NSData * const secret = (__bridge_transfer NSData *)result;
    return secret;
}


#pragma mark - Password - Deletion

+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service {
	return [self deletePasswordForUsername:username service:service withOptions:nil error:NULL];
}

+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error {
	return [self deletePasswordForUsername:username service:service withOptions:nil error:error];
}

+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions>)options error:(NSError *__autoreleasing *)error {
    return [self deleteSecretForKey:username service:service withOptions:options error:error];
}

+ (BOOL)deleteSecretForKey:(NSString *)key service:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions>)options error:(NSError * __autoreleasing *)error {
    if (error) {
        *error = nil;
    }

    if (![key length] || ![service length]) {
        if (error) {
            *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
        }
        return NO;
    }

    NSMutableDictionary * const query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: key,
    }.mutableCopy;

    if (options.prompt.length) {
        query[(__bridge id)kSecUseOperationPrompt] = options.prompt;
    }

    OSStatus const err = SecItemDelete((__bridge CFDictionaryRef)query);
    if (err != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
        }
        return NO;
    }

    return YES;
}

+ (BOOL)deletePasswordsForService:(NSString *)service {
	return [self deletePasswordsForService:service withOptions:nil error:NULL];
}

+ (BOOL)deletePasswordsForService:(NSString *)service error:(NSError * __autoreleasing *)error {
	return [self deletePasswordsForService:service withOptions:nil error:error];
}

+ (BOOL)deletePasswordsForService:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions>)options error:(NSError *__autoreleasing *)error {
	if (error) {
		*error = nil;
	}

	if (![service length]) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

	NSMutableDictionary * const query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
		(__bridge id)kSecAttrService: service,
	}.mutableCopy;

	if (options.prompt.length) {
		query[(__bridge id)kSecUseOperationPrompt] = options.prompt;
	}

	OSStatus const err = SecItemDelete((__bridge CFDictionaryRef)query);
	if (err != errSecSuccess) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
		}
		return NO;
	}

	return YES;
}

@end
