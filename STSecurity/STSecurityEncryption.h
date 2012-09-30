//
//  STSecurityEncryption.h
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "STSecurityKey.h"


NS_ENUM(NSUInteger, STSecurityPadding) {
	STSecurityPaddingNone = 0,
	STSecurityPaddingPKCS1,
	STSecurityPaddingOAEP,
};


extern NSString * const STSecurityEncryptionErrorDomain;


@interface STSecurityEncryption : NSObject

+ (NSData *)dataByEncryptingData:(NSData *)data withPublicKey:(STSecurityPublicKey *)key padding:(enum STSecurityPadding)padding;
+ (NSData *)dataByEncryptingData:(NSData *)data withPublicKey:(STSecurityPublicKey *)key padding:(enum STSecurityPadding)padding error:(NSError * __autoreleasing *)error;

+ (NSData *)dataByDecryptingData:(NSData *)data withPrivateKey:(STSecurityPrivateKey *)key padding:(enum STSecurityPadding)padding;
+ (NSData *)dataByDecryptingData:(NSData *)data withPrivateKey:(STSecurityPrivateKey *)key padding:(enum STSecurityPadding)padding error:(NSError * __autoreleasing *)error;

@end
