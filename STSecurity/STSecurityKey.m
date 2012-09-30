//
//  STSecurityKey.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityKey.h"

#import <Security/Security.h>


@implementation STSecurityPublicKey {
	SecKeyRef _keyRef;
	NSData *_keyData;
}

#pragma mark - Init/Dealloc

- (id)initWithKeyRef:(SecKeyRef)keyRef {
	return [self initWithKeyRef:keyRef keyData:nil];
}

- (id)initWithKeyRef:(SecKeyRef)keyRef keyData:(NSData *)keyData {
	NSParameterAssert(keyRef);
	NSParameterAssert([keyData length]);
	if ((self = [super init])) {
		_keyRef = (SecKeyRef)CFRetain(keyRef);
		_keyData = [keyData copy];
	}
	return self;
}

- (void)dealloc {
	if (_keyRef) {
		CFRelease(_keyRef), _keyRef = nil;
	}
}


#pragma mark - Information

- (SecKeyRef)keyRef {
	return _keyRef;
}

- (NSUInteger)blockSize {
	return SecKeyGetBlockSize(_keyRef);
}

- (NSData *)keyData {
	return _keyData;
}

@end


@implementation STSecurityPrivateKey {
	SecKeyRef _keyRef;
}

#pragma mark - Init/Dealloc

- (id)initWithKeyRef:(SecKeyRef)keyRef {
	NSParameterAssert(keyRef);
	if ((self = [super init])) {
		_keyRef = (SecKeyRef)CFRetain(keyRef);
	}
	return self;
}

- (void)dealloc {
	if (_keyRef) {
		CFRelease(_keyRef), _keyRef = nil;
	}
}


#pragma mark - Information

- (SecKeyRef)keyRef {
	return _keyRef;
}

- (NSUInteger)blockSize {
	return SecKeyGetBlockSize(_keyRef);
}

@end
