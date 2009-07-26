/*
 The MIT License
 
 Copyright (c) 2009 Zero260, Inc.
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#import "ApplicationDelegate.h"

@interface ApplicationDelegate ()

#pragma mark Properties
@property(nonatomic, retain) NSString *payload;

#pragma mark Private
- (BOOL)isConnected;
- (OSStatus)connect;
- (void)disconnect;
- (void)generatePayload;
- (NSData *)searchKeychainForCertificate;
- (NSData *)dataFromTokenString:(NSString *)tokenString;
- (NSCharacterSet *)hexCharacterSet;
- (void)alertUserWithErrorCode:(OSStatus)err;
- (void)alertUser:(NSString *)message;
@end

@implementation ApplicationDelegate

#pragma mark Allocation

- (id)init {
	self = [super init];
	if(self != nil) {
		// Example Raw JSON payload
		self.payload = @"{\"aps\":{\"alert\":\"Message Here!\",\"badge\":123,\"sound\":\"default\"}}";
	}
	return self;
}

- (void)dealloc {
	[self.payload release];
	[super dealloc];
}

#pragma mark Properties

@synthesize payload = payload;

#pragma mark Application Startup & Shutdown

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
}

- (void)applicationWillTerminate:(NSNotification *)notification {
	[self disconnect];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)application {
	return YES;
}

#pragma mark Private

- (NSData *)dataFromTokenString:(NSString *)string {
	
	if (string.length == 0) {
		[self alertUser:@"No Device Token"];
		return nil;
	}
	
	NSMutableData *out = [NSMutableData data];
	NSMutableString *buffer = [NSMutableString string];
	NSCharacterSet *hexCharacterSet = [self hexCharacterSet];
	
	// For every character in the string
	for(int i=0; i<string.length; i++) {
		// If the character is a hex character
		if([hexCharacterSet characterIsMember:[string characterAtIndex:i]]) {
			
			// Add it to the buffer
			[buffer appendString:[string substringWithRange:NSMakeRange(i, 1)]];
			
			// If the buffer is 8 characters long
			if(buffer.length == 8) {
				
				// Parse a hex int from the buffer, make sure it's native order,
				// append it to the output data, and reset the buffer
				NSScanner *scanner = [NSScanner scannerWithString:buffer];
				unsigned int hexInt;
				[scanner scanHexInt:&hexInt];
				hexInt = htonl(hexInt);
				[out appendBytes:&hexInt length:sizeof(hexInt)];
				buffer = [NSMutableString string];
			}
		}
	}
	
	if(out.length != 32) {
		[self alertUser:[NSString stringWithFormat:@"Failed to parse Device Token: \"%@\"", string]];
		return nil;
	}
	
	return out;
}

- (NSData *)searchKeychainForCertificate {
	SecKeychainSearchRef searchRef;
	SecKeychainItemRef itemRef;
	
	NSData *outData = nil;
	
	// Grab all certificates from the keychain
	SecKeychainCopyDefault(&keychain);
	SecKeychainSearchCreateFromAttributes(keychain, kSecCertificateItemClass, 0, &searchRef);
	
	// For each certificate in the keychain
	while (SecKeychainSearchCopyNext (searchRef, &itemRef) == noErr) {
		// Grab the name of the certificate
		SecKeychainAttributeList list;
		SecKeychainAttribute attributes[1];
		
		attributes[0].tag = kSecLabelItemAttr;
		
		list.count = 1;
		list.attr = attributes;
		
		SecKeychainItemCopyContent(itemRef, nil, &list, nil, nil);
		NSString *name = [NSString stringWithCString:attributes[0].data length:attributes[0].length];
		
		UInt32 length = 0;
		void *data = 0;
		
		// If the name of the certificate is the same as our push certificate
		if([name isEqualToString:certificateNameField.stringValue]) {
			// We found our certificate, copy its data to be returned
			SecKeychainItemCopyContent(itemRef, nil, nil, &length, &data);
			
			outData = [NSData dataWithBytes:data length:length];
		}
		
		SecKeychainItemFreeContent(&list, data);
        CFRelease (itemRef);
    }
	
	CFRelease(searchRef);
	CFRelease(keychain);
	keychain = 0;
	
	return outData;
}

- (BOOL)isConnected {
	return (socket != NULL);
}

- (OSStatus)connect {
	// Define result variable
	OSStatus result = noErr;
	
	if ([self isConnected]) {
		return result;
	}

	// Establish connection to server
	if (result == noErr) {
		PeerSpec peer;
		result = MakeServerConnection("gateway.sandbox.push.apple.com", 2195, &socket, &peer);
		NSLog(@"MakeServerConnection %i", (int)result);
	}
	
	// Create new SSL context
	if (result == noErr) {
		result = SSLNewContext(false, &context);
		NSLog(@"SSLNewContext %i", (int)result);
	}
	
	// Set callback functions for SSL context
	if (result == noErr) {
		result = SSLSetIOFuncs(context, SocketRead, SocketWrite);
		NSLog(@"SSLSetIOFuncs %i", (int)result);
	}
	
	// Set SSL context connection
	if (result == noErr) {
		result = SSLSetConnection(context, socket);
		NSLog(@"SSLSetConnection %i", (int)result);
	}
	
	// Set server domain name
	if (result == noErr) {
		result = SSLSetPeerDomainName(context, "gateway.sandbox.push.apple.com", 30);
		NSLog(@"SSLSetPeerDomainName %i", (int)result);
	}
	
	// Create certificate
	if (result == noErr) {
		NSData *certificateData = [self searchKeychainForCertificate];
		CSSM_DATA data;
		data.Data = (uint8 *)[certificateData bytes];
		data.Length = [certificateData length];
		
		result = SecCertificateCreateFromData(&data, CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_BER, &certificate);
		NSLog(@"SecCertificateCreateFromData %i", (int)result);
	}
	
	// Open keychain
	if (result == noErr) {
		result = SecKeychainCopyDefault(&keychain);
		NSLog(@"SecKeychainCopyDefault %i", (int)result);
	}
	
	// Create identity
	if (result == noErr) {
		result = SecIdentityCreateWithCertificate(keychain, certificate, &identity);
		NSLog(@"SecIdentityCreateWithCertificate %i", (int)result);
	}
	
	// Set client certificate
	if (result == noErr) {
		CFArrayRef certificates = CFArrayCreate(NULL, (const void **)&identity, 1, NULL);
		result = SSLSetCertificate(context, certificates);
		NSLog(@"SSLSetCertificate %i", (int)result);
		CFRelease(certificates);
	}
	
	// Perform SSL handshake
	if (result == noErr) {
		do {
			result = SSLHandshake(context);
			NSLog(@"SSLHandshake %i", (int)result);
		} while(result == errSSLWouldBlock);
	}
	
	if (result != noErr) {
		[self disconnect];
	}

	return result;
}

- (void)disconnect {
	// Close SSL session
	if (context) {
		SSLClose(context);
	}
	
	// Release identity
	if (identity) {
		CFRelease(identity);
		identity = NULL;
	}
	
	// Release certificate
	if (certificate) {
		CFRelease(certificate);
		certificate = NULL;
	}
	
	// Release keychain
	if (keychain) {
		CFRelease(keychain);
		keychain = NULL;
	}
	
	// Close connection to server
	if (socket) {
		close((int)socket);
		socket = NULL;
	}
	
	// Delete SSL context
	if (context) {
		SSLDisposeContext(context);
		context = NULL;
	}
}

/*
 Builds the push notification payload from the text fields on the main window
 */
- (void)generatePayload {
	NSMutableString *apsParams = [NSMutableString string];
	if (messageField.stringValue.length > 0) {
		[apsParams appendFormat:@"\"alert\":\"%@\"", messageField.stringValue];
	}
	if (badgeField.stringValue.length > 0) {
		if (apsParams.length > 0) {
			[apsParams appendString:@","];
		}
		[apsParams appendFormat:@"\"badge\":%@", badgeField.stringValue]; 
	}
	if (soundField.stringValue.length > 0) {
		if (apsParams.length > 0) {
			[apsParams appendString:@","];
		}
		[apsParams appendFormat:@"\"sound\":\"%@\"", soundField.stringValue]; 
	}

	// uuid is required for Z2Live service invites, but is optional for this test program
	NSString *uiid = @"";
	if (uiidField.stringValue.length > 0) {
		uiid = [NSString stringWithFormat:@",\"uiid\":\"%@\"", uiidField.stringValue];
	}

	self.payload = [NSString stringWithFormat:@"{\"aps\":{%@}%@}", apsParams, uiid];
}

/*
 Returns an NSCharacterSet consisting of all the characters that can make up a
 hexadecimal number
 */
- (NSCharacterSet *)hexCharacterSet {
	return [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"];
}

/*
 Alert user that an error occurred.
 */
- (void)alertUserWithErrorCode:(OSStatus)err {
	NSString *errMsg;
	
	// Check for common errors and display a better error message
	switch (err) {
		case errSSLCrypto: errMsg = @"Access to keychain denied."; break;
		default:
			// System errors
			errMsg = [NSString stringWithFormat:@"%s", GetMacOSStatusCommentString(err)];
			break;
	}
	[self alertUser:[NSString stringWithFormat:@"Error: %@ (%i)", errMsg, (int)err]];
}

- (void)alertUser:(NSString *)message {
	NSBeginAlertSheet(@"Z2Notify Error", nil, nil, nil, nil, self, @selector(errorSheetDidEnd:returnCode:contextInfo:), NULL, (void*)nil, message);
}

- (void)errorSheetDidEnd:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void  *)contextInfo {
	
}


#pragma mark IBAction

- (IBAction)fieldChanged:(id)sender {
	[self generatePayload];
}

- (IBAction)push:(id)sender {
	// Validate fields
	
	if (certificateNameField.stringValue.length == 0) {
		[self alertUser:@"No Certificate specified"];
		return;
	}
	
	// Convert string into device token data
	NSData *deviceTokenData = [self dataFromTokenString:deviceTokenField.stringValue];
	if (deviceTokenData == nil) {
		return;
	}

	if (self.payload == nil || self.payload.length == 0) {
		[self alertUser:@"No Raw JSON"];
		return;
	}

	OSStatus result = [self connect];

	if (result == noErr) {
		// Create C input variables
		char *deviceTokenBinary = (char *)[deviceTokenData bytes];
		char *payloadBinary = (char *)[self.payload UTF8String];
		size_t payloadLength = strlen(payloadBinary);
		
		// Define some variables
		uint8_t command = 0;
		char message[293];
		char *pointer = message;
		uint16_t networkTokenLength = htons(32);
		uint16_t networkPayloadLength = htons(payloadLength);
		
		// Compose message
		memcpy(pointer, &command, sizeof(uint8_t));
		pointer += sizeof(uint8_t);
		memcpy(pointer, &networkTokenLength, sizeof(uint16_t));
		pointer += sizeof(uint16_t);
		memcpy(pointer, deviceTokenBinary, 32);
		pointer += 32;
		memcpy(pointer, &networkPayloadLength, sizeof(uint16_t));
		pointer += sizeof(uint16_t);
		memcpy(pointer, payloadBinary, payloadLength);
		pointer += payloadLength;
		
		// Send message over SSL
		size_t processed = 0;
		result = SSLWrite(context, &message, (pointer - message), &processed);
		NSLog(@"SSLWrite %i", (int)result);
	}
	
	if (result != noErr) {
		[self alertUserWithErrorCode:result];
	}
}

@end
