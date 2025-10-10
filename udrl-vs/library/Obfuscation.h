#pragma once
#include <windows.h>
#include "LoaderTypes.h"

BOOL RC4(unsigned char* buffer, DWORD size, unsigned char* key, DWORD keyLength);
BOOL XORData(char* buffer, size_t size, char* key, size_t keyLength);
BOOL Base64Decode(char* input, DWORD inputLength, char* output);
