#pragma once
#include <Windows.h> 

#define HASH_KEY  17
#pragma intrinsic( _rotr )

__forceinline DWORD RunTimeHash(const char* str) {
    DWORD hash = 0;
    do {
        hash = _rotr(hash, HASH_KEY);
        if (*str >= 'a') {
            hash += *str - ('a' - 'A');
        }
        else {
            hash += *str;
        }
    } while (*++str);

    return hash;
}

__forceinline DWORD RunTimeHash(const char* data, size_t length) {
    DWORD hash = 0;
    while (length--) {
        hash = _rotr(hash, HASH_KEY);
        if (*data >= 'a') {
            hash += *data - ('a' - 'A');
        }
        else {
            hash += *data;
        }
        ++data;
    }

    return hash;
}

constexpr DWORD CompileTimeHash(const char* str) {
    DWORD hash = 0;
    do {
        hash = (hash >> HASH_KEY) | (hash << (sizeof(DWORD) * 8 - HASH_KEY));
        if (*str >= 'a') {
            hash += *str - ('a' - 'A');
        }
        else {
            hash += *str;
        }
    } while (*++str);

    return hash;
}
