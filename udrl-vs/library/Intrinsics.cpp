#include <windows.h>

#pragma function(memcpy)
#pragma function(memset)
#pragma function(memcmp)
#pragma function(memmove)

#pragma code_seg(".text$h")

extern "C" void* __cdecl memcpy(void* dest, const void* src, size_t count) {
    char* d = (char*)dest;
    const char* s = (const char*)src;

    while (count--) {
        *d++ = *s++;
    }

    return dest;
}

extern "C" void* __cdecl memset(void* dest, int val, size_t count) {
    unsigned char* d = (unsigned char*)dest;
    unsigned char value = (unsigned char)val;

    while (count--) {
        *d++ = value;
    }

    return dest;
}

extern "C" int __cdecl memcmp(const void* buf1, const void* buf2, size_t count) {
    const unsigned char* b1 = (const unsigned char*)buf1;
    const unsigned char* b2 = (const unsigned char*)buf2;

    while (count--) {
        if (*b1 != *b2) {
            return (*b1 < *b2) ? -1 : 1;
        }
        b1++;
        b2++;
    }

    return 0;
}

extern "C" void* __cdecl memmove(void* dest, const void* src, size_t count) {
    char* d = (char*)dest;
    const char* s = (const char*)src;

    if (d <= s || d >= (s + count)) {
        while (count--) {
            *d++ = *s++;
        }
    }
    else {
        d += count - 1;
        s += count - 1;
        while (count--) {
            *d-- = *s--;
        }
    }

    return dest;
}

#ifdef _WIN64
extern "C" void __CxxFrameHandler4() {
}

extern "C" void __GSHandlerCheck() {
}
#endif