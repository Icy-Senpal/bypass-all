#ifndef CUSTOM_CRT_H
#define CUSTOM_CRT_H

#include <windows.h>

#pragma function(memset)
void* memset(void* dest, int val, size_t count) {
    unsigned char* p = (unsigned char*)dest;
    while (count--) {
        *p++ = (unsigned char)val;
    }
    return dest;
}

void* my_memset(void* dest, int val, size_t count) {
    unsigned char* p = (unsigned char*)dest;
    while (count--) {
        *p++ = (unsigned char)val;
    }
    return dest;
}

void* my_memcpy(void* dest, const void* src, size_t count) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (count--) {
        *d++ = *s++;
    }
    return dest;
}

size_t my_strlen(const char* str) {
    const char* s = str;
    while (*s) s++;
    return s - str;
}

size_t my_wcslen(const wchar_t* str) {
    const wchar_t* s = str;
    while (*s) s++;
    return s - str;
}

int my_strcmp(const char* str1, const char* str2) {
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return *(unsigned char*)str1 - *(unsigned char*)str2;
}

int my_wcscmp(const wchar_t* str1, const wchar_t* str2) {
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

void my_strcpy(char* dest, const char* src) {
    while ((*dest++ = *src++) != '\0');
}

void my_wcscpy(wchar_t* dest, const wchar_t* src) {
    while ((*dest++ = *src++) != L'\0');
}

void my_strcat(char* dest, const char* src) {
    while (*dest) dest++;
    while ((*dest++ = *src++) != '\0');
}

void my_wcscat(wchar_t* dest, const wchar_t* src) {
    while (*dest) dest++;
    while ((*dest++ = *src++) != L'\0');
}

#endif

