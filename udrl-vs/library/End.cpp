#include <intrin.h>
#include "Utils.h"

#ifdef _DEBUG
#pragma code_seg(".text$z")
__declspec(allocate(".text$z"))
    #ifdef _WIN64
        #include "DebugDLL.x64.h"
    #elif _WIN32
        #include "DebugDLL.x86.h"
    #endif

#elif _WIN64
#pragma code_seg(".text$z")
void LdrEnd() {}

#elif _WIN32
#pragma optimize( "", off )
#pragma code_seg(".text$z")
void* LdrEnd() {
    return GetLocation();
}
#pragma optimize( "", on )
#endif
