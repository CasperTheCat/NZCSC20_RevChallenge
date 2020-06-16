#pragma once

#ifdef NDEBUG
    #ifndef _WIN32
    #define ASM(x) __asm__(x)
    #else
    #define ASM(x) __asm{x}
    #endif
#else
#define ASM(x)
#endif

typedef void (*voidFnPtr)();	
