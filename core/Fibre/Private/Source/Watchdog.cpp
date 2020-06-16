#include "Public/Header/Watchdog.h"
#include "Private/Header/Util.h"
#include "Public/Header/WatchInterface.h"

#include <iostream>

CWatchdog::CWatchdog(IWatchable *watchedResource)
{
    m_pWatched = watchedResource;
    m_chrLastAckl = std::chrono::high_resolution_clock::now();

#ifdef NDEBUG
    for(uint32_t i = 0; i < 128; ++i)
    {
        m_vtrWatchdogs.emplace_back(&CWatchdog::Watchdog_RT, this);
    }
#endif

    watchedResource->Register(this);
}

void Destroy()
{
    ASM("xor rax, rax");
    ASM("mov rax, rsp");
    ASM("mov rax, rbp");
    ASM("ret");

    exit(0);
}

void CWatchdog::Watchdog_RT()
{
    while(true)
    {
        auto msCount = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now() - m_chrLastAckl).count();

        //std::cout << "[WDOG] " << msCount << std::endl;

        if(msCount > 3000)
        {
            printf("BOOM\n");
            //Internal Destroy
            m_pWatched->Destroy();

            Destroy();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

CWatchdog::~CWatchdog()
{
    auto fn = (voidFnPtr)0xDEADBEEF;
    fn();
}

void CWatchdog::Ack()
{
    m_chrLastAckl = std::chrono::high_resolution_clock::now();
}

uint32_t CWatchdog::GetKeyPart()
{
    return 0xb5e9ebfa;
}