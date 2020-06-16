#pragma once
#include <chrono>
#include <thread>
#include <vector>
//#include <mutex>

//#include "Public/Header/WatchInterface.h"

class CWatchdog
{
    private:
    class IWatchable *m_pWatched;
    std::chrono::time_point<std::chrono::high_resolution_clock> m_chrLastAckl;
    std::vector<std::thread> m_vtrWatchdogs;

    void Watchdog_RT();

    public:
    CWatchdog(class IWatchable *watchedResource);
    ~CWatchdog();

    void Ack();
    //void Trap();
    uint32_t GetKeyPart();
};