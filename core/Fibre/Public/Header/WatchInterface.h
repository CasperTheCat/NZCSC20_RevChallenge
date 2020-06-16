#pragma once
#include "Public/Header/Watchdog.h"

class IWatchable
{
protected:
    CWatchdog* m_pWatchdog;

public:
    virtual void Destroy() = 0;
    virtual void Trap() = 0;
    void Register(CWatchdog *pDog);
};