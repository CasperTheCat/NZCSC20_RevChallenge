#include "Public/Header/WatchInterface.h"

void IWatchable::Register(class CWatchdog *pDog)
{
    m_pWatchdog = pDog;
}