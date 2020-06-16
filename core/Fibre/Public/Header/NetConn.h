#pragma once

#include <vector>
#include <openssl/bio.h>
#include <memory>
#include <string>
#include <cstdint>

#include "Public/Header/WatchInterface.h" // IWatchable


enum ETxOpcodes : uint32_t
{
    GetFlag,
    GetRand,
    Verify,

    TOTAL_TX_OPCODES
};

struct FNetTxHeader
{
    // What op are we doing?
    ETxOpcodes opcode;
};

class CNetConn : public IWatchable
{
private:
    std::vector<char> m_vKey;
    
    // RECV
    std::vector<char> m_vImmediateBuffer;
    std::vector<char> m_vRequestBuffer;
    
    // Connection Data
    BIO* m_bioServer;

    std::string m_strHost;
    uint16_t m_uPort;
    
    uint32_t INTERNAL_Encrypt(std::vector<char> &vBuffer);
    uint32_t INTERNAL_Decrypt(std::vector<char> &vBuffer);

public:
    CNetConn(std::string strHost, uint16_t uPort);
    ~CNetConn();
    
    // "Negiotiate"
    void SetKey(std::vector<char> &&vKey);
    
    void Send(const FNetTxHeader &stHeader, const std::vector<char> &vBuffer);
    void Recv(std::vector<char> &vBuffer);    

    // Watchable
    virtual void Destroy() override;
    virtual void Trap() override;

    void Reconnect();

    uint32_t GetKeyPart();
};
