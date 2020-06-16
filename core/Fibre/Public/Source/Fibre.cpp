#include <iostream>
#include <filesystem>
#include <thread>
#include "Public/Header/NetConn.h"
#include "Public/Header/Watchdog.h"
#include <vector>
#include <cstring>

#define GITHUBLINK "https://github.com/CasperTheCat/NZCSC20_RevChallenge"

#include <ctime>   // localtime
#include <fstream>

#ifndef _WIN32
#define ASM(x) __asm__(x)
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
#include <stdio.h>

#include <signal.h>
#include <sys/ptrace.h>
#else
#define ASM(x) __asm{x}
#endif

struct KeyMaterial
{
    uint32_t Key1;
    uint32_t Key2;
    uint32_t Key3;
    uint32_t Key4;
};

#define ANTI_DEBUG_USF "flag:UnitedStates"

#ifdef NDEBUG
int real(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
    // This region of code is removed due to amazingly silly behaviour ensuing

    //ASM("")
    // Rock this stack frame from here to kazakhstan
    // ASM("xor rax, rax");
    // ASM("mov rax, rsp");
    // ASM("mov rax, rbp");
    // ASM("ret");
    // //if(!argc) return 0;

    // // Slidey
    // ASM("\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop");
    // ASM("\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop");
    // ASM("push rbp");

    // std::cout << "HLELLE" << std::endl;

    // core();
    // Connection
    auto conn = new CNetConn("sushi.nzcsc.org.nz", 80);

    // Create Watchdog
    auto wdog = new CWatchdog(conn);

    
    // Trap
    std::cout << "[INIT] Negiotiating Key" << std::endl;
    
    KeyMaterial key{};
    key.Key1 = 0x7f7f7f7f;
    key.Key2 = conn->GetKeyPart();
    key.Key3 = 0x6ba835c5;
    key.Key4 = wdog->GetKeyPart();

    //std::ofstream m("dummy.key", std::ios::binary);
    //m.write(reinterpret_cast<char*>(&key), sizeof(KeyMaterial));

    std::cout << "[INIT] Key Negiotiated (128-bit)" << std::endl;
    
    // Got keys
    // Leak info for no reason
    {
        std::vector<char> lx;
        lx.resize(128);

        memcpy(lx.data(), &key, sizeof(KeyMaterial));

        conn->SetKey(std::move(lx));

        // LX Moved, do not use
    }
    
    std::cout << "[INIT] Setting Cypher: AES-128-GCM" << std::endl;

    // Here's a story
    
    std::cout << "[INIT] Initialisation Done" << std::endl;

    // Yup, did something...
    
    std::cout << "[INFO] Data Exchange Configured" << std::endl;  


    while(true)
    {
        std::vector<char> dummy;
        FNetTxHeader txHeader{};
        txHeader.opcode = ETxOpcodes::GetRand;

        conn->Send(txHeader, dummy);
        conn->Recv(dummy);
        conn->Reconnect();

        //std::cout << "Size: " << dummy.size() << std::endl;
        std::cout << "C2 Provided RNG: " << *(reinterpret_cast<uint32_t*>(dummy.data())) << std::endl;
        //std::cout << dummy.data() << std::endl;

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}

void sigHandler(int signo)
{
    // Just enter and leave
    // The debugger will catch int3 first
    // But it takes longer
    // So the watchdog should catch



    // Devil Handler
    //auto fn = (voidFnPtr)0xDEADBEEF;

    //fn();

    //exit(0);
}

#ifdef NDEBUG
int main(int argc, char **argv)
{
    // Check the date
    std::tm pnt = {
        0, 0, 0, // sec, min, hour
        1, 8, 120
    };

    pnt.tm_isdst = -1;

    auto tp = std::chrono::system_clock::from_time_t(std::mktime(&pnt));
    auto now = std::chrono::system_clock::now();

    if (now > tp)
    {
        std::time_t tx = std::chrono::system_clock::to_time_t(tp);
        std::cout << "As of:\n\t" << std::ctime(&tx) << "This challenge has completed." << std::endl;

        // Try to write to disk
        std::ofstream motd("NZCSC-2020.txt");

        if(motd)
        {
            // Got a write!
            motd << "Thank you for participating in the 2020 New Zealand Cybersecurity Challenge :)" << std::endl;
            motd << "This challenge has automatically ended." << std::endl;
            motd << std::endl << "If you would like the source code of the reverse engineering challenge, it is available at: " << GITHUBLINK << std::endl;



        // Only do the show if we actually wrote to disk
        for(uint32_t i = 0; i < 5; ++i)
        {
            std::cout << "\rThis message will self-destruct in " << 5 - i  << " second" << ((i > 1) ? "s" : "") << "..." << std::flush;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Finish the print
        std::cout << "\rThis message has self-destructed. Please read NZCSC-2020.txt for more information. :)" << std::endl;
        }

        std::filesystem::remove(argv[0]);
        return 0;
    }

    // If we are us, then we are Mirai!
    //auto thisExe = std::filesystem::path(argv[0]);
    //auto launchExe = std::filesystem::path("./notrealbaidu.flag");
    //std::filesystem::remove(argv[0]);

    auto fn = real;// + 17;

    //auto fn = *(&real + 5);
    //return fn(0, &argv[0]);

#ifndef _WIN32

    signal(SIGTRAP, sigHandler);

    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0)
    {
        std::cout << ANTI_DEBUG_USF << std::endl;
        return 0;
    }

    auto pid = fork();
    if(pid == 0)
    {
        // We are the child
        // wat.exe
        char arg[20] = "notRealBaidu.flag";
        argv[0] = arg;

        fn(0, &argv[0]);

        exit(420);
    }
    else
    {
        std::cout << "feebdeef:galf" << std::endl;
    }

#endif

    return 0;
}
#endif
     
