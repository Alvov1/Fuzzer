#include <iostream>
#include <fstream>
#include <string>
#include <streambuf>
#include <filesystem>

#include <Windows.h>

static constexpr auto ResultsFilename = "Results.txt";
static std::ofstream results;

void Registers(CONTEXT& ctx, const std::string& ExceptionStr, HANDLE hProcess) {
    static unsigned char buffer[4048] = {0};

    results << std::setfill('0');

    results << "Exception: " << ExceptionStr << "." << std::endl;
    results << "EAX - 0x" << reinterpret_cast<void*>(ctx.Eax) << ", ESP - 0x" << reinterpret_cast<void*>(ctx.Esp) << "." << std::endl;
    results << "EBX - 0x" << reinterpret_cast<void*>(ctx.Ebx) << ", EBP - 0x" << reinterpret_cast<void*>(ctx.Ebp) << "." << std::endl;
    results << "ECX - 0x" << reinterpret_cast<void*>(ctx.Ecx) << ", EDI - 0x" << reinterpret_cast<void*>(ctx.Edi) << "." << std::endl;
    results << "EDX - 0x" << reinterpret_cast<void*>(ctx.Edx) << ", ESI - 0x" << reinterpret_cast<void*>(ctx.Esi) << "." << std::endl;
    results << "EIP - 0x" << reinterpret_cast<void*>(ctx.Eip) << ", Flags - 0x" << reinterpret_cast<void*>(ctx.EFlags) << "." << std::endl;

    SIZE_T recSize = 0;
    if(ReadProcessMemory(hProcess, reinterpret_cast<void*>(ctx.Esp), buffer, sizeof(buffer), &recSize) == 0)
        std::cout << "[-] ReadProcessMemory failed with code " << GetLastError() << std::endl;

    std::cout << "Read " << recSize << " bytes from stack." << std::endl;
    results << "Read " << recSize << " bytes from stack." << std::endl;

    for(auto i = 0; i < recSize; ++i) {
        if(i % 4 == 0)
            results << "0x" << reinterpret_cast<void*>(ctx.Esp + i) << " - ";

        results << std::setw(2) << static_cast<int>(buffer[i]);

        if(i % 4 == 3) results << std::endl;
    }
    results << std::endl;
}
void Execute(const std::filesystem::path& exeFile) {
    STARTUPINFO sInfo{};
    sInfo.cb = sizeof(sInfo);
    PROCESS_INFORMATION pInfo;

    std::cout << "[+] Tracking process '" << exeFile.string().c_str() << "'." << std::endl;

    if(!CreateProcessA((LPCSTR) exeFile.string().c_str(), nullptr, nullptr, nullptr,
       false, DEBUG_PROCESS, nullptr, nullptr, (LPSTARTUPINFOA) &sInfo, &pInfo))
        throw std::runtime_error("[-] Process creation failed with code " + std::to_string(GetLastError()) + ".");

    DEBUG_EVENT dEvent = {0};
    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
    while(true) {
        if(!WaitForDebugEvent(&dEvent, 500)) {
            if (GetLastError() != ERROR_SEM_TIMEOUT)
                throw std::runtime_error("[-] WaitForDebugEvent failed with code " + std::to_string(GetLastError()) + ".");
            break;
        }
        if(dEvent.dwDebugEventCode != EXCEPTION_DEBUG_EVENT) {
            ContinueDebugEvent(dEvent.dwProcessId, dEvent.dwThreadId, DBG_CONTINUE);
            continue;
        }

        const auto thread = OpenThread(THREAD_ALL_ACCESS, false, dEvent.dwThreadId);
        if(thread == nullptr)
            throw std::runtime_error("[-] OpenThread failed with code " + std::to_string(GetLastError()) + ".");

        if(!GetThreadContext(thread, &ctx))
            throw std::runtime_error("[-] GetThreadContext failed with code " + std::to_string(GetLastError()) + ".");

        const auto exception = dEvent.u.Exception.ExceptionRecord.ExceptionCode;
        std::string exceptionStr;

        switch (exception) {
            case EXCEPTION_ACCESS_VIOLATION:
                exceptionStr = "EXCEPTION_ACCESS_VIOLATION"; break;
            case EXCEPTION_STACK_OVERFLOW:
                exceptionStr = "EXCEPTION_STACK_OVERFLOW"; break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
                exceptionStr = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED"; break;
            case EXCEPTION_DATATYPE_MISALIGNMENT:
                exceptionStr = "EXCEPTION_DATATYPE_MISALIGNMENT"; break;
            case EXCEPTION_FLT_DENORMAL_OPERAND:
                exceptionStr = "EXCEPTION_FLT_DENORMAL_OPERAND"; break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO:
                exceptionStr = "EXCEPTION_FLT_DIVIDE_BY_ZERO"; break;
            case EXCEPTION_FLT_INEXACT_RESULT:
                exceptionStr = "EXCEPTION_FLT_INEXACT_RESULT"; break;
            case EXCEPTION_FLT_INVALID_OPERATION:
                exceptionStr = "EXCEPTION_FLT_INVALID_OPERATION"; break;
            case EXCEPTION_FLT_OVERFLOW:
                exceptionStr = "EXCEPTION_FLT_OVERFLOW"; break;
            case EXCEPTION_FLT_STACK_CHECK:
                exceptionStr = "EXCEPTION_FLT_STACK_CHECK"; break;
            case EXCEPTION_FLT_UNDERFLOW:
                exceptionStr = "EXCEPTION_FLT_UNDERFLOW"; break;
            case EXCEPTION_ILLEGAL_INSTRUCTION:
                exceptionStr = "EXCEPTION_ILLEGAL_INSTRUCTION"; break;
            case EXCEPTION_IN_PAGE_ERROR:
                exceptionStr = "EXCEPTION_IN_PAGE_ERROR"; break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                exceptionStr = "EXCEPTION_INT_DIVIDE_BY_ZERO"; break;
            case EXCEPTION_INT_OVERFLOW:
                exceptionStr = "EXCEPTION_INT_OVERFLOW"; break;
            case EXCEPTION_INVALID_DISPOSITION:
                exceptionStr = "EXCEPTION_INVALID_DISPOSITION"; break;
            case EXCEPTION_NONCONTINUABLE_EXCEPTION:
                exceptionStr = "EXCEPTION_NONCONTINUABLE_EXCEPTION"; break;
            case EXCEPTION_PRIV_INSTRUCTION:
                exceptionStr = "EXCEPTION_PRIV_INSTRUCTION"; break;
            case EXCEPTION_SINGLE_STEP:
                exceptionStr = "EXCEPTION_SINGLE_STEP"; break;
            case 0x80000003:
                std::cout << "[?] Application crashed. " << std::endl;
                ContinueDebugEvent(dEvent.dwProcessId, dEvent.dwThreadId, DBG_CONTINUE);
                continue;
            default:
                std::cout << "[?] Unknown exception with code 0x" << std::hex << exception << std::endl;
                ContinueDebugEvent(dEvent.dwProcessId, dEvent.dwThreadId, DBG_CONTINUE);
                continue;
        }
        Registers(ctx, exceptionStr, pInfo.hProcess);
        throw std::runtime_error("Found exception: " + exceptionStr);
    }
    CloseHandle(pInfo.hProcess);
}

void changeByBytes(const std::filesystem::path& config, const std::filesystem::path& exeFile) {
    static constexpr unsigned hexMasOneBytes[] = {
        0xAB, 0x75, 0x55, 0x89,
        0x02, 0x01, 0xEF, 0x00,
        0xFF, 0xFFFF, 0x7FFF, 0x8000,
        0x7FFE, 0xFFFFFFFF
    };
    static constexpr unsigned hexMasTwoBytes[] = {
            0xFF, 0xFF, 0x7F, 0xFF,
            0x80, 0x00, 0x7F, 0xFE
    };

    std::ifstream temp(config);
    std::string str((std::istreambuf_iterator<char>(temp)), std::istreambuf_iterator<char>());
    temp.close();

    const auto startPos = str.find("/start");
    if(startPos == std::string::npos)
        throw std::runtime_error("Config file doesn't have '/start' label.");

    const char variant = str[0];
    std::string change = str.substr(1, startPos);
    std::string buffer = str.substr(startPos + 6);

    try {/* Adding incorrect values. */
//        for (auto i = 1; i < change.size(); ++i) {
//            for (unsigned ch: hexMasOneBytes) {
//                results << "Changed sym " << i << ": " << change[i] << " -> " << std::hex << ch << std::endl;
//                change[i] = static_cast<char>(ch);
//
//                std::ofstream output(config);
//                output << variant << change << "/start" << buffer;
//                output.close();
//
//                Execute(exeFile);
//            }
//        }

        std::cerr << "One-byte changes ended. Switching to adding 'start' labels." << std::endl;

        /* Adding '/start' labels. */
        for (auto i = 1; i < startPos / 6; ++i) {
            results << "Adding '/start' label in the beginning " << i << " times." << std::endl;

            const auto newStartPos = startPos - 6 * i;
            change.replace(newStartPos, 6, "/start");

            std::ofstream output(config);
            output << variant << change << "/start" << buffer;
            output.close();

            Execute(exeFile);
        }

        std::cerr << "'/start' label changes ended. Switching to two-bytes changes." << std::endl;

        /* Changing to incorrect values twice. */
        for (auto i = 1; i < change.size(); ++i) {
            for (auto ch: hexMasTwoBytes) {
                results << "Changed sym " << i << ": " << change[i] << " -> " << std::hex << ch << std::endl;
                change[i] = static_cast<char>(ch);

                std::ofstream output(config);
                output << variant << change << "/start" << buffer;
                output.close();

                Execute(exeFile);
            }
        }

    } catch(const std::runtime_error& e) {
        results << "Error was found." << std::endl;
        results << "Error was found." << std::endl;
        std::cerr << "Error was found." << std::endl;
        std::cerr << "Config file contents: '" << change << "/start" << buffer << "'." << std::endl;
    }
}

void run(const std::filesystem::path& config, const std::filesystem::path& exeFile) {
    static constexpr auto info = "Select an option:\n"
                                 "\t1. Automatic testing.\n"
                                 "\t2. Write back.\n"
                                 "\t3. Change bytes.\n"
                                 "\t4. Exit.";

    unsigned choice = 1;
//    while(true){
//        std::cout << info << std::endl;
//        try {
//            std::string choiceStr;
//            std::getline(std::cin, choiceStr);
//            choice = std::stoi(choiceStr) % 4;
//        } catch (const std::invalid_argument &e) {
//            std::cerr << "Please enter a value between 1 and 4." << std::endl;
//            continue;
//        }
//        break;
//    }

    switch(choice) {
        case 1:
            changeByBytes(config, exeFile);
//            Execute(exeFile);
            break;
        case 2:
            break;
        case 3:
            break;
        case 4:
            break;
        default:;
    }
}

int main() {
    static constexpr auto config = "config_8";
    static constexpr auto executable = "vuln8.exe";

    if(!std::filesystem::exists(config))
        throw std::runtime_error("[-] Configuration results is not found.");
    if(!std::filesystem::exists(executable))
        throw std::runtime_error("[-] Executable results is not found.");

    results.open(ResultsFilename);
    run({config}, {executable});
    return 0;
}
