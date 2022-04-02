#include <iostream>
#include <fstream>
#include <string>
#include <streambuf>
#include <filesystem>
#include <limits>
#include <iterator>

#include <Windows.h>

unsigned GetNumber(unsigned upperBound, unsigned LowerBound = 0) {
    unsigned value = 0;
    std::string line;
    while(true) {
        std::getline(std::cin, line);
        try {
            value = std::stoul(line) % upperBound;
        } catch(const std::invalid_argument& e) {
            std::cout << "Please enter a number between " << LowerBound
                      << " and " << upperBound << "." << std::endl;
            continue;
        }
        break;
    }

    return value;
}
void CheckRegistersState(CONTEXT &ctx, const std::string &ExceptionStr, HANDLE hProcess) {
    static unsigned char buffer[4048] = {0};

    std::cout << std::setfill('0');

    std::cout << "Exception: " << ExceptionStr << "." << std::endl;
    std::cout << "EAX - 0x" << reinterpret_cast<void *>(ctx.Eax) << ", ESP - 0x" << reinterpret_cast<void *>(ctx.Esp)
            << "." << std::endl;
    std::cout << "EBX - 0x" << reinterpret_cast<void *>(ctx.Ebx) << ", EBP - 0x" << reinterpret_cast<void *>(ctx.Ebp)
            << "." << std::endl;
    std::cout << "ECX - 0x" << reinterpret_cast<void *>(ctx.Ecx) << ", EDI - 0x" << reinterpret_cast<void *>(ctx.Edi)
            << "." << std::endl;
    std::cout << "EDX - 0x" << reinterpret_cast<void *>(ctx.Edx) << ", ESI - 0x" << reinterpret_cast<void *>(ctx.Esi)
            << "." << std::endl;
    std::cout << "EIP - 0x" << reinterpret_cast<void *>(ctx.Eip) << ", Flags - 0x" << reinterpret_cast<void *>(ctx.EFlags)
            << "." << std::endl;

    SIZE_T recSize = 0;
    if (ReadProcessMemory(hProcess, reinterpret_cast<void *>(ctx.Esp), buffer, sizeof(buffer), &recSize) == 0)
        std::cout << "[-] ReadProcessMemory failed with code " << GetLastError() << std::endl;

    std::cout << "Read " << recSize << " bytes from stack." << std::endl;
    std::cout << "Read " << recSize << " bytes from stack." << std::endl;

    for (auto i = 0; i < recSize; ++i) {
        if (i % 4 == 0)
            std::cout << "0x" << reinterpret_cast<void *>(ctx.Esp + i) << " - ";

        std::cout << std::setw(2) << static_cast<int>(buffer[i]);

        if (i % 4 == 3) std::cout << std::endl;
    }
    std::cout << std::endl;
}
void Execute(const std::filesystem::path &exeFile) {
    STARTUPINFO sInfo{};
    sInfo.cb = sizeof(sInfo);
    PROCESS_INFORMATION pInfo;

    std::cout << "[+] Tracking process '" << exeFile.string().c_str() << "'." << std::endl;

    if (!CreateProcessA((LPCSTR) exeFile.string().c_str(), nullptr, nullptr, nullptr,
                        false, DEBUG_PROCESS, nullptr, nullptr, (LPSTARTUPINFOA) &sInfo, &pInfo))
        throw std::runtime_error("[-] Process creation failed with code " + std::to_string(GetLastError()) + ".");

    DEBUG_EVENT dEvent = {0};
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    while (true) {
        if (!WaitForDebugEvent(&dEvent, 500)) {
            if (GetLastError() != ERROR_SEM_TIMEOUT)
                throw std::runtime_error(
                        "[-] WaitForDebugEvent failed with code " + std::to_string(GetLastError()) + ".");
            break;
        }
        if (dEvent.dwDebugEventCode != EXCEPTION_DEBUG_EVENT) {
            ContinueDebugEvent(dEvent.dwProcessId, dEvent.dwThreadId, DBG_CONTINUE);
            continue;
        }

        const auto thread = OpenThread(THREAD_ALL_ACCESS, false, dEvent.dwThreadId);
        if (thread == nullptr)
            throw std::runtime_error("[-] OpenThread failed with code " + std::to_string(GetLastError()) + ".");

        if (!GetThreadContext(thread, &ctx))
            throw std::runtime_error("[-] GetThreadContext failed with code " + std::to_string(GetLastError()) + ".");

        const auto exception = dEvent.u.Exception.ExceptionRecord.ExceptionCode;
        std::string exceptionStr;

        switch (exception) {
            case EXCEPTION_ACCESS_VIOLATION:
                exceptionStr = "EXCEPTION_ACCESS_VIOLATION";
                break;
            case EXCEPTION_STACK_OVERFLOW:
                exceptionStr = "EXCEPTION_STACK_OVERFLOW";
                break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
                exceptionStr = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
                break;
            case EXCEPTION_DATATYPE_MISALIGNMENT:
                exceptionStr = "EXCEPTION_DATATYPE_MISALIGNMENT";
                break;
            case EXCEPTION_FLT_DENORMAL_OPERAND:
                exceptionStr = "EXCEPTION_FLT_DENORMAL_OPERAND";
                break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO:
                exceptionStr = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
                break;
            case EXCEPTION_FLT_INEXACT_RESULT:
                exceptionStr = "EXCEPTION_FLT_INEXACT_RESULT";
                break;
            case EXCEPTION_FLT_INVALID_OPERATION:
                exceptionStr = "EXCEPTION_FLT_INVALID_OPERATION";
                break;
            case EXCEPTION_FLT_OVERFLOW:
                exceptionStr = "EXCEPTION_FLT_OVERFLOW";
                break;
            case EXCEPTION_FLT_STACK_CHECK:
                exceptionStr = "EXCEPTION_FLT_STACK_CHECK";
                break;
            case EXCEPTION_FLT_UNDERFLOW:
                exceptionStr = "EXCEPTION_FLT_UNDERFLOW";
                break;
            case EXCEPTION_ILLEGAL_INSTRUCTION:
                exceptionStr = "EXCEPTION_ILLEGAL_INSTRUCTION";
                break;
            case EXCEPTION_IN_PAGE_ERROR:
                exceptionStr = "EXCEPTION_IN_PAGE_ERROR";
                break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                exceptionStr = "EXCEPTION_INT_DIVIDE_BY_ZERO";
                break;
            case EXCEPTION_INT_OVERFLOW:
                exceptionStr = "EXCEPTION_INT_OVERFLOW";
                break;
            case EXCEPTION_INVALID_DISPOSITION:
                exceptionStr = "EXCEPTION_INVALID_DISPOSITION";
                break;
            case EXCEPTION_NONCONTINUABLE_EXCEPTION:
                exceptionStr = "EXCEPTION_NONCONTINUABLE_EXCEPTION";
                break;
            case EXCEPTION_PRIV_INSTRUCTION:
                exceptionStr = "EXCEPTION_PRIV_INSTRUCTION";
                break;
            case EXCEPTION_SINGLE_STEP:
                exceptionStr = "EXCEPTION_SINGLE_STEP";
                break;
            case 0x80000003:
                std::cout << "[?] Application crashed. " << std::endl;
                ContinueDebugEvent(dEvent.dwProcessId, dEvent.dwThreadId, DBG_CONTINUE);
                continue;
            default:
                std::cout << "[?] Unknown exception with code 0x" << std::hex << exception << std::endl;
                ContinueDebugEvent(dEvent.dwProcessId, dEvent.dwThreadId, DBG_CONTINUE);
                continue;
        }
        CheckRegistersState(ctx, exceptionStr, pInfo.hProcess);
        CloseHandle(pInfo.hProcess);
        throw std::runtime_error("Found exception: " + exceptionStr);
    }
    CloseHandle(pInfo.hProcess);
}
void ShowBytes(const std::filesystem::path& configFile) {
    std::ifstream input(configFile, std::ios::binary);
    if(input.fail())
        throw std::runtime_error("[-] ShowBytes: failed to open the config file.");
    std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());

    std::cout << "\t";
    for(auto i = 0; i < 10; ++i)
        std::cout << std::setw(3) << std::setfill('0') << i << " ";

    unsigned count = 0;
    for(auto& ch : content) {
        if(count++ % 10 == 0)
            std::cout << std::endl << std::setw(3) << std::setfill('0') << count << ":\t";
        std::cout << std::setw(3) << std::setfill('0') << std::hex << std::uppercase << ch << " ";
    }
}
void ChangeByte(const std::filesystem::path& config) {
    std::ofstream output(config, std::ios::app);
    if(output.fail())
        throw std::runtime_error("[-] ChangeByte: failed to open the config file.");
    const auto fileSize = output.tellp();

    std::cout << "Enter the offset in the file." << std::endl;
    const auto offset = GetNumber(fileSize);
    std::cout << "Enter the byte to input." << std::endl;
    const unsigned char byte = GetNumber(UCHAR_MAX);

    output.seekp(offset);
    output << byte;
}
void ChangeByte(unsigned offset, unsigned char byte, const std::filesystem::path& config) {
    std::ofstream output(config, std::ios::app);
    if(output.fail())
        throw std::runtime_error("[-] ChangeByte: failed to open the config file.");
    const auto fileSize = output.tellp();

    output.seekp(offset);
    output << byte;
}
void ChangeFewBytes(const std::filesystem::path& config) {
    std::ofstream output(config, std::ios::app);
    if(output.fail())
        throw std::runtime_error("[-] ChangeFewBytes: failed to open the config file.");
    const auto fileSize = output.tellp();

    std::cout << "Enter the offset in the file." << std::endl;
    const auto offset = GetNumber(fileSize);
    std::cout << "Enter the byte to input." << std::endl;
    const unsigned char byte = GetNumber(UCHAR_MAX);
    std::cout << "Enter the number of bytes." << std::endl;
    const unsigned number = GetNumber(UINT_MAX);

    output.seekp(offset);
    for(auto i = 0; i < number; ++i)
        output << byte;
}
void WriteToEnd(const std::filesystem::path& config) {
    std::ofstream output(config, std::ios::app);
    if(output.fail())
        throw std::runtime_error("[-] ChangeByte: failed to open the config file.");
    output.seekp(-1, std::ios::cur);
    std::cout << "Enter the byte to input." << std::endl;
    const unsigned char byte = GetNumber(UCHAR_MAX);
    std::cout << "Enter the number of bytes." << std::endl;
    const auto number = GetNumber(UINT_MAX);

    for(auto i = 0; i < number; ++i)
        output << byte;
}
void DividingSymbols(const std::filesystem::path& config) {
    static constexpr char symbols[] = {',', ':', '=', ';'};

    std::ifstream file(config);
    if(file.fail())
        throw std::runtime_error("[-] ChangeByte: failed to open the config file.");

    struct S{
        unsigned count = 0;
        unsigned lastPos = 0;
    } Metrics[sizeof(symbols)];

    char c = 0;
    file >> c;
    for(auto pos = 0; !file.eof(); file >> c, ++pos)
        for(auto i = 0; i < sizeof(symbols); ++i)
            if(c == symbols[i]) {
                Metrics[i].count++;
                Metrics[i].lastPos = pos;
            }

    for(auto i = 0; i < sizeof(symbols); ++i)
        std::cout << "Symbol " << symbols[i] << ": founded " << Metrics[i].count
        << " and last position is " << Metrics[i].lastPos << "." << std::endl;
}
void AutoFuzzing(const std::filesystem::path& conf, const std::filesystem::path& exec) {
    static constexpr unsigned char OneByteValues[] = {
            0x00, 0xFF, 0xFF / 2, 0xFF / 2 - 1, 0xFF / 2 + 1};
    static constexpr unsigned TwoByteValues[] = {
            0x0000, 0xFFFF, 0xFFFF / 2, 0xFFFF / 2 - 1, 0xFFFF / 2 + 1};
    static constexpr unsigned ThreeByteValues[] = {
            0x00000000, 0xFFFFFFFF, 0xFFFFFFFF / 2, 0xFFFFFFFF / 2 - 1, 0xFFFFFFFF / 2 + 1,};

    std::ifstream file(conf);
    if(file.fail())
        throw std::runtime_error("[-] AutoFuzzing: failed to open the config file.");
    std::string str((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    const auto startLabelPosition = str.find("/start") + 6;

    std::filesystem::path newPath = conf;
    newPath.replace_filename("temp");
    std::filesystem::copy_file(conf, newPath, std::filesystem::copy_options::overwrite_existing);

    try {
        std::cerr << "Adding one-byte symbols." << std::endl;
        for (auto &ch: OneByteValues) {
            for (auto offset = 1; offset < startLabelPosition; ++offset) {
                ChangeByte(offset, ch, conf);
                Execute(exec);
                std::filesystem::copy_file(newPath, conf, std::filesystem::copy_options::overwrite_existing);
            }
        }

        std::cerr << "Adding two-byte symbols." << std::endl;
        for (auto &ch: TwoByteValues) {
            for (auto offset = 2; offset < startLabelPosition; offset += 2) {
                ChangeByte(offset, ch >> 8, conf);
                ChangeByte(offset + 1, static_cast<unsigned char>(ch), conf);
                Execute(exec);
                std::filesystem::copy_file(newPath, conf, std::filesystem::copy_options::overwrite_existing);
            }
        }

        std::cerr << "Adding three-byte symbols." << std::endl;
        for (auto &ch: ThreeByteValues) {
            for (auto offset = 4; offset < startLabelPosition; offset += 4) {
                ChangeByte(offset, ch >> 24, conf);
                ChangeByte(offset + 1, ch >> 16, conf);
                ChangeByte(offset + 2, ch >> 8, conf);
                ChangeByte(offset + 3, static_cast<unsigned char>(ch), conf);
                Execute(exec);
                std::filesystem::copy_file(newPath, conf, std::filesystem::copy_options::overwrite_existing);
            }
        }
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
}

void Run(const std::filesystem::path& config, const std::filesystem::path& exeFile) {
    static constexpr auto helpInfo = "Options:\n\t0. Change byte.\n\t1. Change bytes.\n\t2. Write."
     "\n\t3. Auto fuzzing.\n\t4. Find dividing symbols.\n\t5. Execute.\n\t6. Show bytes.\n\t7. Exit.";

    while (true) {
        std::cout << helpInfo << std::endl;
        const auto choice = GetNumber(8);

        switch(choice) {
            case 0:
                ChangeByte(config);
                break;
            case 1:
                ChangeFewBytes(config);
                break;
            case 2:
                WriteToEnd(config);
                break;
            case 3:
                AutoFuzzing(config, exeFile);
                break;
            case 4:
                DividingSymbols(config);
                break;
            case 5:
                try {
                    Execute(exeFile);
                } catch(const std::exception& e) {
                    std::cout << e.what() << std::endl;
                }
                break;
            case 6:
                ShowBytes(config);
                break;
            case 7:
                return;
            default:;
        }
    }
}

int main() {
    static constexpr auto configName = "config_8";
    static constexpr auto executable = "vuln8.exe";

    const std::filesystem::path configPath(configName);
    const std::filesystem::path exePath(executable);

    if(!std::filesystem::exists(configPath))
        throw std::runtime_error("[-] Config file is not found.");
    if(!std::filesystem::exists(exePath))
        throw std::runtime_error("[-] Executable file is not found.");

    Run(configPath, exePath);
    return 0;
}

