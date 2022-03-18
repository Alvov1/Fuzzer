#include <iostream>
#include <fstream>
#include <string>
#include <streambuf>
#include <filesystem>

#include <Windows.h>

using PathPair = std::pair<const std::filesystem::path&, const std::filesystem::path&>;
static constexpr auto ResultsFilename = "Results.txt";
static std::ofstream results;

inline void ReturnDefaultVersion() {
    if (CopyFileA(path_config_default, path_config, false) == false)
        throw std::runtime_error("[-] CopyFileA failed with code " + std::to_string(GetLastError()));
}

/**/void Registers(CONTEXT &ctx, const std::string &ExceptionStr, HANDLE hProcess) {
    static unsigned char buffer[4048] = {0};

    results << std::setfill('0');

    results << "Exception: " << ExceptionStr << "." << std::endl;
    results << "EAX - 0x" << reinterpret_cast<void *>(ctx.Eax) << ", ESP - 0x" << reinterpret_cast<void *>(ctx.Esp)
            << "." << std::endl;
    results << "EBX - 0x" << reinterpret_cast<void *>(ctx.Ebx) << ", EBP - 0x" << reinterpret_cast<void *>(ctx.Ebp)
            << "." << std::endl;
    results << "ECX - 0x" << reinterpret_cast<void *>(ctx.Ecx) << ", EDI - 0x" << reinterpret_cast<void *>(ctx.Edi)
            << "." << std::endl;
    results << "EDX - 0x" << reinterpret_cast<void *>(ctx.Edx) << ", ESI - 0x" << reinterpret_cast<void *>(ctx.Esi)
            << "." << std::endl;
    results << "EIP - 0x" << reinterpret_cast<void *>(ctx.Eip) << ", Flags - 0x" << reinterpret_cast<void *>(ctx.EFlags)
            << "." << std::endl;

    SIZE_T recSize = 0;
    if (ReadProcessMemory(hProcess, reinterpret_cast<void *>(ctx.Esp), buffer, sizeof(buffer), &recSize) == 0)
        std::cout << "[-] ReadProcessMemory failed with code " << GetLastError() << std::endl;

    std::cout << "Read " << recSize << " bytes from stack." << std::endl;
    results << "Read " << recSize << " bytes from stack." << std::endl;

    for (auto i = 0; i < recSize; ++i) {
        if (i % 4 == 0)
            results << "0x" << reinterpret_cast<void *>(ctx.Esp + i) << " - ";

        results << std::setw(2) << static_cast<int>(buffer[i]);

        if (i % 4 == 3) results << std::endl;
    }
    results << std::endl;

    ReturnDefaultVersion();
}
/**/void Execute(const std::filesystem::path &exeFile) {
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
        Registers(ctx, exceptionStr, pInfo.hProcess);
        throw std::runtime_error("Found exception: " + exceptionStr);
    }
    CloseHandle(pInfo.hProcess);
}
/**/void Show_Bytes(const std::filesystem::path& configFile) {
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

void ChangeByte(const PathPair& paths) {
    FILE *p_conf_file = fopen(path_config, "r+b");
    if (p_conf_file == nullptr) {
        cout << "fopen error" << endl;
        return;
    }
    char _res[5] = {0};

    // установить на начало файла
    fseek(p_conf_file, offset, SEEK_SET);
    fputc(new_value, p_conf_file);
    fclose(p_conf_file);
}

void ChangeFewBytes(const PathPair& paths) {
    FILE *pConfFile = fopen(path_config, "r+b");
    if (pConfFile == nullptr) {
        cout << "fopen error" << endl;
        return;
    }

    char _res[5] = {0};
    //установка на offset с начала файла
    fseek(pConfFile, offset, SEEK_SET);

    for (int i = 0; i < count; i++) {
        fputc(new_value, pConfFile); //вставлять несколько символов
    }

    fclose(pConfFile);
}

void WriteToEnd(const PathPair& paths) {
    FILE *p_conf_file = fopen(path_config, "r+b");
    if (p_conf_file == nullptr) {
        cout << "fopen error" << endl;
        return;
    }
    //устновить на конец файла
    fseek(p_conf_file, 0, SEEK_END);

    for (int i = 0; i < count; i++) {
        fputc(new_value, p_conf_file);
    }

    fclose(p_conf_file);
}

void RunProgram(const PathPair& paths) {
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    DEBUG_EVENT debug_event = {0};
    HANDLE thread;
    CONTEXT cont;

    BOOL status;

    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    status = CreateProcessA(path_vuln, NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi);
    if (status == false) {
        cout << "CreateProcess fail: " << std::dec << GetLastError() << endl;
        return;
    }

    while (true) {
        // ожидаем событие отладки
        status = WaitForDebugEvent(&debug_event, 500);
        if (status == false) {
            if (GetLastError() != ERROR_SEM_TIMEOUT)
                cout << "WaitForDebugEvent fail: " << dec << GetLastError() << endl;
            break;
        }

        // смотрим код события
        if (debug_event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT) {
            // если это не исключение - продолжаем ожидать
            ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
            continue;
        }

        // получаем хэндл потока, в котором произошло событие отладки
        thread = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
        if (thread == NULL) {
            cout << "OpenThread failed: " << dec << GetLastError() << endl;
            break;
        }

        cont.ContextFlags = CONTEXT_FULL;

        // по хэндлу получаем его контекст
        status = GetThreadContext(thread, &cont);
        if (status == false) {
            cout << "GetThreadContext failed: " << dec << GetLastError() << endl;
            CloseHandle(thread);
            break;
        }


        switch (debug_event.u.Exception.ExceptionRecord.ExceptionCode) {
            case EXCEPTION_ACCESS_VIOLATION:
                GetRegistersState(&cont, "EXCEPTION_ACCESS_VIOLATION", pi.hProcess);
                break;
            case EXCEPTION_STACK_OVERFLOW:
                GetRegistersState(&cont, "EXCEPTION_STACK_OVERFLOW", pi.hProcess);
                break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
                GetRegistersState(&cont, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED", pi.hProcess);
                break;
            case EXCEPTION_DATATYPE_MISALIGNMENT:
                GetRegistersState(&cont, "EXCEPTION_DATATYPE_MISALIGNMENT", pi.hProcess);
                break;
            case EXCEPTION_FLT_DENORMAL_OPERAND:
                GetRegistersState(&cont, "EXCEPTION_FLT_DENORMAL_OPERAND", pi.hProcess);
                break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO:
                GetRegistersState(&cont, "EXCEPTION_FLT_DIVIDE_BY_ZERO", pi.hProcess);
                break;
            case EXCEPTION_FLT_INEXACT_RESULT:
                GetRegistersState(&cont, "EXCEPTION_FLT_INEXACT_RESULT", pi.hProcess);
                break;
            case EXCEPTION_FLT_INVALID_OPERATION:
                GetRegistersState(&cont, "EXCEPTION_FLT_INVALID_OPERATION", pi.hProcess);
                break;
            case EXCEPTION_FLT_OVERFLOW:
                GetRegistersState(&cont, "EXCEPTION_FLT_OVERFLOW", pi.hProcess);
                break;
            case EXCEPTION_FLT_STACK_CHECK:
                GetRegistersState(&cont, "EXCEPTION_FLT_STACK_CHECK", pi.hProcess);
                break;
            case EXCEPTION_FLT_UNDERFLOW:
                GetRegistersState(&cont, "EXCEPTION_FLT_UNDERFLOW", pi.hProcess);
                break;
            case EXCEPTION_ILLEGAL_INSTRUCTION:
                GetRegistersState(&cont, "EXCEPTION_ILLEGAL_INSTRUCTION", pi.hProcess);
                break;
            case EXCEPTION_IN_PAGE_ERROR:
                GetRegistersState(&cont, "EXCEPTION_IN_PAGE_ERROR", pi.hProcess);
                break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                GetRegistersState(&cont, "EXCEPTION_INT_DIVIDE_BY_ZERO", pi.hProcess);
            case EXCEPTION_INT_OVERFLOW:
                GetRegistersState(&cont, "EXCEPTION_INT_OVERFLOW", pi.hProcess);
                break;
            case EXCEPTION_INVALID_DISPOSITION:
                GetRegistersState(&cont, "EXCEPTION_INVALID_DISPOSITION", pi.hProcess);
                break;
            case EXCEPTION_NONCONTINUABLE_EXCEPTION:
                GetRegistersState(&cont, "EXCEPTION_NONCONTINUABLE_EXCEPTION", pi.hProcess);
                break;
            case EXCEPTION_PRIV_INSTRUCTION:
                GetRegistersState(&cont, "EXCEPTION_PRIV_INSTRUCTION", pi.hProcess);
                break;
            case EXCEPTION_SINGLE_STEP:
                GetRegistersState(&cont, "EXCEPTION_SINGLE_STEP", pi.hProcess);
                break;
            default:
                cout << "Unknown exception: " << hex << debug_event.u.Exception.ExceptionRecord.ExceptionCode << endl;
                ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
        }
    }

    CloseHandle(pi.hProcess);
}

void Find_Dividing_Symbol(char symbol) {
    int position = -1;
    int counter = 0;
    int size;
    FILE *pConfFile = fopen(path_config, "rb");
    if (pConfFile == nullptr) {
        cout << "fopen error" << endl;
        return;
    }

    fseek(pConfFile, 0, SEEK_END);
    size = ftell(pConfFile);
    rewind(pConfFile);

    for (int i = 0; i < size; i++) {
        if (fgetc(pConfFile) == symbol) {
            counter++;
            position = i;
        }
    }
    if (position == -1) cout << "no symbols " << symbol << endl;
    else
        cout << "symb : " << symbol << "  count : " << counter << "  posishion : " << position << endl;
    fclose(pConfFile);
}

void AutoFuzzing(const PathPair& paths) {
    static constexpr unsigned values[] = {
            0x00, 0xFF, 0xFF / 2, 0xFF / 2 - 1, 0xFF / 2 + 1,
            0x0000, 0xFFFF, 0xFFFF / 2, 0xFFFF / 2 - 1,
            0xFFFF / 2 + 1, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF / 2,
            0xFFFFFFFF / 2 - 1, 0xFFFFFFFF / 2 + 1,
    };

    switch (mode) {
        case 1:
            for (int i = 1; i < HEADER; i++) {
                ChangeByte(i, new_value);
                RunProgram();
                ReturnDefaultVersion();
            }
            break;
        case 2:
            for (int i = 2; i < HEADER; i += 2) {
                ChangeByte(i, new_value >> 8);
                ChangeByte(i + 1, (unsigned char) new_value);
                RunProgram();
                ReturnDefaultVersion();
            }
            break;
        case 3:
            for (int i = 4; i < HEADER; i += 4) {
                ChangeByte(i, new_value >> 24);
                ChangeByte(i + 1, new_value >> 16);
                ChangeByte(i + 2, new_value >> 8);
                ChangeByte(i + 3, (unsigned char) new_value);
                RunProgram();
                ReturnDefaultVersion();
            }
            break;
        default:
            cout << "Invalid command" << endl;
    }
}

void ProcessRequest(const PathPair& paths, unsigned command) {
    static constexpr char divisors[] = {',', ':', '=', ';'};
    switch (command) {
        case 0:
            ChangeByte(paths);
            break;
        case 2:
            ChangeFewBytes(paths);
            break;
        case 3:
            WriteToEnd(paths);
            break;
        case 4:
            AutoFuzzing(paths);
            break;
        case 5:
            for(auto div : divisors)
                Find_Dividing_Symbol(div);
            break;
        case 6:
            RunProgram(paths);
            break;
        case 7:
            Show_Bytes(paths);
            break;
        default:;
    }
}

void Run(const std::filesystem::path& conf, const std::filesystem::path& exec) {
    static constexpr auto helpInfo = "\t0. Change byte.\n\t1. Change bytes.\n\t2. Write."
     "\n\t3. Auto fuzzing.\n\t4. Find dividing symbols.\n\t5. Execute.\n\t6. Show bytes.\n\t7. Exit.";

    while (true) {
        std::cout << helpInfo << std::endl;
        unsigned choice = 0;
        try {
            std::string line;
            std::getline(std::cin, line);
            choice = std::stoi(line) % 7;
        } catch(const std::invalid_argument& e) {
            std::cerr << "Please enter an appropriate value." << std::endl;
            continue;
        }

        ProcessRequest({conf, exec}, choice);
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

    results.open(ResultsFilename);
    Run(configPath, exePath);
    return 0;
}

