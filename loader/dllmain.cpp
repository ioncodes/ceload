#include <fstream>
#include <vector>
#include <array>
#include <Windows.h>
#include <Psapi.h>

// Note: The A, B, C and D values have been extracted from API Monitor

const wchar_t CE_EXECUTABLE[]        = L"C:\\Program Files\\Cheat Engine 7.3\\cheatengine-x86_64.exe";
const wchar_t CE_DRIVER[]            = L"C:\\Program Files\\Cheat Engine 7.3\\dbk64.sys";
const wchar_t CE_REG_PATH[]          = L"SYSTEM\\CurrentControlSet\\Services\\CEDRIVER73";
const wchar_t CE_DISPLAY_NAME[]      = L"CEDRIVER73";
const wchar_t CE_OBJECT_PATH[]       = L"\\\\.\\CEDRIVER73";
const wchar_t DRIVER_STRING[]        = L"\\Device\\CEDRIVER73";                            // A
const wchar_t DEVICE_STRING[]        = L"\\DosDevices\\CEDRIVER73";                        // B
const wchar_t PROCESS_EVENT_STRING[] = L"\\BaseNamedObjects\\DBKProcList60";               // C
const wchar_t THREAD_EVENT_STRING[]  = L"\\BaseNamedObjects\\DBKThreadList60";             // D

static constexpr std::uint32_t ctl_code(
    std::uint32_t device_type, std::uint32_t function,
    std::uint32_t method, std::uint32_t access)
{
    return ((device_type) << 16) | ((access) << 14) | ((function) << 2) | method;
}

// Example IOCTL to read virtual memory
enum class ioctl : std::uint32_t
{
    read_memory = ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
};

struct read_memory_t
{
    std::uint64_t process_id;
    std::uint64_t address;
    std::uint16_t size;
};

std::vector<std::uint8_t> read_executable()
{
    std::ifstream in(CE_EXECUTABLE, std::ios::binary);

    in.seekg(0, std::ios_base::end);
    std::streampos length = in.tellg();
    in.seekg(0, std::ios_base::beg);

    std::vector<std::uint8_t> buffer(length);
    in.read((char*)buffer.data(), length);

    return buffer;
}

void load_driver()
{
    // Start and configure CheatEngine
    const auto manager = OpenSCManagerW(nullptr, nullptr, GENERIC_READ | GENERIC_WRITE);
    const auto service = OpenServiceW(manager, L"CEDRIVER73", SERVICE_ALL_ACCESS);
    ChangeServiceConfigW(
        service, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        CE_DRIVER, nullptr, nullptr, nullptr, nullptr, nullptr, CE_DISPLAY_NAME);

    // Prepare the registry for driver load
    HKEY service_key;
    RegOpenKeyExW(HKEY_LOCAL_MACHINE, CE_REG_PATH, 0, KEY_ALL_ACCESS, &service_key);
    RegSetKeyValueW(service_key, nullptr, L"A", REG_SZ, DRIVER_STRING, sizeof(DRIVER_STRING));
    RegSetKeyValueW(service_key, nullptr, L"B", REG_SZ, DEVICE_STRING, sizeof(DEVICE_STRING));
    RegSetKeyValueW(service_key, nullptr, L"C", REG_SZ, PROCESS_EVENT_STRING, sizeof(PROCESS_EVENT_STRING));
    RegSetKeyValueW(service_key, nullptr, L"D", REG_SZ, THREAD_EVENT_STRING, sizeof(THREAD_EVENT_STRING));
    RegCloseKey(service_key);

    // Stop the service if it's already running
    SERVICE_STATUS service_status{};
    ControlService(service, SERVICE_QUERY_STATUS, &service_status);

    if (service_status.dwCurrentState == SERVICE_RUNNING)
        ControlService(service, SERVICE_CONTROL_STOP, &service_status);

    // Start the service
    StartServiceW(service, 0, nullptr);
    CloseServiceHandle(service);

    // Wipe the registry values. Unsure why, just mimick what CheatEngine does
    RegDeleteValueW(service_key, L"A");
    RegDeleteValueW(service_key, L"B");
    RegDeleteValueW(service_key, L"C");
    RegDeleteValueW(service_key, L"D");

    // Allocate a console to to print debug messages
    AllocConsole();
    freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);

    // Read the original executable into a std::vector
    auto buffer = read_executable();

    // Cast the buffer to the corresponding PE structures for parsing
    const auto image = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
    const auto base = reinterpret_cast<std::uintptr_t>(image);
    const auto headers = reinterpret_cast<PIMAGE_NT_HEADERS>(base + image->e_lfanew);
    const auto sections = IMAGE_FIRST_SECTION(headers);

    for (int i = 0; i < headers->FileHeader.NumberOfSections; i++)
    {
        // Dismiss all sections other than .text
        if (strcmp((char*)sections[i].Name, ".text") == 0)
        {
            const auto dst = reinterpret_cast<std::uint8_t*>(0x00400000 + sections[i].VirtualAddress);
            const auto src = reinterpret_cast<std::uint8_t*>(base + sections[i].PointerToRawData);
            const auto len = sections[i].SizeOfRawData;

            // Copy the original bytes from the on-disk file into the current process
            DWORD old_flags;
            VirtualProtect(dst, len, PAGE_READWRITE, &old_flags);
            for (auto i = 0; i < len; i++)
                dst[i] = src[i];

            // This line of code is the integrity check performed by the driver
            // If match_count == len, we will successfully pass the driver's check
            const auto match_count = RtlCompareMemory(src, dst, len);
            printf("RtlCompareMemory(%p, %p) == %ld == %ld\n", src, dst, match_count, len);

            break;
        }
    }

    // Grab a handle to the driver
    const auto handle = CreateFileW(
        CE_OBJECT_PATH, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);

    // If the handle is valid we successfully bypassed all checks
    if (handle != INVALID_HANDLE_VALUE)
    {
        // Example: Read out MZ from current process from kernel
        std::array<std::uint8_t, 2> buffer;

        read_memory_t request
        {
            GetCurrentProcessId(),
            0x0000000000400000,
            2
        };

        DWORD bytes_read;
        DeviceIoControl(
            handle, static_cast<std::uint32_t> (ioctl::read_memory),
            &request, sizeof(read_memory_t),
            buffer.data(), 2,
            &bytes_read, nullptr);

        printf("Trying to read PE header from kernel: %c%c\n", buffer[0], buffer[1]);

        // Create a message box to halt the process. This gives us time to inspect the console
        MessageBoxA(NULL, "Successfully got handle to dbk64.sys", "ayy", NULL);

        CloseHandle(handle);
    }

    // Cleanly exit the process
    FreeConsole();
    ExitProcess(0);
}

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        load_driver();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

