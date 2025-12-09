#define INITGUID
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <atomic>
#include <algorithm>
#include <unordered_map>
#include <mutex>

// Microsoft-Windows-DxgKrnl provider GUID
// {802ec45a-1e99-4b83-9920-87c98277ba9d}
DEFINE_GUID(DxgKrnlGuid,
    0x802ec45a, 0x1e99, 0x4b83, 0x99, 0x20, 0x87, 0xc9, 0x82, 0x77, 0xba, 0x9d);

// Microsoft-Windows-Kernel-Process provider GUID
// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
DEFINE_GUID(KernelProcessGuid,
    0x22FB2CD6, 0x0E7B, 0x422B, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16);

// Kernel Process event IDs
enum KernelProcessEventIds {
    ProcessStart = 1,
    ProcessStop = 2,
    ProcessRundown = 15,  // DCStart - enumerates already-running processes
};

// Session name for our trace
static const wchar_t* SESSION_NAME = L"GpuMemoryTrackerSession";

// Known DxgKrnl event IDs for memory tracking
// Validated through live ETW capture on Windows 11
enum DxgKrnlEventIds {
    // AdapterAllocation events (keyword: Resource 0x40)
    AdapterAllocation_Start = 33,
    AdapterAllocation_Stop = 34,
    AdapterAllocation_DCStart = 35,

    // DeviceAllocation events (keyword: Resource 0x40)
    DeviceAllocation_Start = 36,
    DeviceAllocation_Stop = 37,
    DeviceAllocation_DCStart = 38,

    // Other allocation events
    TerminateAllocation = 39,
    ProcessTerminateAllocation = 40,

    // ReferenceAllocations (keyword: References 0x4) - frequently seen
    ReferenceAllocations = 43,

    RenameAllocation_Start = 64,
    RenameAllocation_Stop = 65,

    // Memory events (keyword: Memory)
    ProcessAllocation_Start = 225,
    ProcessAllocation_Stop = 226,

    // ProcessAllocationDetails (keyword: Resource 0x40)
    ProcessAllocationDetails_Start = 288,
    ProcessAllocationDetails_Stop = 289,

    // RecycleRangeTracking (keyword: 0x80) - memory range management
    RecycleRangeTracking_Info1 = 301,
    RecycleRangeTracking_Info2 = 302,
    RecycleRangeTracking_Info3 = 303,

    // VidMm events (keyword: References 0x4)
    VidMmMakeResident = 320,
    VidMmEvict = 321,
    VidMmMakeResident_DCStart = 374,
};

// Global state
static std::atomic<int64_t> g_totalMemoryBytes{ 0 };
static std::wstring g_targetProcessName;
static DWORD g_targetPid = 0;
static std::atomic<bool> g_targetProcessRunning{ false };
static TRACEHANDLE g_sessionHandle = 0;
static TRACEHANDLE g_traceHandle = INVALID_PROCESSTRACE_HANDLE;
static bool g_verbose = false;
static bool g_dumpAll = false;
static FILE* g_logFile = nullptr;

// Track allocations by handle to know size on free
// g_adapterAllocMap: maps AdapterAllocation handle to size (temporary, until DeviceAllocation links it)
// g_vidMmAllocMap: maps hVidMmAlloc (from DeviceAllocation, used in TerminateAllocation) to size
static std::unordered_map<ULONGLONG, ULONGLONG> g_adapterAllocMap;
static std::unordered_map<ULONGLONG, ULONGLONG> g_vidMmAllocMap;
static std::mutex g_mapMutex;

// Track last AdapterAllocation per process for linking to subsequent DeviceAllocation
struct LastAlloc {
    ULONGLONG handle;
    ULONGLONG size;
};
static std::unordered_map<DWORD, LastAlloc> g_lastAdapterAlloc;

std::wstring ToLower(const std::wstring& str) {
    std::wstring result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

std::wstring GetFileName(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        return path.substr(pos + 1);
    }
    return path;
}

std::wstring GetProcessName(DWORD processId) {
    std::wstring processName;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess) {
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            processName = GetFileName(path);
        }
        CloseHandle(hProcess);
    }
    return processName;
}

DWORD FindProcessByName(const wchar_t* name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}

void FormatBytes(int64_t bytes, wchar_t* buffer, size_t bufferSize) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
    int unitIndex = 0;
    double value = (double)(bytes < 0 ? -bytes : bytes);

    while (value >= 1024.0 && unitIndex < 4) {
        value /= 1024.0;
        unitIndex++;
    }

    if (bytes < 0) {
        swprintf_s(buffer, bufferSize, L"-%.2f %s", value, units[unitIndex]);
    } else {
        swprintf_s(buffer, bufferSize, L"%.2f %s", value, units[unitIndex]);
    }
}

// Get property value from event by name
bool GetEventProperty(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, const wchar_t* propName, ULONGLONG* pValue) {
    for (DWORD i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        wchar_t* name = (wchar_t*)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
        if (_wcsicmp(name, propName) == 0) {
            PROPERTY_DATA_DESCRIPTOR dataDesc = {};
            dataDesc.PropertyName = (ULONGLONG)name;
            dataDesc.ArrayIndex = ULONG_MAX;

            DWORD propSize = 0;
            if (TdhGetPropertySize(pEvent, 0, nullptr, 1, &dataDesc, &propSize) == ERROR_SUCCESS) {
                if (propSize > 0 && propSize <= 8) {
                    BYTE buffer[8] = { 0 };
                    if (TdhGetProperty(pEvent, 0, nullptr, 1, &dataDesc, 8, buffer) == ERROR_SUCCESS) {
                        if (propSize == 8) *pValue = *(ULONGLONG*)buffer;
                        else if (propSize == 4) *pValue = *(ULONG*)buffer;
                        else if (propSize == 2) *pValue = *(USHORT*)buffer;
                        else if (propSize == 1) *pValue = *(UCHAR*)buffer;
                        return true;
                    }
                }
            }
            break;
        }
    }
    return false;
}

// Reset tracking state when target process exits
void ResetTrackingState() {
    std::lock_guard<std::mutex> lock(g_mapMutex);
    g_adapterAllocMap.clear();
    g_vidMmAllocMap.clear();
    g_lastAdapterAlloc.clear();
    g_totalMemoryBytes = 0;
}

// Handle process start/stop events from Microsoft-Windows-Kernel-Process
void HandleProcessEvent(PEVENT_RECORD pEvent) {
    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;

    // For Kernel-Process events, the header ProcessId is NOT the target process
    // We need to get the ProcessID from the event payload
    DWORD processId = 0;

    // Get event info to extract properties
    DWORD bufferSize = 0;
    if (TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufferSize) != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
    if (!pInfo) return;

    if (TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSize) != ERROR_SUCCESS) {
        free(pInfo);
        return;
    }

    // Extract ProcessID and ImageName from event properties
    std::wstring imageName;
    for (DWORD i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        wchar_t* propName = (wchar_t*)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);

        // Get the target process ID from the event payload
        if (_wcsicmp(propName, L"ProcessID") == 0) {
            PROPERTY_DATA_DESCRIPTOR dataDesc = {};
            dataDesc.PropertyName = (ULONGLONG)propName;
            dataDesc.ArrayIndex = ULONG_MAX;

            DWORD propSize = 0;
            if (TdhGetPropertySize(pEvent, 0, nullptr, 1, &dataDesc, &propSize) == ERROR_SUCCESS && propSize >= sizeof(DWORD)) {
                DWORD pidValue = 0;
                if (TdhGetProperty(pEvent, 0, nullptr, 1, &dataDesc, sizeof(DWORD), (PBYTE)&pidValue) == ERROR_SUCCESS) {
                    processId = pidValue;
                }
            }
        }
        // Get the image name
        else if (_wcsicmp(propName, L"ImageName") == 0) {
            PROPERTY_DATA_DESCRIPTOR dataDesc = {};
            dataDesc.PropertyName = (ULONGLONG)propName;
            dataDesc.ArrayIndex = ULONG_MAX;

            DWORD propSize = 0;
            if (TdhGetPropertySize(pEvent, 0, nullptr, 1, &dataDesc, &propSize) == ERROR_SUCCESS && propSize > 0) {
                wchar_t* buffer = (wchar_t*)malloc(propSize);
                if (buffer && TdhGetProperty(pEvent, 0, nullptr, 1, &dataDesc, propSize, (PBYTE)buffer) == ERROR_SUCCESS) {
                    imageName = buffer;
                }
                free(buffer);
            }
        }
    }

    // Extract just the filename from the path
    std::wstring fileName = GetFileName(imageName);

    if (eventId == ProcessStart || eventId == ProcessRundown) {
        // Check if this is our target process
        // ProcessRundown (DCStart) enumerates already-running processes at trace start
        if (!fileName.empty() && ToLower(fileName) == ToLower(g_targetProcessName)) {
            // Only set if we don't already have a target (avoid resetting on rundown if already tracking)
            if (g_targetPid == 0) {
                g_targetPid = processId;
                g_targetProcessRunning = true;

                const wchar_t* eventType = (eventId == ProcessRundown) ? L"DETECTED (already running)" : L"STARTED";
                wprintf(L"\n>>> Target process %s: %s (PID: %lu)\n", eventType, fileName.c_str(), processId);
                fflush(stdout);
                if (g_logFile) {
                    fwprintf(g_logFile, L"\n>>> Target process %s: %s (PID: %lu)\n", eventType, fileName.c_str(), processId);
                    fflush(g_logFile);
                }
            }
        }
    }
    else if (eventId == ProcessStop) {
        // Check if our target process stopped - primarily by PID match
        if (processId == g_targetPid && g_targetPid != 0) {
            wchar_t totalStr[32];
            FormatBytes(g_totalMemoryBytes.load(), totalStr, 32);

            wprintf(L"\n>>> Target process STOPPED: %s (PID: %lu) | Final GPU memory: %s\n",
                    g_targetProcessName.c_str(), processId, totalStr);
            fflush(stdout);
            if (g_logFile) {
                fwprintf(g_logFile, L"\n>>> Target process STOPPED: %s (PID: %lu) | Final GPU memory: %s\n",
                        g_targetProcessName.c_str(), processId, totalStr);
                fflush(g_logFile);
            }

            g_targetProcessRunning = false;
            g_targetPid = 0;
            // Don't reset tracking state yet - in case there are pending deallocation events
        }
    }

    free(pInfo);
}

void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
    if (!pEvent) return;

    // Handle process start/stop events
    if (IsEqualGUID(pEvent->EventHeader.ProviderId, KernelProcessGuid)) {
        HandleProcessEvent(pEvent);
        return;
    }

    // Handle DxgKrnl events
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, DxgKrnlGuid)) {
        return;
    }

    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;
    DWORD processId = pEvent->EventHeader.ProcessId;

    // Get event info
    DWORD bufferSize = 0;
    TDHSTATUS status = TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
    if (!pInfo) return;

    status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSize);
    if (status != ERROR_SUCCESS) {
        free(pInfo);
        return;
    }

    const wchar_t* taskName = L"";
    if (pInfo->TaskNameOffset > 0) {
        taskName = (const wchar_t*)((PBYTE)pInfo + pInfo->TaskNameOffset);
    }

    const wchar_t* opcodeName = L"";
    if (pInfo->OpcodeNameOffset > 0) {
        opcodeName = (const wchar_t*)((PBYTE)pInfo + pInfo->OpcodeNameOffset);
    }

    // Dump all mode
    if (g_dumpAll) {
        wprintf(L"[%u] PID=%lu Task=%s Opcode=%s Props=%lu\n",
                eventId, processId, taskName, opcodeName, pInfo->TopLevelPropertyCount);
        for (DWORD i = 0; i < pInfo->TopLevelPropertyCount && i < 10; i++) {
            wchar_t* propName = (wchar_t*)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
            ULONGLONG value = 0;
            if (GetEventProperty(pEvent, pInfo, propName, &value)) {
                wprintf(L"    %s = %llu (0x%llX)\n", propName, value, value);
            }
        }
        free(pInfo);
        return;
    }

    // Check if this is an allocation event we care about
    bool isAllocation = false;
    bool isDeallocation = false;
    bool isResidencyChange = false;
    const wchar_t* eventType = L"";

    // Track if this is a DeviceAllocation that links AdapterAlloc handle to VidMmAlloc handle
    bool isDeviceAllocationLink = false;

    switch (eventId) {
        // Only count AdapterAllocation for actual memory tracking
        // This is the primary allocation event with size info
        case AdapterAllocation_Start:
        case AdapterAllocation_DCStart:
            isAllocation = true;
            eventType = taskName;
            break;

        // DeviceAllocation links AdapterAllocation handle to hVidMmAlloc handle
        // We need to track this to know size when TerminateAllocation occurs
        case DeviceAllocation_Start:
        case DeviceAllocation_DCStart:
            isDeviceAllocationLink = true;
            eventType = taskName;
            break;

        // ProcessAllocation/ProcessAllocationDetails are duplicates - skip
        case ProcessAllocation_Start:
        case ProcessAllocationDetails_Start:
        case VidMmMakeResident:
        case VidMmMakeResident_DCStart:
        case AdapterAllocation_Stop:
        case DeviceAllocation_Stop:
        case ProcessAllocation_Stop:
        case ProcessAllocationDetails_Stop:
        case VidMmEvict:
            // Skip these - they don't add useful size info or are duplicates
            free(pInfo);
            return;

        case TerminateAllocation:
        case ProcessTerminateAllocation:
            isDeallocation = true;
            eventType = taskName;
            break;

        case ReferenceAllocations:
            // Just informational - DMA buffer referencing allocations
            // Skip for now to reduce noise
            free(pInfo);
            return;

        case RecycleRangeTracking_Info1:
        case RecycleRangeTracking_Info2:
        case RecycleRangeTracking_Info3:
            // Memory range recycling - informational
            free(pInfo);
            return;

        default:
            free(pInfo);
            return;
    }

    // Try to get process ID from event properties
    // AdapterAllocation/DeviceAllocation use hProcessId
    ULONGLONG contextPid = 0;
    GetEventProperty(pEvent, pInfo, L"hProcessId", &contextPid);
    if (contextPid == 0) GetEventProperty(pEvent, pInfo, L"ProcessId", &contextPid);
    if (contextPid == 0) GetEventProperty(pEvent, pInfo, L"ContextProcessId", &contextPid);
    if (contextPid == 0) GetEventProperty(pEvent, pInfo, L"hProcess", &contextPid);

    DWORD effectivePid = contextPid ? (DWORD)contextPid : processId;

    // Filter by process
    if (!g_targetProcessName.empty()) {
        if (g_targetPid == 0) {
            g_targetPid = FindProcessByName(g_targetProcessName.c_str());
        }

        bool matchesTarget = false;
        if (g_targetPid != 0 && effectivePid == g_targetPid) {
            matchesTarget = true;
        } else {
            std::wstring procName = GetProcessName(effectivePid);
            if (!procName.empty() && ToLower(procName) == ToLower(g_targetProcessName)) {
                matchesTarget = true;
                g_targetPid = effectivePid;
            }
        }

        if (!matchesTarget) {
            free(pInfo);
            return;
        }
    }

    // Get allocation size from various property names
    // AdapterAllocation uses "allocSize", other events use different names
    ULONGLONG allocationSize = 0;
    ULONGLONG handle = 0;

    // Try property names in order of likelihood based on observed events
    if (!GetEventProperty(pEvent, pInfo, L"allocSize", &allocationSize)) {
        if (!GetEventProperty(pEvent, pInfo, L"Size", &allocationSize)) {
            if (!GetEventProperty(pEvent, pInfo, L"AllocationSize", &allocationSize)) {
                if (!GetEventProperty(pEvent, pInfo, L"ByteSize", &allocationSize)) {
                    GetEventProperty(pEvent, pInfo, L"Bytes", &allocationSize);
                }
            }
        }
    }

    // Try to get handle for tracking - different events use different property names
    // VidMm events use hVidMmAlloc or pVidMmAlloc
    if (!GetEventProperty(pEvent, pInfo, L"hVidMmAlloc", &handle)) {
        if (!GetEventProperty(pEvent, pInfo, L"pVidMmAlloc", &handle)) {
            if (!GetEventProperty(pEvent, pInfo, L"hVidMmGlobalAlloc", &handle)) {
                if (!GetEventProperty(pEvent, pInfo, L"hAllocation", &handle)) {
                    if (!GetEventProperty(pEvent, pInfo, L"Allocation", &handle)) {
                        GetEventProperty(pEvent, pInfo, L"pAllocation", &handle);
                    }
                }
            }
        }
    }

    if (g_verbose) {
        wprintf(L"[DEBUG] EventId=%u %s PID=%lu Size=%llu Handle=0x%llX\n",
                eventId, eventType, effectivePid, allocationSize, handle);
        fflush(stdout);
        if (g_logFile) {
            fwprintf(g_logFile, L"[DEBUG] EventId=%u %s PID=%lu Size=%llu Handle=0x%llX\n",
                    eventId, eventType, effectivePid, allocationSize, handle);
            fflush(g_logFile);
        }
    }

    int64_t delta = 0;
    const wchar_t* action = L"";

    if (isAllocation && allocationSize > 0) {
        delta = (int64_t)allocationSize;
        g_totalMemoryBytes += delta;
        action = L"ALLOC";

        // Store this allocation by handle for later linking
        if (handle != 0) {
            std::lock_guard<std::mutex> lock(g_mapMutex);
            g_adapterAllocMap[handle] = allocationSize;
            // Also track as the most recent allocation for this process
            g_lastAdapterAlloc[effectivePid] = {handle, allocationSize};
        }
    }
    else if (isDeviceAllocationLink) {
        // DeviceAllocation links an AdapterAllocation to a hVidMmAlloc handle
        // The hVidMmAlloc is used in TerminateAllocation
        ULONGLONG hVidMmAlloc = 0;
        GetEventProperty(pEvent, pInfo, L"hVidMmAlloc", &hVidMmAlloc);

        if (hVidMmAlloc != 0) {
            std::lock_guard<std::mutex> lock(g_mapMutex);
            // Try to find the most recent AdapterAllocation for this process
            auto lastIt = g_lastAdapterAlloc.find(effectivePid);
            if (lastIt != g_lastAdapterAlloc.end() && lastIt->second.size > 0) {
                // Link the hVidMmAlloc to the allocation size
                g_vidMmAllocMap[hVidMmAlloc] = lastIt->second.size;
                if (g_verbose && g_logFile) {
                    fwprintf(g_logFile, L"[LINK] hVidMmAlloc=0x%llX -> Size=%llu\n",
                            hVidMmAlloc, lastIt->second.size);
                    fflush(g_logFile);
                }
                // Clear the last allocation to avoid double-linking
                lastIt->second.size = 0;
            }
        }
        free(pInfo);
        return;  // Don't print anything for DeviceAllocation
    }
    else if (isDeallocation) {
        // TerminateAllocation uses hVidMmAlloc handle
        if (handle != 0 && allocationSize == 0) {
            std::lock_guard<std::mutex> lock(g_mapMutex);
            // First try vidMmAllocMap (linked from DeviceAllocation)
            auto it = g_vidMmAllocMap.find(handle);
            if (it != g_vidMmAllocMap.end()) {
                allocationSize = it->second;
                g_vidMmAllocMap.erase(it);
            }
        }

        if (allocationSize > 0) {
            delta = -(int64_t)allocationSize;
            g_totalMemoryBytes += delta;
            action = L"FREE";
        }
    }

    if (delta != 0) {
        wchar_t sizeStr[32], totalStr[32], deltaStr[32];
        FormatBytes((int64_t)allocationSize, sizeStr, 32);
        FormatBytes(g_totalMemoryBytes.load(), totalStr, 32);
        FormatBytes(delta, deltaStr, 32);

        wprintf(L"[PID %5lu] %-6s %-25s | Size: %12s | Delta: %12s | Total: %12s\n",
                effectivePid, action, eventType, sizeStr, deltaStr, totalStr);
        fflush(stdout);
        if (g_logFile) {
            fwprintf(g_logFile, L"[PID %5lu] %-6s %-25s | Size: %12s | Delta: %12s | Total: %12s\n",
                    effectivePid, action, eventType, sizeStr, deltaStr, totalStr);
            fflush(g_logFile);
        }
    }

    free(pInfo);
}

void StopTraceSession() {
    if (g_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_traceHandle);
        g_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    if (g_sessionHandle != 0) {
        size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(SESSION_NAME) + 1) * sizeof(wchar_t);
        PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);
        if (pProperties) {
            ZeroMemory(pProperties, bufferSize);
            pProperties->Wnode.BufferSize = (ULONG)bufferSize;
            pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            ControlTraceW(g_sessionHandle, SESSION_NAME, pProperties, EVENT_TRACE_CONTROL_STOP);
            free(pProperties);
        }
        g_sessionHandle = 0;
    }
}

BOOL WINAPI ConsoleHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        wprintf(L"\nStopping trace...\n");
        StopTraceSession();
        return TRUE;
    }
    return FALSE;
}

extern "C" __declspec(dllexport) int64_t GetCurrentGpuMemory() {
    return g_totalMemoryBytes.load();
}

void PrintUsage(const wchar_t* progName) {
    wprintf(L"Usage: %s <executable_name> [options]\n", progName);
    wprintf(L"Example: %s chrome.exe\n", progName);
    wprintf(L"\nTracks GPU memory allocations for the specified process using ETW.\n");
    wprintf(L"Requires Administrator privileges.\n");
    wprintf(L"\nOptions:\n");
    wprintf(L"  -v       Verbose mode (show event details)\n");
    wprintf(L"  -dump    Dump allocation events (for debugging)\n");
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    g_targetProcessName = argv[1];

    for (int i = 2; i < argc; i++) {
        if (wcscmp(argv[i], L"-v") == 0) {
            g_verbose = true;
        } else if (wcscmp(argv[i], L"-dump") == 0) {
            g_dumpAll = true;
        }
    }

    // Check if target process is already running
    g_targetPid = FindProcessByName(g_targetProcessName.c_str());
    if (g_targetPid != 0) {
        g_targetProcessRunning = true;
        wprintf(L"Tracking GPU memory allocations for: %s (PID: %lu, already running)\n",
                g_targetProcessName.c_str(), g_targetPid);
    } else {
        wprintf(L"Waiting for process to start: %s\n", g_targetProcessName.c_str());
    }
    if (g_verbose) wprintf(L"Verbose mode enabled.\n");
    if (g_dumpAll) wprintf(L"Dump mode enabled.\n");
    wprintf(L"Press Ctrl+C to stop.\n\n");

    // Open log file for reliable output capture
    _wfopen_s(&g_logFile, L"D:\\git\\cl-evict\\tracker-log.txt", L"w");
    if (g_logFile) {
        fwprintf(g_logFile, L"=== GPU Memory Tracker Log ===\n");
        fwprintf(g_logFile, L"Target: %s\n\n", g_targetProcessName.c_str());
        fflush(g_logFile);
    }

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // Stop any existing session
    {
        size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(SESSION_NAME) + 1) * sizeof(wchar_t);
        PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);
        if (pProperties) {
            ZeroMemory(pProperties, bufferSize);
            pProperties->Wnode.BufferSize = (ULONG)bufferSize;
            pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            ControlTraceW(0, SESSION_NAME, pProperties, EVENT_TRACE_CONTROL_STOP);
            free(pProperties);
        }
    }

    size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(SESSION_NAME) + 1) * sizeof(wchar_t);
    PEVENT_TRACE_PROPERTIES pSessionProperties = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);
    if (!pSessionProperties) {
        wprintf(L"Failed to allocate memory for trace properties.\n");
        return 1;
    }

    ZeroMemory(pSessionProperties, bufferSize);
    pSessionProperties->Wnode.BufferSize = (ULONG)bufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1;
    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&g_sessionHandle, SESSION_NAME, pSessionProperties);
    if (status != ERROR_SUCCESS) {
        wprintf(L"Failed to start trace session. Error: %lu\n", status);
        if (status == ERROR_ACCESS_DENIED) {
            wprintf(L"Please run as Administrator.\n");
        }
        free(pSessionProperties);
        return 1;
    }

    // Enable DxgKrnl provider - use all keywords to get Resource, Memory, References events
    status = EnableTraceEx2(
        g_sessionHandle,
        &DxgKrnlGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF,  // All keywords including Resource, Memory, References
        0,
        0,
        nullptr
    );

    if (status != ERROR_SUCCESS) {
        wprintf(L"Failed to enable DxgKrnl provider. Error: %lu\n", status);
        StopTraceSession();
        free(pSessionProperties);
        return 1;
    }

    // Request rundown/capture state to enumerate existing GPU allocations (DCStart events)
    status = EnableTraceEx2(
        g_sessionHandle,
        &DxgKrnlGuid,
        EVENT_CONTROL_CODE_CAPTURE_STATE,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF,
        0,
        0,
        nullptr
    );

    if (status != ERROR_SUCCESS) {
        wprintf(L"Warning: Failed to request DxgKrnl rundown. Error: %lu\n", status);
        wprintf(L"Existing GPU allocations may not be enumerated.\n");
        // Continue anyway - new allocations will still be tracked
    }

    // Enable Kernel-Process provider for process start/stop detection
    // Keyword 0x10 = WINEVENT_KEYWORD_PROCESS for process events
    // Keyword 0x20 = WINEVENT_KEYWORD_PROCESS_RUNDOWN for enumerating existing processes
    ENABLE_TRACE_PARAMETERS kernelProcessParams = {};
    kernelProcessParams.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    kernelProcessParams.EnableProperty = EVENT_ENABLE_PROPERTY_PROCESS_START_KEY;

    status = EnableTraceEx2(
        g_sessionHandle,
        &KernelProcessGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x10 | 0x20,  // WINEVENT_KEYWORD_PROCESS | WINEVENT_KEYWORD_PROCESS_RUNDOWN
        0,
        0,
        &kernelProcessParams
    );

    if (status != ERROR_SUCCESS) {
        wprintf(L"Warning: Failed to enable Kernel-Process provider. Error: %lu\n", status);
        wprintf(L"Process start/stop detection will not work.\n");
        // Continue anyway - we can still track if process is already running
    }

    wprintf(L"ETW session started. Listening for allocation events...\n");
    wprintf(L"  AdapterAllocation (33-35), DeviceAllocation (36-38), Terminate (39-40)\n");
    wprintf(L"  VidMmMakeResident (320), VidMmEvict (321)\n");
    wprintf(L"  Process start/stop detection: %s\n\n", status == ERROR_SUCCESS ? L"enabled" : L"disabled");

    EVENT_TRACE_LOGFILEW logfile = { 0 };
    logfile.LoggerName = (LPWSTR)SESSION_NAME;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EventRecordCallback;

    g_traceHandle = OpenTraceW(&logfile);
    if (g_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        wprintf(L"Failed to open trace. Error: %lu\n", GetLastError());
        StopTraceSession();
        free(pSessionProperties);
        return 1;
    }

    status = ProcessTrace(&g_traceHandle, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        wprintf(L"ProcessTrace failed. Error: %lu\n", status);
    }

    StopTraceSession();
    free(pSessionProperties);

    wchar_t totalStr[32];
    FormatBytes(g_totalMemoryBytes.load(), totalStr, 32);
    wprintf(L"\nFinal total memory: %s (%lld bytes)\n", totalStr, g_totalMemoryBytes.load());

    if (g_logFile) {
        fwprintf(g_logFile, L"\n=== Final total memory: %s (%lld bytes) ===\n", totalStr, g_totalMemoryBytes.load());
        fclose(g_logFile);
        g_logFile = nullptr;
    }

    return 0;
}
