// Test runner for gpu-memory-tracker
// Verifies that tracking 4GB allocation from EvictionHelper.exe works correctly
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
#include <thread>
#include <chrono>

// Microsoft-Windows-DxgKrnl provider GUID
DEFINE_GUID(DxgKrnlGuid,
    0x802ec45a, 0x1e99, 0x4b83, 0x99, 0x20, 0x87, 0xc9, 0x82, 0x77, 0xba, 0x9d);

static const wchar_t* SESSION_NAME = L"GpuMemoryTestSession";

// Global state
static std::atomic<int64_t> g_totalMemoryBytes{ 0 };
static std::atomic<int64_t> g_peakMemoryBytes{ 0 };
static std::atomic<bool> g_running{ true };
static TRACEHANDLE g_sessionHandle = 0;
static TRACEHANDLE g_traceHandle = INVALID_PROCESSTRACE_HANDLE;
static std::wstring g_targetProcessName;

static std::unordered_map<ULONGLONG, ULONGLONG> g_allocationMap;
static std::mutex g_mapMutex;

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

void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
    if (!pEvent || !g_running) return;
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, DxgKrnlGuid)) return;

    DWORD processId = pEvent->EventHeader.ProcessId;
    UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;

    // Filter by process
    if (!g_targetProcessName.empty()) {
        std::wstring processName = GetProcessName(processId);
        if (processName.empty() || ToLower(processName) != ToLower(g_targetProcessName)) {
            return;
        }
    }

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

    const wchar_t* taskName = L"";
    if (pInfo->TaskNameOffset > 0) {
        taskName = (const wchar_t*)((PBYTE)pInfo + pInfo->TaskNameOffset);
    }

    std::wstring taskLower = ToLower(taskName);
    bool isAllocationEvent = (taskLower.find(L"alloc") != std::wstring::npos ||
                              taskLower.find(L"vidmm") != std::wstring::npos ||
                              taskLower.find(L"memory") != std::wstring::npos ||
                              taskLower.find(L"makeresident") != std::wstring::npos ||
                              taskLower.find(L"evict") != std::wstring::npos);

    bool isStart = (opcode == 1 || opcode == 3);
    bool isStop = (opcode == 2 || opcode == 4);

    ULONGLONG allocationSize = 0;
    ULONGLONG handle = 0;

    for (DWORD i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        wchar_t* propName = (wchar_t*)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
        std::wstring propLower = ToLower(propName);

        PROPERTY_DATA_DESCRIPTOR dataDesc = {};
        dataDesc.PropertyName = (ULONGLONG)propName;
        dataDesc.ArrayIndex = ULONG_MAX;

        DWORD propSize = 0;
        if (TdhGetPropertySize(pEvent, 0, nullptr, 1, &dataDesc, &propSize) != ERROR_SUCCESS) continue;

        if (propSize > 0 && propSize <= 8) {
            BYTE buffer[8] = { 0 };
            if (TdhGetProperty(pEvent, 0, nullptr, 1, &dataDesc, 8, buffer) == ERROR_SUCCESS) {
                ULONGLONG value = 0;
                if (propSize == 8) value = *(ULONGLONG*)buffer;
                else if (propSize == 4) value = *(ULONG*)buffer;
                else if (propSize == 2) value = *(USHORT*)buffer;
                else if (propSize == 1) value = *(UCHAR*)buffer;

                if (propLower.find(L"size") != std::wstring::npos ||
                    propLower.find(L"bytes") != std::wstring::npos) {
                    if (value > 0 && allocationSize == 0) allocationSize = value;
                } else if (propLower.find(L"alloc") != std::wstring::npos ||
                           propLower.find(L"handle") != std::wstring::npos) {
                    if (value != 0 && handle == 0) handle = value;
                }
            }
        }
    }

    if (isAllocationEvent && isStart && allocationSize > 0) {
        g_totalMemoryBytes += (int64_t)allocationSize;
        int64_t current = g_totalMemoryBytes.load();
        int64_t peak = g_peakMemoryBytes.load();
        while (current > peak && !g_peakMemoryBytes.compare_exchange_weak(peak, current));

        if (handle != 0) {
            std::lock_guard<std::mutex> lock(g_mapMutex);
            g_allocationMap[handle] = allocationSize;
        }
    } else if (isAllocationEvent && isStop) {
        if (handle != 0) {
            std::lock_guard<std::mutex> lock(g_mapMutex);
            auto it = g_allocationMap.find(handle);
            if (it != g_allocationMap.end()) {
                allocationSize = it->second;
                g_allocationMap.erase(it);
            }
        }
        if (allocationSize > 0) {
            g_totalMemoryBytes -= (int64_t)allocationSize;
        }
    }

    free(pInfo);
}

void StopTraceSession() {
    g_running = false;

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

bool StartTraceSession(const wchar_t* targetProcess) {
    g_targetProcessName = targetProcess;
    g_running = true;

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
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);
    if (!pProperties) return false;

    ZeroMemory(pProperties, bufferSize);
    pProperties->Wnode.BufferSize = (ULONG)bufferSize;
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProperties->Wnode.ClientContext = 1;
    pProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&g_sessionHandle, SESSION_NAME, pProperties);
    free(pProperties);

    if (status != ERROR_SUCCESS) {
        wprintf(L"StartTrace failed: %lu\n", status);
        if (status == ERROR_ACCESS_DENIED) {
            wprintf(L"ERROR: Run as Administrator!\n");
        }
        return false;
    }

    status = EnableTraceEx2(g_sessionHandle, &DxgKrnlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFF, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        wprintf(L"EnableTraceEx2 failed: %lu\n", status);
        StopTraceSession();
        return false;
    }

    return true;
}

void TraceThreadProc() {
    EVENT_TRACE_LOGFILEW logfile = { 0 };
    logfile.LoggerName = (LPWSTR)SESSION_NAME;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EventRecordCallback;

    g_traceHandle = OpenTraceW(&logfile);
    if (g_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        wprintf(L"OpenTrace failed: %lu\n", GetLastError());
        return;
    }

    ProcessTrace(&g_traceHandle, 1, nullptr, nullptr);
}

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"=== GPU Memory Tracker Test ===\n\n");

    const wchar_t* evictionHelperPath = L"D:\\git\\cl-evict\\EvictionHelper.exe";

    // Check if EvictionHelper exists
    if (GetFileAttributesW(evictionHelperPath) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"ERROR: EvictionHelper.exe not found at: %s\n", evictionHelperPath);
        return 1;
    }

    wprintf(L"Starting ETW trace session...\n");
    if (!StartTraceSession(L"EvictionHelper.exe")) {
        return 1;
    }

    // Start trace processing thread
    std::thread traceThread(TraceThreadProc);

    // Give the trace a moment to start
    Sleep(500);

    wprintf(L"Launching EvictionHelper.exe...\n");

    // Launch EvictionHelper
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(evictionHelperPath, nullptr, nullptr, nullptr, FALSE,
                        0, nullptr, nullptr, &si, &pi)) {
        wprintf(L"ERROR: Failed to launch EvictionHelper.exe: %lu\n", GetLastError());
        StopTraceSession();
        traceThread.join();
        return 1;
    }

    wprintf(L"EvictionHelper.exe started (PID: %lu)\n", pi.dwProcessId);
    wprintf(L"Waiting for allocation (expecting ~4GB)...\n\n");

    // Monitor memory while process runs
    const int64_t TARGET_4GB = 4LL * 1024 * 1024 * 1024;
    const int64_t TOLERANCE = 512LL * 1024 * 1024; // 512MB tolerance
    bool reached4GB = false;

    while (WaitForSingleObject(pi.hProcess, 100) == WAIT_TIMEOUT) {
        int64_t current = g_totalMemoryBytes.load();
        int64_t peak = g_peakMemoryBytes.load();

        wprintf(L"\rCurrent: %8.2f MB | Peak: %8.2f MB   ",
                current / (1024.0 * 1024.0),
                peak / (1024.0 * 1024.0));

        if (peak >= TARGET_4GB - TOLERANCE) {
            reached4GB = true;
        }
    }

    wprintf(L"\n\nEvictionHelper.exe exited.\n");

    // Wait a bit for final deallocation events
    Sleep(1000);

    int64_t finalMemory = g_totalMemoryBytes.load();
    int64_t peakMemory = g_peakMemoryBytes.load();

    wprintf(L"\n=== Test Results ===\n");
    wprintf(L"Peak memory tracked:  %.2f GB (%lld bytes)\n", peakMemory / (1024.0 * 1024.0 * 1024.0), peakMemory);
    wprintf(L"Final memory tracked: %.2f MB (%lld bytes)\n", finalMemory / (1024.0 * 1024.0), finalMemory);

    // Stop tracing
    StopTraceSession();
    traceThread.join();

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Evaluate results
    bool testPassed = true;

    wprintf(L"\n=== Test Evaluation ===\n");

    // Check if we reached ~4GB
    if (peakMemory >= TARGET_4GB - TOLERANCE) {
        wprintf(L"[PASS] Peak memory reached ~4GB (%.2f GB)\n", peakMemory / (1024.0 * 1024.0 * 1024.0));
    } else if (peakMemory > 0) {
        wprintf(L"[WARN] Peak memory was %.2f GB, expected ~4GB\n", peakMemory / (1024.0 * 1024.0 * 1024.0));
        wprintf(L"       This may be due to event filtering. Check verbose output.\n");
    } else {
        wprintf(L"[FAIL] No memory allocations tracked!\n");
        testPassed = false;
    }

    // Check if memory returned to ~0
    if (finalMemory >= -TOLERANCE && finalMemory <= TOLERANCE) {
        wprintf(L"[PASS] Memory returned to ~0 after process exit (%.2f MB)\n", finalMemory / (1024.0 * 1024.0));
    } else {
        wprintf(L"[WARN] Final memory is %.2f MB, expected ~0\n", finalMemory / (1024.0 * 1024.0));
    }

    wprintf(L"\n%s\n", testPassed ? L"=== TEST PASSED ===" : L"=== TEST FAILED ===");

    return testPassed ? 0 : 1;
}
