// Diagnostic tool to dump all DxgKrnl ETW events with specific event IDs
#define INITGUID
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include <string>

DEFINE_GUID(DxgKrnlGuid,
    0x802ec45a, 0x1e99, 0x4b83, 0x99, 0x20, 0x87, 0xc9, 0x82, 0x77, 0xba, 0x9d);

static const wchar_t* SESSION_NAME = L"DxgKrnlDumperSession";
static TRACEHANDLE g_sessionHandle = 0;
static TRACEHANDLE g_traceHandle = INVALID_PROCESSTRACE_HANDLE;
static int g_eventCount = 0;
static int g_allocationCount = 0;
static FILE* g_logFile = nullptr;

// Allocation event IDs we're looking for
bool IsAllocationEvent(USHORT eventId) {
    return (eventId >= 33 && eventId <= 40) ||  // AdapterAllocation, DeviceAllocation, Terminate
           (eventId == 64 || eventId == 65) ||   // RenameAllocation
           (eventId == 225 || eventId == 226) || // ProcessAllocation
           (eventId == 320 || eventId == 321 || eventId == 374) || // VidMm
           (eventId == 43) ||  // ReferenceAllocations - seen in real traces
           (eventId == 289) || // ProcessAllocationDetails - seen in real traces
           (eventId == 301 || eventId == 302 || eventId == 303); // RecycleRangeTracking - memory related
}

// Track unique event IDs seen
#include <set>
static std::set<USHORT> g_seenEventIds;

static bool g_firstEvent = true;

void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
    if (g_firstEvent) {
        g_firstEvent = false;
        if (g_logFile) { fwprintf(g_logFile, L"First event callback received!\n"); fflush(g_logFile); }
    }

    if (!pEvent) return;
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, DxgKrnlGuid)) return;

    g_eventCount++;

    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;
    UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;
    ULONGLONG keyword = pEvent->EventHeader.EventDescriptor.Keyword;
    DWORD processId = pEvent->EventHeader.ProcessId;

    // Track unique event IDs
    bool isNewId = g_seenEventIds.insert(eventId).second;

    // Log first 100 events unconditionally
    bool logThis = (g_eventCount <= 100);

    // Only show allocation events or every 1000th event or new event IDs
    bool isAlloc = IsAllocationEvent(eventId);
    if (isAlloc) g_allocationCount++;

    if (!isAlloc && !isNewId && !logThis && (g_eventCount % 1000 != 0)) {
        return;
    }

    DWORD bufferSize = 0;
    TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufferSize);

    PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
    if (!pInfo) return;

    if (TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSize) == ERROR_SUCCESS) {
        const wchar_t* taskName = (pInfo->TaskNameOffset > 0)
            ? (const wchar_t*)((PBYTE)pInfo + pInfo->TaskNameOffset) : L"(none)";
        const wchar_t* opcodeName = (pInfo->OpcodeNameOffset > 0)
            ? (const wchar_t*)((PBYTE)pInfo + pInfo->OpcodeNameOffset) : L"(none)";

        if (isAlloc) {
            wprintf(L"[ALLOC #%d] Id=%u Task=%s Opcode=%s PID=%lu Keywords=0x%llX\n",
                    g_allocationCount, eventId, taskName, opcodeName, processId, keyword);
            if (g_logFile) { fwprintf(g_logFile, L"[ALLOC #%d] Id=%u Task=%s Opcode=%s PID=%lu Keywords=0x%llX\n",
                    g_allocationCount, eventId, taskName, opcodeName, processId, keyword); fflush(g_logFile); }
        } else if (isNewId) {
            wprintf(L"[NEW ID] Id=%u Task=%s Opcode=%s Keywords=0x%llX\n",
                    eventId, taskName, opcodeName, keyword);
            if (g_logFile) { fwprintf(g_logFile, L"[NEW ID] Id=%u Task=%s Opcode=%s Keywords=0x%llX\n",
                    eventId, taskName, opcodeName, keyword); fflush(g_logFile); }
        } else if (logThis) {
            wprintf(L"[%d] Id=%u Task=%s Opcode=%s\n", g_eventCount, eventId, taskName, opcodeName);
            if (g_logFile) { fwprintf(g_logFile, L"[%d] Id=%u Task=%s Opcode=%s\n", g_eventCount, eventId, taskName, opcodeName); fflush(g_logFile); }
        } else {
            wprintf(L"[%d] Id=%u Task=%s (every 1000th event)\n",
                    g_eventCount, eventId, taskName);
        }

        // Dump properties for allocation events
        if (isAlloc) {
            for (DWORD i = 0; i < pInfo->TopLevelPropertyCount && i < 10; i++) {
                wchar_t* propName = (wchar_t*)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);

                PROPERTY_DATA_DESCRIPTOR dataDesc = {};
                dataDesc.PropertyName = (ULONGLONG)propName;
                dataDesc.ArrayIndex = ULONG_MAX;

                DWORD propSize = 0;
                if (TdhGetPropertySize(pEvent, 0, nullptr, 1, &dataDesc, &propSize) == ERROR_SUCCESS) {
                    if (propSize <= 8 && propSize > 0) {
                        BYTE buffer[8] = {0};
                        if (TdhGetProperty(pEvent, 0, nullptr, 1, &dataDesc, 8, buffer) == ERROR_SUCCESS) {
                            ULONGLONG value = 0;
                            if (propSize == 8) value = *(ULONGLONG*)buffer;
                            else if (propSize == 4) value = *(ULONG*)buffer;
                            else if (propSize == 2) value = *(USHORT*)buffer;
                            else if (propSize == 1) value = *(UCHAR*)buffer;
                            wprintf(L"    %s = %llu (0x%llX)\n", propName, value, value);
                        }
                    }
                }
            }
        }
    }

    free(pInfo);

    if (g_eventCount >= 20000) {
        wprintf(L"\nReached 20000 events. Allocation events found: %d\n", g_allocationCount);
        CloseTrace(g_traceHandle);
    }
}

void StopSession() {
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
        wprintf(L"\nStopping... Total events: %d, Allocation events: %d\n", g_eventCount, g_allocationCount);
        StopSession();
        return TRUE;
    }
    return FALSE;
}

int wmain() {
    // Open log file
    errno_t err = _wfopen_s(&g_logFile, L"D:\\git\\cl-evict\\dumper-log.txt", L"w");
    if (err != 0 || !g_logFile) {
        wprintf(L"Failed to open log file! Error: %d\n", err);
    } else {
        fwprintf(g_logFile, L"=== DxgKrnl Dumper Started ===\n");
        fflush(g_logFile);
    }

    wprintf(L"DxgKrnl Allocation Event Finder\n");
    wprintf(L"================================\n");
    wprintf(L"Looking for event IDs: 33-40 (Adapter/DeviceAllocation),\n");
    wprintf(L"                       64-65 (RenameAllocation),\n");
    wprintf(L"                       225-226 (ProcessAllocation),\n");
    wprintf(L"                       320-321, 374 (VidMm)\n\n");
    wprintf(L"Keywords enabled: ALL keywords\n\n");
    wprintf(L"Log file: D:\\git\\cl-evict\\dumper-log.txt\n\n");

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // Stop existing session
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
    ZeroMemory(pProperties, bufferSize);
    pProperties->Wnode.BufferSize = (ULONG)bufferSize;
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProperties->Wnode.ClientContext = 1;
    pProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&g_sessionHandle, SESSION_NAME, pProperties);
    if (status != ERROR_SUCCESS) {
        wprintf(L"StartTrace failed: %lu\n", status);
        if (status == ERROR_ACCESS_DENIED) wprintf(L"Run as Administrator!\n");
        return 1;
    }

    // Enable ALL keywords to see everything
    ULONGLONG keywords = 0xFFFFFFFFFFFFFFFF;
    wprintf(L"Using keywords: ALL (0x%llX)\n\n", keywords);

    status = EnableTraceEx2(g_sessionHandle, &DxgKrnlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE, keywords, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        wprintf(L"EnableTraceEx2 failed: %lu\n", status);
        if (g_logFile) { fwprintf(g_logFile, L"EnableTraceEx2 failed: %lu\n", status); fflush(g_logFile); }
        StopSession();
        return 1;
    }
    wprintf(L"EnableTraceEx2 succeeded!\n");
    if (g_logFile) { fwprintf(g_logFile, L"EnableTraceEx2 succeeded!\n"); fflush(g_logFile); }

    wprintf(L"Listening... (Ctrl+C to stop)\n\n");
    if (g_logFile) { fwprintf(g_logFile, L"Starting to listen for events...\n"); fflush(g_logFile); }

    EVENT_TRACE_LOGFILEW logfile = {0};
    logfile.LoggerName = (LPWSTR)SESSION_NAME;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EventRecordCallback;

    g_traceHandle = OpenTraceW(&logfile);
    if (g_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        wprintf(L"OpenTrace failed: %lu\n", GetLastError());
        StopSession();
        return 1;
    }

    ProcessTrace(&g_traceHandle, 1, nullptr, nullptr);
    StopSession();
    free(pProperties);

    wprintf(L"\nFinal: Total events: %d, Allocation events: %d\n", g_eventCount, g_allocationCount);
    wprintf(L"Unique event IDs seen: %zu\n", g_seenEventIds.size());
    wprintf(L"Event IDs: ");
    for (auto id : g_seenEventIds) {
        wprintf(L"%u ", id);
    }
    wprintf(L"\n");

    if (g_logFile) {
        fwprintf(g_logFile, L"\nFinal: Total events: %d, Allocation events: %d\n", g_eventCount, g_allocationCount);
        fwprintf(g_logFile, L"Unique event IDs seen: %zu\n", g_seenEventIds.size());
        fwprintf(g_logFile, L"Event IDs: ");
        for (auto id : g_seenEventIds) {
            fwprintf(g_logFile, L"%u ", id);
        }
        fwprintf(g_logFile, L"\n");
        fclose(g_logFile);
    }

    return 0;
}
