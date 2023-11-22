#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <conio.h>
#include <stdio.h>
#include "utils.h"
#include "Detours/detours.h"

IInputSystem* g_InputSystem = nullptr;
CInput* g_Input = nullptr;

typedef bool(__thiscall* GetRawMouseAccumulatorsFn)(void*, int&, int&);
typedef LRESULT(__thiscall* WindowProcFn)(void*, HWND, UINT, WPARAM, LPARAM);
typedef void(__thiscall* GetAccumulatedMouseDeltasAndResetAccumulatorsFn)(void*, float*, float*);
typedef void(__thiscall* ControllerMoveFn)(void*, float, void*);
typedef void(__thiscall* In_SetSampleTimeFn)(void*, float);

GetRawMouseAccumulatorsFn oGetRawMouseAccumulators;
WindowProcFn oWindowProc;
GetAccumulatedMouseDeltasAndResetAccumulatorsFn oGetAccumulatedMouseDeltasAndResetAccumulators;
ControllerMoveFn oControllerMove;
In_SetSampleTimeFn oIn_SetSampleTime;


typedef void(__cdecl* ConMsgFn)(const char*, ...);
ConMsgFn ConMsg;

typedef double(__cdecl* Plat_FloatTimeFn)();
Plat_FloatTimeFn Plat_FloatTime;

float mouseMoveFrameTime;

double m_mouseSplitTime;
double m_mouseSampleTime;
float m_flMouseSampleTime;

void Error(char* text)
{
	MessageBoxA(0, text, "ERROR", 16);
	ExitProcess(0);
}

bool GetRawMouseAccumulators(int& accumX, int& accumY, double frame_split)
{
	static int* m_mouseRawAccumX = (int*)((uintptr_t)g_InputSystem + 0x119C);
	static int* m_mouseRawAccumY = (int*)((uintptr_t)g_InputSystem + 0x11A0);
	static bool* m_bRawInputSupported = (bool*)((uintptr_t)g_InputSystem + 0x1198);

	//ConMsg("GetRawMouseAccumulators: %d | %d | %d\n", *(int*)m_mouseRawAccumX, *(int*)m_mouseRawAccumY, *(bool*)m_bRawInputSupported);

	MSG msg;
	if (frame_split != 0.0 && PeekMessageW(&msg, NULL, WM_INPUT, WM_INPUT, PM_REMOVE))
	{
		do
		{
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		} while (PeekMessageW(&msg, NULL, WM_INPUT, WM_INPUT, PM_REMOVE));
	}

	double mouseSplitTime = m_mouseSplitTime;
	if (mouseSplitTime == 0.0)
	{
		mouseSplitTime = m_mouseSampleTime - 0.01;
		m_mouseSplitTime = mouseSplitTime;
	}

	double mouseSampleTime = m_mouseSampleTime;

	if (abs(mouseSplitTime - mouseSampleTime) >= 0.000001)
	{
		if (frame_split == 0.0 || frame_split >= mouseSampleTime)
		{
			accumX = *(int*)m_mouseRawAccumX;
			accumY = *(int*)m_mouseRawAccumY;
			*(int*)m_mouseRawAccumX = *(int*)m_mouseRawAccumY = 0;

			m_mouseSplitTime = m_mouseSampleTime;

			return *(bool*)m_bRawInputSupported;
		}
		else if (frame_split >= mouseSplitTime)
		{
			float splitSegment = (frame_split - mouseSplitTime) / (mouseSampleTime - mouseSplitTime);

			accumX = splitSegment * (*(int*)m_mouseRawAccumX);
			accumY = splitSegment * (*(int*)m_mouseRawAccumY);

			*(int*)m_mouseRawAccumX -= accumX;
			*(int*)m_mouseRawAccumY -= accumY;

			m_mouseSplitTime = frame_split;

			return *(bool*)m_bRawInputSupported;
		}
	}

	accumX = accumY = 0;

	return *(bool*)m_bRawInputSupported;
}

void GetAccumulatedMouseDeltasAndResetAccumulators(float* mx, float* my, float frametime)
{
	//Assert(mx);
	//Assert(my);

	static float* m_flAccumulatedMouseXMovement = (float*)((uintptr_t)g_Input + 0x8);
	static float* m_flAccumulatedMouseYMovement = (float*)((uintptr_t)g_Input + 0xC);

	static uintptr_t client = (uintptr_t)GetModuleHandle("client.dll");
	int m_rawinput = *(int*)(client + 0x4F5EA0);

	//ConMsg("GetAccumulatedMouseDeltasAndResetAccumulators: %.3f | %.3f | %d\n", *(float*)m_flAccumulatedMouseXMovement, *(float*)m_flAccumulatedMouseYMovement, m_rawinput);

	if (m_flMouseSampleTime > 0.0)
	{
		int rawMouseX, rawMouseY;
		if(m_rawinput != 0)
		{
			if (m_rawinput == 2 && frametime > 0.0)
			{
				m_flMouseSampleTime -= MIN(m_flMouseSampleTime, frametime);
				GetRawMouseAccumulators(rawMouseX, rawMouseY, Plat_FloatTime() - m_flMouseSampleTime);
			}
			else
			{
				GetRawMouseAccumulators(rawMouseX, rawMouseY, 0.0);
				m_flMouseSampleTime = 0.0;
			}
		}
		else
		{
			rawMouseX = *(float*)m_flAccumulatedMouseXMovement;
			rawMouseY = *(float*)m_flAccumulatedMouseYMovement;
		}

		*(float*)m_flAccumulatedMouseXMovement = 0.0;
		*(float*)m_flAccumulatedMouseYMovement = 0.0;

		*mx = (float)rawMouseX;
		*my = (float)rawMouseY;
	}
	else
	{
		*mx = 0.0;
		*my = 0.0;
	}
}

bool __fastcall Hooked_GetRawMouseAccumulators(void* thisptr, void* edx, int& accumX, int& accumY)
{
	return GetRawMouseAccumulators(accumX, accumY, 0.0);

	//GetRawMouseAccumulators(accumX, accumY, 0.0);
	//return oGetRawMouseAccumulators(thisptr, accumX, accumY);
}

LRESULT __fastcall Hooked_WindowProc(void* thisptr, void* edx, HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//ConMsg("WindowProc: %.3f\n", m_mouseSampleTime);

	switch (uMsg)
	{
	case WM_INPUT:
		{
			m_mouseSampleTime = Plat_FloatTime();
			break;
		}
	}

	return oWindowProc(thisptr, hwnd, uMsg, wParam, lParam);
}

void __fastcall Hooked_GetAccumulatedMouseDeltasAndResetAccumulators(void* thisptr, void* edx, float* mx, float* my)
{
	GetAccumulatedMouseDeltasAndResetAccumulators(mx, my, mouseMoveFrameTime);

	mouseMoveFrameTime = 0.0;

	//ConMsg("test: %.5f\n", mouseMoveFrameTime);

	//oGetAccumulatedMouseDeltasAndResetAccumulators(thisptr, mx, my);
}

void __fastcall Hooked_ControllerMove(void* thisptr, void* edx, float ft, void* cmd)
{
	mouseMoveFrameTime = ft;

	oControllerMove(thisptr, mouseMoveFrameTime, cmd);
}

void __fastcall Hooked_IN_SetSampleTime(void* thisptr, void* edx, float frametime)
{
	m_flMouseSampleTime = frametime;

	oIn_SetSampleTime(thisptr, frametime);
}

BOOL IsProcessRunning(DWORD processID)
{
	HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, processID);
	DWORD ret = WaitForSingleObject(process, 0);
	CloseHandle(process);
	return ret == WAIT_TIMEOUT;
}

// https://stackoverflow.com/questions/10866311/getmessage-with-a-timeout/10866328#10866328
BOOL GetMessageWithTimeout(MSG* msg, UINT to)
{
	BOOL res;
	UINT_PTR timerId = SetTimer(NULL, NULL, to, NULL);
	res = GetMessage(msg, NULL, 0, 0);
	KillTimer(NULL, timerId);
	if (!res)
		return FALSE;
	if (msg->message == WM_TIMER && msg->hwnd == NULL && msg->wParam == timerId)
		return FALSE; //TIMEOUT! You could call SetLastError() or something...
	return TRUE;
}

DWORD InjectionEntryPoint(DWORD processID)
{
	LoadLibraryA("VCRUNTIME140.dll");

	auto inputsystem_factory = reinterpret_cast<CreateInterfaceFn>(GetProcAddress(GetModuleHandleA("inputsystem.dll"), "CreateInterface"));
	g_InputSystem = reinterpret_cast<IInputSystem*>(inputsystem_factory("InputSystemVersion001", nullptr));
	g_Input = **reinterpret_cast<CInput***>(FindPattern("client.dll", "8B 0D ? ? ? ? 8B 01 FF 60 44") + 2);

	oGetRawMouseAccumulators = (GetRawMouseAccumulatorsFn)(FindPattern("inputsystem.dll", "55 8B EC 8B 45 08 8B 91 9C 11 00 00"));
	oWindowProc = (WindowProcFn)(FindPattern("inputsystem.dll", "55 8B EC 83 EC 20 57"));
	oGetAccumulatedMouseDeltasAndResetAccumulators = (GetAccumulatedMouseDeltasAndResetAccumulatorsFn)(FindPattern("client.dll", "55 8B EC 53 8B 5D 0C 56 8B F1 57"));
	oControllerMove = (ControllerMoveFn)(FindPattern("client.dll", "55 8B EC 56 8B F1 57 8B 7D 0C 80 BE 8C 00 00 00 00"));
	oIn_SetSampleTime = (In_SetSampleTimeFn)(FindPattern("client.dll", "55 8B EC F3 0F 10 45 08 F3 0F 11 41 1C"));

	uintptr_t tier = (uintptr_t)GetModuleHandleA("tier0.dll");
	ConMsg = (ConMsgFn)(uintptr_t)GetProcAddress((HMODULE)tier, "?ConMsg@@YAXPBDZZ");
	Plat_FloatTime = (Plat_FloatTimeFn)(uintptr_t)GetProcAddress((HMODULE)tier, "Plat_FloatTime");

	//ConMsg("Plat_FloatTime: %.5f\n", Plat_FloatTime());

	BYTE nopBuffer[6] = { 0x90,0x90,0x90,0x90,0x90,0x90 };
	BYTE jumpPredOriginalBytes[6];
	auto jumpPred = reinterpret_cast<void*>(FindPattern("client.dll", "85 C0 8B 46 08 0F 84 ? FF FF FF F6 40 28 02 0F 85 ? FF FF FF") + 15);
	memcpy(jumpPredOriginalBytes, jumpPred, 6);
	DWORD jumpPredOriginalProtect;
	VirtualProtect(jumpPred, 6, PAGE_EXECUTE_READWRITE, &jumpPredOriginalProtect);
	memcpy(jumpPred, nopBuffer, 6);

	auto pReleaseVideo = reinterpret_cast<void*>(FindPattern("engine.dll", "56 8B F1 8B 06 8B 40 ? FF D0 84 C0 75 ? 8B 06") + 12);
	auto pFUCKD3D9 = reinterpret_cast<void*>(FindPattern("d3d9.dll", "0F 84 ? ? ? ? 6A 07 FF B3"));
	DWORD pReleaseVideoOriginalProtect, pFUCKD3D9OriginalProtect;
	VirtualProtect(pReleaseVideo, 1, PAGE_EXECUTE_READWRITE, &pReleaseVideoOriginalProtect);
	VirtualProtect(pFUCKD3D9, 2, PAGE_EXECUTE_READWRITE, &pFUCKD3D9OriginalProtect);

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)oGetRawMouseAccumulators, Hooked_GetRawMouseAccumulators);
	DetourAttach(&(PVOID&)oWindowProc, Hooked_WindowProc);
	DetourAttach(&(PVOID&)oGetAccumulatedMouseDeltasAndResetAccumulators, Hooked_GetAccumulatedMouseDeltasAndResetAccumulators);
	DetourAttach(&(PVOID&)oControllerMove, Hooked_ControllerMove);
	DetourAttach(&(PVOID&)oIn_SetSampleTime, Hooked_IN_SetSampleTime);
	DetourTransactionCommit();

	bool jumpPredPatched = true;
	bool fullScreenPatched = false;

	RegisterHotKey(NULL, 1, MOD_NOREPEAT, VK_F5);
	RegisterHotKey(NULL, 2, MOD_NOREPEAT, VK_F6);

	while (IsProcessRunning(processID))
	//while(FindWindowA(NULL, "CS:S RawInput2") != 0)
	{
		MSG msg;
		if (GetMessageWithTimeout(&msg, 200))
		{
			if (msg.message == WM_HOTKEY && msg.wParam == 1)
			{
				if (jumpPredPatched)
					memcpy(jumpPred, jumpPredOriginalBytes, 6);
				else
					memcpy(jumpPred, nopBuffer, 6);
				jumpPredPatched = !jumpPredPatched;
			}
			else if (msg.message == WM_HOTKEY && msg.wParam == 2)
			{
				if (fullScreenPatched)
				{
					memcpy(pReleaseVideo, "\x75", 1);
					memcpy(pFUCKD3D9, "\x0F\x84", 2);
				}
				else
				{
					memcpy(pReleaseVideo, "\xEB", 1);
					memcpy(pFUCKD3D9, "\x90\xE9", 2);
				}
				fullScreenPatched = !fullScreenPatched;
			}
		}

		//Sleep(55);
	}

	UnregisterHotKey(NULL, 1);
	UnregisterHotKey(NULL, 2);

	memcpy(pReleaseVideo, "\x75", 1);
	memcpy(pFUCKD3D9, "\x0F\x84", 2);
	VirtualProtect(pReleaseVideo, 1, pReleaseVideoOriginalProtect, &pReleaseVideoOriginalProtect);
	VirtualProtect(pFUCKD3D9, 2, pFUCKD3D9OriginalProtect, &pFUCKD3D9OriginalProtect);
	memcpy(jumpPred, jumpPredOriginalBytes, 6);
	VirtualProtect(jumpPred, 6, jumpPredOriginalProtect, &jumpPredOriginalProtect);

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)oGetRawMouseAccumulators, Hooked_GetRawMouseAccumulators);
	DetourDetach(&(PVOID&)oWindowProc, Hooked_WindowProc);
	DetourDetach(&(PVOID&)oGetAccumulatedMouseDeltasAndResetAccumulators, Hooked_GetAccumulatedMouseDeltasAndResetAccumulators);
	DetourDetach(&(PVOID&)oControllerMove, Hooked_ControllerMove);
	DetourDetach(&(PVOID&)oIn_SetSampleTime, Hooked_IN_SetSampleTime);
	DetourTransactionCommit();

	ExitThread(0);
	return 0;
}

//Credits: https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes
void PEInjector(DWORD processID, DWORD Func(DWORD))
{
	// Get current image's base address
	PVOID imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	// Allocate a new memory block and copy the current PE image to this new memory block
	PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

	// Open the target process - this is process we will be injecting this PE into
	HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, processID);

	// Allote a new memory block in the target process. This is where we will be injecting this PE
	PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Calculate delta between addresses of where the image will be located in the target process and where it's located currently
	DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

	// Relocate localImage, to ensure that it will have correct addresses once its in the target process
	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD relocationEntriesCount = 0;
	PDWORD_PTR patchedAddress;
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	while (relocationTable->SizeOfBlock > 0)
	{
		relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

		for (DWORD i = 0; i < relocationEntriesCount; i++)
		{
			if (relocationRVA[i].Offset)
			{
				patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
				*patchedAddress += deltaImageBase;
			}
		}
		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}

	// Write the relocated localImage into the target process
	WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);

	// Start the injected PE inside the target process
	CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)Func + deltaImageBase), (LPVOID)GetCurrentProcessId(), 0, NULL);
}

// Assumes the libraryfolders.vdf is "well formed"
std::string GetCSSPath()
{
	HKEY key;
	RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", &key);
	char buf[256];
	DWORD size = sizeof(buf) / sizeof(buf[0]);
	RegQueryValueExA(key, "InstallPath", 0, NULL, (BYTE*)buf, &size);
	auto steampath = std::string(buf);

	std::ifstream libraryfolders(steampath + "\\steamapps\\libraryfolders.vdf");
	std::string line, css_path, library_path;
	while (std::getline(libraryfolders, line))
	{
#define PPPPP "\t\t\"path\"\t\t\""
		if (line.rfind(PPPPP, 0) == 0)
		{
			library_path = line.substr(sizeof(PPPPP) - 1, line.size() - sizeof(PPPPP));
		}
		if (line.rfind("\t\t\t\"240\"", 0) == 0)
		{
			css_path = library_path;
			break;
		}
	}
	if (css_path != "")
		css_path += "\\steamapps\\common\\Counter-Strike Source\\";
	return css_path;
}

//Сredits: https://github.com/alkatrazbhop/BunnyhopAPE
int main()
{
	SetConsoleTitle("CS:S RawInput2 + BunnyhopAPE");

	auto css_path = GetCSSPath();
	auto css_exe = css_path + "hl2.exe";
#if 1
	char launch_options[] = "-steam -game cstrike -insecure -novid -console";
#else
	char launch_options[] = "-steam -game cstrike -insecure -novid";
#endif
	PROCESS_INFORMATION pi = {};
	STARTUPINFOA si = {};
	CreateProcessA(css_exe.c_str(), launch_options, NULL, NULL, FALSE, 0, NULL, css_path.c_str(), &si, &pi);

	HANDLE g_hProcess = pi.hProcess;
	DWORD processID = pi.dwProcessId;

	while (1)
	{
		DWORD pClient = (DWORD)GetModuleHandleExtern(processID, "client.dll");
		if (pClient) break;
		Sleep(1000);
	}

	DWORD pHL = (DWORD)GetModuleHandleExtern(processID, "hl2.exe");
	DWORD* pCmdLine = (DWORD*)(FindPatternEx(g_hProcess, pHL, 0x4000, (PBYTE)"\x85\xC0\x79\x08\x6A\x08", "xxxxxx") - 0x13);
	char* cmdLine = new char[255];
	ReadProcessMemory(g_hProcess, pCmdLine, &pCmdLine, sizeof(DWORD), NULL);
	ReadProcessMemory(g_hProcess, pCmdLine, &pCmdLine, sizeof(DWORD), NULL);
	ReadProcessMemory(g_hProcess, pCmdLine, cmdLine, 255, NULL);
	if (!strstr(cmdLine, " -insecure"))
		Error("-insecure key is missing!");

	system("cls");
	printf("Set \"m_rawinput 2\" in game for it to take effect\n\nPress F5 to toggle BunnyhopAPE autobhop prediction (on by default)\nPress F6 to toggle the fullscreen hook (you probably don't want this)\n");

	PEInjector(processID, InjectionEntryPoint);

	while (1)
	{
		if (WaitForSingleObject(g_hProcess, 0) != WAIT_TIMEOUT)
			return 0;
		if (_kbhit() && _getch() != VK_RETURN)
			return 0;
		Sleep(500);
	}
	return 0;
}