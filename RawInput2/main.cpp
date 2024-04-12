#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <urlmon.h> // URLDownloadToFileW
#include <wininet.h> // DeleteUrlCacheEntryW
#include <fstream>
#include <string>
#include <conio.h>
#include <stdio.h>
#include "utils.h"
#include "Detours/detours.h"

#pragma comment(lib, "Urlmon.lib") // URLDownloadToFileW
#pragma comment(lib, "Wininet.lib") // DeleteUrlCacheEntryW

#define HAXOR_BSP_PERIODS 1

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

typedef void(__thiscall* CDownloadManager_UpdateProgressBarFn)(void*);
typedef void(__stdcall* CEngineVGui_UpdateCustomProgressBarFn)(float, const wchar_t*);
typedef void(__thiscall* DownloadCache_PersistToDiskFn)(void*, void*);
typedef bool(__stdcall* DecompressBZipToDiskFn)(const char*, const char*, char*, int);
typedef int(__stdcall* BZ2_bzreadFn)(int, int, int);

CDownloadManager_UpdateProgressBarFn oCDownloadManager_UpdateProgressBar;
CEngineVGui_UpdateCustomProgressBarFn oCEngineVGui_UpdateCustomProgressBar;
DownloadCache_PersistToDiskFn oDownloadCache_PersistToDisk;
DecompressBZipToDiskFn oDecompressBZipToDisk;
BZ2_bzreadFn oBZ2_bzread;

typedef void(__thiscall* CHostState_OnClientConnectedFn)(void*);
CHostState_OnClientConnectedFn oCHostState_OnClientConnected;

typedef bool(__thiscall* CClientState_ProcessServerInfoFn)(void*, void*);
CClientState_ProcessServerInfoFn oCClientState_ProcessServerInfo;
typedef bool(__stdcall* MD5_MapFileFn)(char* buf, const char* map);
MD5_MapFileFn MD5_MapFile;
typedef void(__thiscall* CDownloadManager_QueueFn)(void*, char*, char*, char*);
CDownloadManager_QueueFn oCDownloadManager_Queue;
typedef void(__thiscall* CDownloadManager_CheckActiveDownloadFn)(void*);
CDownloadManager_CheckActiveDownloadFn oCDownloadManager_CheckActiveDownload;
//typedef void(__thiscall* CDownloadManager_QueueInternalFn)(void*, const char*, const char*, const char*, bool, bool);
//CDownloadManager_QueueInternalFn oCDownloadManager_QueueInternal;

//typedef bool(__thiscall* C_SoundscapeSystem_InitFn)(void*);
//C_SoundscapeSystem_InitFn oC_SoundscapeSystem_Init;
typedef void(__thiscall* CHLClient_LevelInitPreEntityFn)(void*, const char*);
CHLClient_LevelInitPreEntityFn oCHLClient_LevelInitPreEntity;

// NOTE: __thiscall for the typedefs so the original function is called correctly.
//       __fastcall for the hook function because msvc won't let you use thiscall outside of member declarations...
//       thiscall = ecx, then stack
//       fastcall = ecx, edx, then stack. That's why the fastcall funcs have a void* edx argument.
//         (so we have the rest of the parameters be on stack and then ignore edx)

typedef void(__cdecl* ConMsgFn)(const char*, ...);
ConMsgFn ConMsg;

typedef double(__cdecl* Plat_FloatTimeFn)();
Plat_FloatTimeFn Plat_FloatTime;

float mouseMoveFrameTime;

double m_mouseSplitTime;
double m_mouseSampleTime;
float m_flMouseSampleTime;

DWORD haxorThreadID;

char* g_lump_checksums{};
char g_matching_map_sha1[40+1]{};
char g_server_lumps_md5_bytes[16]{};
char g_server_map[260]{};
bool g_hijack_map = false;
bool g_we_have_queued_after_a_404 = false;

struct request_t {
	char _pad0; // originally missed this padding. whoops.
	char _pad1;
	char bz2;
	char http;
	int _pad2;
	int state;
	int _pad3;
	int _pad4;
	char sv_downloadurl[256];
	char urlpath[256];
	char fullpath[256];
	char relativepath[256];
	char _buf3[256];
	char _pad5;
	char _buf4[256];
	int total;
	int current;
};
struct dlman_t {
	void** vtable;
	char _pre[0x14];
	struct request_t* req;
};

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
	case WM_SYSKEYDOWN:
	case WM_KEYDOWN:
		{
			// bit 30: "The previous key state. The value is 1 if the key is down before the message is sent, or it is zero if the key is up."
			if ((lParam & 0x40000000) == 0) {
				if (wParam == VK_F5 || wParam == VK_F6 || wParam == VK_F7) {
					PostThreadMessageA(haxorThreadID, WM_HOTKEY, wParam - VK_F5 + 1, 0);
				}
			}
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

static int downloadBytesCurrent, downloadBytesTotal, downloadShowBytes;
void __fastcall Hooked_CDownloadManager_UpdateProgressBar(struct dlman_t* thisptr, void* edx)
{
	if (thisptr->req && thisptr->req->http)
	{
		downloadBytesCurrent = thisptr->req->current;
		downloadBytesTotal = thisptr->req->total;
		downloadShowBytes = 1;
	}

	oCDownloadManager_UpdateProgressBar(thisptr);
}

void __stdcall Hooked_CEngineVGui_UpdateCustomProgressBar(float progress, const wchar_t* ws)
{
	wchar_t buf[256];

	if (downloadShowBytes)
	{
		ws = &ws[12]; // skip "Downloading "
		if (wcsstr(ws, L"maps/") == ws)
			ws = &ws[5];
		_snwprintf(buf, sizeof(buf) / sizeof(buf[0]), L"DL %s (%dM/%dM)", ws, downloadBytesCurrent / 1024 / 1024, downloadBytesTotal / 1024 / 1024);
		progress = (float)downloadBytesCurrent / (float)downloadBytesTotal;
	}

	oCEngineVGui_UpdateCustomProgressBar(progress, downloadShowBytes ? buf : ws);

	downloadBytesCurrent = downloadBytesTotal = downloadShowBytes = 0;
}

void __fastcall Hooked_DownloadCache_PersistToDisk(void* thisptr, void* edx, void* req)
{
	oCEngineVGui_UpdateCustomProgressBar(0.0, L"Writing to disk...");
	oDownloadCache_PersistToDisk(thisptr, req);
	oCEngineVGui_UpdateCustomProgressBar(100.0, L"Done...");
}

static int totalBz2, bz2Iter;
bool __stdcall Hooked_DecompressBZipToDisk(const char* outfile, const char* srcfile, char* data, int totalbytes)
{
	oCEngineVGui_UpdateCustomProgressBar(0.0, L"Decompressing bz2 to disk...");
	totalBz2 = bz2Iter = 0;
	return oDecompressBZipToDisk(outfile, srcfile, data, totalbytes);
}

int __stdcall Hooked_BZ2_bzread(int a, int b, int c)
{
	int x = oBZ2_bzread(a, b, c);
	if (x > 0)
	{
		totalBz2 += x;

		if (!(++bz2Iter % 16))
		{
			wchar_t buf[256];
			_snwprintf(buf, sizeof(buf) / sizeof(buf[0]), L"Bytes uncompressed and written: %dM", totalBz2 / 1024 / 1024);
			oCEngineVGui_UpdateCustomProgressBar(0.0, buf);
		}
	}
	else if (x == 0)
	{
		oCEngineVGui_UpdateCustomProgressBar(100.0, L"Done...");
	}
	else if (x < 0)
	{
		oCEngineVGui_UpdateCustomProgressBar(0.0, L"bz2 error");
	}
	return x;
}

void __fastcall Hooked_CHostState_OnClientConnected(void* thisptr)
{
	oCHostState_OnClientConnected(thisptr);
	FlashWindow(FindWindowA("Valve001", NULL), TRUE);
}

void DownloadLumpChecksums()
{
	wchar_t lump_checksums[MAX_PATH];
	GetTempPathW(sizeof(lump_checksums)/sizeof(wchar_t), lump_checksums);
	wcscat(lump_checksums, L"lump_checksums.csv");
	WIN32_FILE_ATTRIBUTE_DATA attr;
	bool needs_download = true;

	if (GetFileAttributesExW(lump_checksums, GetFileExInfoStandard, &attr))
	{
		UINT64 currenttime;
		GetSystemTimeAsFileTime((LPFILETIME)&currenttime);
		INT64 difference = currenttime - *(UINT64*)&attr.ftLastWriteTime;
		if (difference < 0) difference = -difference;
		// a FILETIME is how many 100 nanoseconds since January 1, 1601.
		if (difference < (10ull * 1000 * 1000 * 60 * 60 * 36)) // -> micro -> milli -> second -> minute -> hour -> X
			needs_download = false;
	}

	if (needs_download)
	{
		printf("downloading https://venus.fastdl.me/lump_checksums.csv to %%TEMP%%\\lump_checksums.csv\nit's almost 4 megabytes so it might take a moment...\n\n");
		DeleteUrlCacheEntryW(L"https://venus.fastdl.me/lump_checksums.csv"); // fuck you windows
		HRESULT res = URLDownloadToFileW(NULL, L"https://venus.fastdl.me/lump_checksums.csv", lump_checksums, 0, NULL);
		DeleteUrlCacheEntryW(L"https://venus.fastdl.me/lump_checksums.csv"); // fuck you windows
	}
}
void ReadLumpChecksums()
{
	wchar_t lump_checksums[MAX_PATH];
	GetTempPathW(sizeof(lump_checksums) / sizeof(wchar_t), lump_checksums);
	wcscat(lump_checksums, L"lump_checksums.csv");

	// dumb
	HANDLE hFile = CreateFileW(lump_checksums, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD filesize = GetFileSize(hFile, NULL);
		char *filecontents = (char*)calloc(filesize + 1, 1);
		auto success = ReadFile(hFile, filecontents, filesize, NULL, NULL);
		CloseHandle(hFile);
		if (success)
			g_lump_checksums = filecontents;
		else
			free(filecontents);
	}
}
std::string bytes_to_hex(char* bytes, size_t len)
{
	char buf[101]{}; // sha1 = 40 characters. md5 = 32.
	for (auto i = 0; i < len; i++)
		sprintf(&buf[i*2], "%02x", (unsigned char)bytes[i]);
	return std::string(buf);
}
bool __fastcall Hooked_CClientState_ProcessServerInfo(void* thisptr, void* edx, char* msg)
{
	g_matching_map_sha1[0] = '\0';
	g_hijack_map = false;
	g_we_have_queued_after_a_404 = false;
	strcpy(g_server_map, *(char**)(msg + 0x44));

	if (g_lump_checksums)
	{
		memcpy(g_server_lumps_md5_bytes, msg + 0x20, sizeof(g_server_lumps_md5_bytes));

		auto md5string = bytes_to_hex(g_server_lumps_md5_bytes, sizeof(g_server_lumps_md5_bytes));
		// lump_checksums.csv is a well formed file of "sha1hash,md5hash\n"
		if (strchr(g_lump_checksums, '\r')) md5string.push_back('\r'); // fuck you
		md5string.push_back('\n');
		const char* found = strstr(g_lump_checksums, md5string.c_str());
		//MessageBoxA(0, md5string.c_str(), "server md5", MB_OK);

		if (found)
		{
			memcpy(g_matching_map_sha1, found - 41, 40);
			//auto sha1string = bytes_to_hex(g_matching_map_sha1, sizeof(g_matching_map_sha1));
			//MessageBoxA(0, sha1string.c_str(), sha1string.c_str(), MB_OK);

			char map[260];
			_snprintf(map, sizeof(map), "maps/%s.bsp", *(char**)(msg + 0x44));
			//memcpy(map, *(char**)((char*)msg + 0x44), sizeof(map));

			char mymd5bytes[16];
			if (MD5_MapFile(mymd5bytes, map))
			{
				//auto myhex = bytes_to_hex(mymd5bytes, sizeof(mymd5bytes));
				//MessageBoxA(0, myhex.c_str(), map, MB_OK);

				if (0 != memcmp(g_server_lumps_md5_bytes, mymd5bytes, 16))
				{
					// maps don't match...
					g_hijack_map = true;
					strcpy(*(char**)(msg + 0x44), g_matching_map_sha1);
				}
			}
			else
			{
				// we probably don't have the map downloaded so we're not going to hax things
			}
		}
		else
		{
			// fastdl.me does not have the map
		}
	}

	return oCClientState_ProcessServerInfo(thisptr, msg);
}
void __fastcall Righter_CDownloadManager_SetupURLPath(void* thisptr, void* edx, struct request_t* req, const char* urlpath)
{
	// The original SetupURLPath does strcpy(req->urlpath, req->relativepath) and completely ignores the `urlpath` function argument... frustrating...

	//MessageBoxA(0, urlpath ? urlpath : ".", req->relativepath, MB_OK);
	if (urlpath)
	{
		strcpy(req->urlpath, urlpath);
		if (req->bz2)
			strcat(req->urlpath, ".bz2");
	}
	else
	{
		strcpy(req->urlpath, req->relativepath);
	}
}
void Fix_CDownloadManager_SetupURLPath(struct dlman_t* thisptr)
{
	DWORD fuck;
	VirtualProtect(thisptr->vtable, 64, PAGE_READWRITE, &fuck);
	thisptr->vtable[4] = Righter_CDownloadManager_SetupURLPath;
}
void __fastcall Hooked_CDownloadManager_Queue(void* thisptr, void* edx, char* sv_downloadurl, char* bleh, char* file)
{
#if 0
	if (0 == strncmp(file, "~/map/sha1:", 11))
	{
		// stuff...
	}
#endif

	bool is_map = !strncmp("maps\\", file, 5) && !strncmp(".bsp", &file[strlen(file) - 4], 4);

	if (g_hijack_map && is_map)
	{
		g_hijack_map = false;
		//MessageBoxA(0, file, file, MB_OK);

		Fix_CDownloadManager_SetupURLPath((struct dlman_t*)thisptr);

		char urlbuf[256], filebuf[256];
		_snprintf(filebuf, sizeof(filebuf), "maps/%s.bsp", g_matching_map_sha1);
		_snprintf(urlbuf, sizeof(urlbuf), "hashed/%s.bsp", g_matching_map_sha1);
		oCDownloadManager_Queue(thisptr, "http://main.fastdl.me/", urlbuf, filebuf);
	}
	else
	{
		oCDownloadManager_Queue(thisptr, sv_downloadurl, bleh, file);
	}
}
void __fastcall Hooked_CDownloadManager_CheckActiveDownload(struct dlman_t* thisptr)
{
	if (!g_we_have_queued_after_a_404 && g_matching_map_sha1[0] != '\0' && thisptr->req && thisptr->req->http && thisptr->req->state == 4 && !thisptr->req->bz2)
	{
		//MessageBoxA(0, thisptr->req->urlpath ? thisptr->req->urlpath : ".", thisptr->req->relativepath, MB_OK);
		auto len = strlen(thisptr->req->relativepath);
		if (len >= 10 && 0 == strncmp(thisptr->req->relativepath, "maps/", 5) && 0 == strcmp(&thisptr->req->relativepath[len - 4], ".bsp"))
		{
			// Error downloading.
			g_we_have_queued_after_a_404 = true;

			Fix_CDownloadManager_SetupURLPath(thisptr);

			char urlbuf[256];
			_snprintf(urlbuf, sizeof(urlbuf), "hashed/%s.bsp", g_matching_map_sha1);
			oCDownloadManager_Queue(thisptr, "http://main.fastdl.me/", urlbuf, thisptr->req->urlpath);
			//MessageBoxA(0, thisptr->req->urlpath, urlbuf, MB_OK);
		}
	}
	oCDownloadManager_CheckActiveDownload(thisptr);
}
#if 0
void __fastcall Hooked_CDownloadManager_QueueInternal(void* thisptr, void* edx, const char* sv_downloadurl, const char* urlpath, const char* relativepath, bool http, bool bz2)
{
	char buf[1024];
	_snprintf(buf, sizeof(buf), "sv_downloadurl = \"%s\"\nurlpath = \"%s\"\nrelativepath = \"%s\"\nhttp = %d\nbz2 = %d", sv_downloadurl, pURLPath, relativepath, http, bz2);
	MessageBoxA(0, buf, ".", MB_OK);
	oCDownloadManager_QueueInternal(thisptr, sv_downloadurl, urlpath, relativepath, http, bz2);
}
#endif

#if HAXOR_BSP_PERIODS
bool __stdcall is_okay_name_end(const char* extension, int check_if_bsp)
{
	if (check_if_bsp)
		return 0 == strcmp(strrchr(extension, '.'), ".bsp"); // only good if equals ".bsp"
	else
		return 0 == strchr(extension, ' '); // only good if no ' '
}
__declspec(naked) void Hack_IsValidFileForTransfer_For_Periods_In_Bsp_Name()
{
	__asm {
		push eax // 0 == extension passed the length & type checks. we don't have to do anything else but the last check (for a space).
		push esi // extension string
		call is_okay_name_end
		// copy of the stack resetting code from original function...
		pop esi
		pop edi
		mov esp, ebp
		pop ebp
		// return address of original function is still on stack. so ret with it...
		ret
	}
}
#endif

#if 0
char** s_pMapName = NULL;
bool __fastcall Hooked_C_SoundscapeSystem_Init(void* thisptr)
{
	//if (*s_pMapName) MessageBoxA(0, *s_pMapName, *s_pMapName, 0);
	if (!s_pMapName || !*s_pMapName || !**s_pMapName) return oC_SoundscapeSystem_Init(thisptr);
	char* original_mapname = *s_pMapName;
	//*s_pMapName = "bhop_badges";
	//*s_pMapName = g_server_map;
	//DebugBreak();
	bool ret = oC_SoundscapeSystem_Init(thisptr);

	if (original_mapname) *s_pMapName = original_mapname;

	return ret;
}
#endif

void __fastcall Hooked_CHLClient_LevelInitPreEntity(void* thisptr, void* edx, const char* mapname)
{
	char* end = max(strrchr(g_server_map, '/'), strrchr(g_server_map, '\\'));
	return oCHLClient_LevelInitPreEntity(thisptr, end ? end + 1 : g_server_map);
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

void RecvProxy_ZeroToVector(const void* fuck1, void* fuck2, float* fuck3)
{
	for (int i = 0; i < 3; i++)
		fuck3[i] = 0.0;
}

DWORD InjectionEntryPoint(DWORD processID)
{
	LoadLibraryA("VCRUNTIME140.dll");

	haxorThreadID = GetCurrentThreadId();
	ReadLumpChecksums();

	auto inputsystem_factory = reinterpret_cast<CreateInterfaceFn>(GetProcAddress(GetModuleHandleA("inputsystem.dll"), "CreateInterface"));
	g_InputSystem = reinterpret_cast<IInputSystem*>(inputsystem_factory("InputSystemVersion001", nullptr));
	g_Input = **reinterpret_cast<CInput***>(FindPattern("client.dll", "8B 0D ? ? ? ? 8B 01 FF 60 44") + 2);

	oGetRawMouseAccumulators = (GetRawMouseAccumulatorsFn)(FindPattern("inputsystem.dll", "55 8B EC 8B 45 08 8B 91 9C 11 00 00"));
	oWindowProc = (WindowProcFn)(FindPattern("inputsystem.dll", "55 8B EC 83 EC 20 57"));
	oGetAccumulatedMouseDeltasAndResetAccumulators = (GetAccumulatedMouseDeltasAndResetAccumulatorsFn)(FindPattern("client.dll", "55 8B EC 53 8B 5D 0C 56 8B F1 57"));
	oControllerMove = (ControllerMoveFn)(FindPattern("client.dll", "55 8B EC 56 8B F1 57 8B 7D 0C 80 BE 8C 00 00 00 00"));
	oIn_SetSampleTime = (In_SetSampleTimeFn)(FindPattern("client.dll", "55 8B EC F3 0F 10 45 08 F3 0F 11 41 1C"));

	oCDownloadManager_UpdateProgressBar = (CDownloadManager_UpdateProgressBarFn)(FindPattern("engine.dll", "55 8B EC 81 EC 10 02 00 00 56"));
	oCEngineVGui_UpdateCustomProgressBar = (CEngineVGui_UpdateCustomProgressBarFn)(FindPattern("engine.dll", "55 8B EC 81 EC 00 04 00 00 83 3D ? ? ? ? 00"));
	oDownloadCache_PersistToDisk = (DownloadCache_PersistToDiskFn)(FindPattern("engine.dll", "55 8B EC 81 EC 08 02 00 00 53 8B D9"));
	oDecompressBZipToDisk = (DecompressBZipToDiskFn)(FindPattern("engine.dll", "55 8B EC B8 14 03 01 00"));
	oBZ2_bzread = (BZ2_bzreadFn)(FindPattern("engine.dll", "55 8B EC 8B 45 ? 83 B8 ? ? ? ? 04"));

	oCHostState_OnClientConnected = (CHostState_OnClientConnectedFn)(FindPattern("engine.dll", "55 8B EC 83 EC 0C 56 8B F1 80 BE ? ? ? ? 00 0F 84"));

	oCClientState_ProcessServerInfo = (CClientState_ProcessServerInfoFn)(FindPattern("engine.dll", "55 8B EC 56 57 8B F1 E8 ? ? ? ? 8B 7D"));
	MD5_MapFile = (MD5_MapFileFn)(FindPattern("engine.dll", "55 8B EC 81 EC 6C 08 00 00"));
	oCDownloadManager_Queue = (CDownloadManager_QueueFn)(FindPattern("engine.dll", "55 8B EC 51 53 8B 5D ? 56 8B F1 53"));
	oCDownloadManager_CheckActiveDownload = (CDownloadManager_CheckActiveDownloadFn)(FindPattern("engine.dll", "55 8B EC 51 56 8B F1 8B 4E ? 57"));
	//oCDownloadManager_QueueInternal = (CDownloadManager_QueueInternalFn)(FindPattern("engine.dll", "55 8B EC 81 EC 0C 02 00 00 53 8B D9 57"));
	//oC_SoundscapeSystem_Init = (C_SoundscapeSystem_InitFn)(FindPattern("client.dll", "55 8B EC 51 53 8B D9 57 C7 83 ? ? ? ? 00 00 00 00"));
	//s_pMapName = (char**)(((DWORD)GetModuleHandleA("client.dll")) + 0x4f3924); // can't be arsed to make this dynamic
	oCHLClient_LevelInitPreEntity = (CHLClient_LevelInitPreEntityFn)(FindPattern("client.dll", "55 8B EC 80 3D ? ? ? ? 00 0F 85 ? ? ? ? 8B 0D"));

#if HAXOR_BSP_PERIODS
	auto EndOf_IsValidFileForTransfer = (void**)FindPattern("engine.dll", "75 ? 6A 20 56");
	DWORD dummy;
	VirtualProtect(EndOf_IsValidFileForTransfer, 16, PAGE_EXECUTE_READWRITE, &dummy);
	unsigned char shellcode[] = {
		// overwrite jnz to block exit after failed ".sw.vtx" check...
		0x90, // nop
		0x90, // nop
		// absolute address "jump"...
		0x68, 0x78, 0x56, 0x34, 0x12, // push 0x12345678
		0xC3, // ret
	};
	*(void**)(shellcode + 3) = Hack_IsValidFileForTransfer_For_Periods_In_Bsp_Name;
	memcpy(EndOf_IsValidFileForTransfer, shellcode, sizeof(shellcode));
#endif

#if 0
	// This is used so `download_debug` will actually print the fucking messages!!!
	// I could not figure out how to get the spew to work because the `developer` cvar kept resetting to 0. Frustrating.
	// I wanted to set the ConDColorMsg IAT entry to point to ConColorMsg but that's why more work than this stupid piece of shit.
	auto condcolormsg_spew_check = (char*)FindPattern("tier0.dll", "83 7C ? ? 02 EB ? 83 3D ? ? ? ? 02 0F 9D C0 84 C0 74 ? 56 8B 35 ? ? ? ? 8D 45 ? 50 FF 75 ? 8D 85 ? ? ? ? 68 9B 13 00 00 50 E8 ? ? ? ? 83 C4 10 83 F8 FF 74 ? 8B 45");
	DWORD fucky;
	VirtualProtect(condcolormsg_spew_check, 6, PAGE_EXECUTE_READWRITE, &fucky);
	condcolormsg_spew_check[4] = 0;
#endif

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

	BYTE prleNew[6] = { 0x5e,   0x5f,   0x5d,   0xc2, 0x04, 0x00 }; // pop esi ; pop edi ; pop ebp ; ret 0x4
	BYTE prleOriginal[6];
	auto pFuckPlayerRoughLandingEffects = reinterpret_cast<void*>(FindPattern("client.dll", "55 8B EC F3 0F 10 45 ? 0F 2F 05 ? ? ? ? 57") + 73 /* after ->PlayStepSound */);
	memcpy(prleOriginal, pFuckPlayerRoughLandingEffects, 6);
	DWORD pFuckPlayerRoughtLandingEffectsOriginalProtect;
	VirtualProtect(pFuckPlayerRoughLandingEffects, 2, PAGE_EXECUTE_READWRITE, &pFuckPlayerRoughtLandingEffectsOriginalProtect);
	memcpy(pFuckPlayerRoughLandingEffects, prleNew, 6);
	auto m_vecPunchAngle_RecvProp = (void**)((DWORD)GetModuleHandleA("client.dll") + 0x4c8c40);
	auto m_vecPunchAngle_RecvProp_Original = m_vecPunchAngle_RecvProp[8];
	m_vecPunchAngle_RecvProp[8] = RecvProxy_ZeroToVector;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)oGetRawMouseAccumulators, Hooked_GetRawMouseAccumulators);
	DetourAttach(&(PVOID&)oWindowProc, Hooked_WindowProc);
	DetourAttach(&(PVOID&)oGetAccumulatedMouseDeltasAndResetAccumulators, Hooked_GetAccumulatedMouseDeltasAndResetAccumulators);
	DetourAttach(&(PVOID&)oControllerMove, Hooked_ControllerMove);
	DetourAttach(&(PVOID&)oIn_SetSampleTime, Hooked_IN_SetSampleTime);
	DetourAttach(&(PVOID&)oCEngineVGui_UpdateCustomProgressBar, Hooked_CEngineVGui_UpdateCustomProgressBar);
	DetourAttach(&(PVOID&)oCDownloadManager_UpdateProgressBar, Hooked_CDownloadManager_UpdateProgressBar);
	DetourAttach(&(PVOID&)oDownloadCache_PersistToDisk, Hooked_DownloadCache_PersistToDisk);
	DetourAttach(&(PVOID&)oDecompressBZipToDisk, Hooked_DecompressBZipToDisk);
	DetourAttach(&(PVOID&)oBZ2_bzread, Hooked_BZ2_bzread);
	DetourAttach(&(PVOID&)oCHostState_OnClientConnected, Hooked_CHostState_OnClientConnected);
	DetourAttach(&(PVOID&)oCClientState_ProcessServerInfo, Hooked_CClientState_ProcessServerInfo);
	DetourAttach(&(PVOID&)oCDownloadManager_Queue, Hooked_CDownloadManager_Queue);
	DetourAttach(&(PVOID&)oCDownloadManager_CheckActiveDownload, Hooked_CDownloadManager_CheckActiveDownload);
	//DetourAttach(&(PVOID&)oCDownloadManager_QueueInternal, Hooked_CDownloadManager_QueueInternal);
	//DetourAttach(&(PVOID&)oC_SoundscapeSystem_Init, Hooked_C_SoundscapeSystem_Init);
	DetourAttach(&(PVOID&)oCHLClient_LevelInitPreEntity, Hooked_CHLClient_LevelInitPreEntity);
	DetourTransactionCommit();

	bool jumpPredPatched = true;
	bool fullScreenPatched = false;
	bool fuckViewpunch = true;

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
			else if (msg.message == WM_HOTKEY && msg.wParam == 3)
			{
				if (fuckViewpunch) {
					memcpy(pFuckPlayerRoughLandingEffects, prleOriginal, 6);
					m_vecPunchAngle_RecvProp[8] = m_vecPunchAngle_RecvProp_Original;
				} else {
					memcpy(pFuckPlayerRoughLandingEffects, prleNew, 6);
					m_vecPunchAngle_RecvProp[8] = RecvProxy_ZeroToVector;
				}
				fuckViewpunch = !fuckViewpunch;
			}
		}

		//Sleep(55);
	}

	memcpy(pFuckPlayerRoughLandingEffects, prleOriginal, 6);
	m_vecPunchAngle_RecvProp[8] = m_vecPunchAngle_RecvProp_Original;
	VirtualProtect(pFuckPlayerRoughLandingEffects, 6, pFuckPlayerRoughtLandingEffectsOriginalProtect, &pFuckPlayerRoughtLandingEffectsOriginalProtect);
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
	// The game would crash when trying to spawn in after joining.
	// But only when these DetourDetach() calls were here.
	// It was CEngine... & the Decompress... one I believe...
	// Anyway, enabling "/hotpatch" (Create Hotpatchable Image) made it stop crashing.
	// Why? I still don't know. So annoying.
	DetourDetach(&(PVOID&)oCEngineVGui_UpdateCustomProgressBar, Hooked_CEngineVGui_UpdateCustomProgressBar);
	DetourDetach(&(PVOID&)oCDownloadManager_UpdateProgressBar, Hooked_CDownloadManager_UpdateProgressBar);
	DetourDetach(&(PVOID&)oDownloadCache_PersistToDisk, Hooked_DownloadCache_PersistToDisk);
	DetourDetach(&(PVOID&)oDecompressBZipToDisk, Hooked_DecompressBZipToDisk);
	DetourDetach(&(PVOID&)oBZ2_bzread, Hooked_BZ2_bzread);
	DetourDetach(&(PVOID&)oCHostState_OnClientConnected, Hooked_CHostState_OnClientConnected);
	DetourDetach(&(PVOID&)oCClientState_ProcessServerInfo, Hooked_CClientState_ProcessServerInfo);
	DetourDetach(&(PVOID&)oCDownloadManager_Queue, Hooked_CDownloadManager_Queue);
	DetourDetach(&(PVOID&)oCDownloadManager_CheckActiveDownload, Hooked_CDownloadManager_CheckActiveDownload);
	//DetourDetach(&(PVOID&)oCDownloadManager_QueueInternal, Hooked_CDownloadManager_QueueInternal);
	//DetourDetach(&(PVOID&)oC_SoundscapeSystem_Init, Hooked_C_SoundscapeSystem_Init);
	DetourDetach(&(PVOID&)oCHLClient_LevelInitPreEntity, Hooked_CHLClient_LevelInitPreEntity);
	DetourTransactionCommit();

	ExitThread(0);
	return 0;
}

//Credits: https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes
void PEInjector(HANDLE targetProcess, DWORD Func(DWORD))
{
	// Get current image's base address
	PVOID imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	// Allocate a new memory block and copy the current PE image to this new memory block
	PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

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

// https://stackoverflow.com/a/14678800
std::string ReplaceString(std::string subject, const std::string& search,
	const std::string& replace) {
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != std::string::npos) {
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
	return subject;
}

std::string GetSteamPath()
{
	HKEY key;
	RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", &key);
	char buf[256];
	DWORD size = sizeof(buf) / sizeof(buf[0]);
	RegQueryValueExA(key, "InstallPath", 0, NULL, (BYTE*)buf, &size);
	return std::string(buf);
}

// Assumes the libraryfolders.vdf is "well formed"
std::string GetCSSPath(std::string const & steampath)
{
	std::ifstream libraryfolders(steampath + "\\steamapps\\libraryfolders.vdf");
	std::string line, css_path, library_path;
	while (std::getline(libraryfolders, line))
	{
#define PPPPP "\t\t\"path\"\t\t\""
		if (line.rfind(PPPPP, 0) == 0)
		{
			library_path = line.substr(sizeof(PPPPP) - 1, line.size() - sizeof(PPPPP));
			library_path = ReplaceString(library_path, "\\\\", "\\");
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

std::string GetSteamID3()
{
	HKEY key;
	RegOpenKeyA(HKEY_CURRENT_USER, "SOFTWARE\\Valve\\Steam\\ActiveProcess", &key);
	DWORD steamid3, size = sizeof(steamid3);
	RegQueryValueExA(key, "ActiveUser", 0, NULL, (BYTE*)&steamid3, &size);
	return std::to_string(steamid3);
}

// Assumes "X:\Program Files (x86)\Steam\userdata\STEAMIDHERE\config\localconfig.vdf" is "well formed"
std::string GetCSSLaunchOptions(std::string const & steampath, std::string const & steamid3)
{
	std::ifstream localconfig(steampath + "\\userdata\\" + steamid3 + "\\config\\localconfig.vdf");
	std::string line;
	bool in_css = false;
	while (std::getline(localconfig, line))
	{
		if (line.rfind("\t\t\t\t\t\"240\"", 0) == 0)
			in_css = true;
		if (line.rfind("\t\t\t\t\t}", 0) == 0)
			in_css = false;
#define LLLLL "\t\t\t\t\t\t\"LaunchOptions\"\t\t\""
		if (in_css && line.rfind(LLLLL, 0) == 0)
		{
			line = line.substr(sizeof(LLLLL) - 1, line.size() - sizeof(LLLLL));
			line = ReplaceString(line, "\\\\", "\\");
			return line;
		}
#if 1
		// You're not going to believe it but this section is required to not crash when spawning in.
		for (int i = 0; i < 5; i++)
			(void)GetCurrentProcessId();
#endif
	}
	return "";
}

//Сredits: https://github.com/alkatrazbhop/BunnyhopAPE
int main()
{
	SetConsoleTitle("RawInput2BunnyhopAPE");

	DownloadLumpChecksums();

	//printf("%d\n", &(((struct request_t*)0)->total));

	auto steamid3 = GetSteamID3();
	printf("steamid3  = %s\n", steamid3.c_str());
	auto steam_path = GetSteamPath();
	printf("steampath = %s\n", steam_path.c_str());
	auto launch_options = GetCSSLaunchOptions(steam_path, steamid3);
	launch_options = "-steam -game cstrike -insecure -novid -console   " + launch_options;
	printf("launchopt = %s\n", launch_options.c_str());
	auto css_path = GetCSSPath(steam_path);
	printf("css path  = %s\n\n", css_path.c_str());
	auto css_exe = css_path + "hl2.exe";

	PROCESS_INFORMATION pi = {};
	STARTUPINFOA si = {};

	if (!CreateProcessA(css_exe.c_str(), (char*)launch_options.c_str(), NULL, NULL, FALSE, 0, NULL, css_path.c_str(), &si, &pi))
	{
		auto err = GetLastError();
		char* buf;
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);

		printf("CreateProcessA failed (0x%x): %s\n", err, buf);

		while (1)
		{
			if (_kbhit() && _getch() == VK_RETURN)
				return 0;
			Sleep(500);
		}

		return 1;
	}


	while (1)
	{
		DWORD pClient = (DWORD)GetModuleHandleExtern(pi.dwProcessId, "client.dll");
		if (pClient) break;
		Sleep(1000);
		DWORD exitcode;
		if (GetExitCodeProcess(pi.hProcess, &exitcode) && exitcode != STILL_ACTIVE)
			return 0;
	}

	//system("cls");
	printf("Set \"m_rawinput 2\" in game for it to take effect\n\nPress F5 to toggle BunnyhopAPE autobhop prediction (on by default)\nPress F6 to toggle the fullscreen hook (you probably don't want this)\nPress F7 to toggle the viewpunch remover (e.g. from fall-damage) (on by default)\n");

	PEInjector(pi.hProcess, InjectionEntryPoint);

	WaitForSingleObject(pi.hProcess, INFINITE);
	return 0;
}
