#define WIN32_LEAN_AND_MEAN TRUE
#define UNICODE TRUE
#include <windows.h>

#define WSOCK32_DIRECTORY_SIZE  200
#define WSOCK32_FUNCTIONS_COUNT 75

HMODULE g_hWinSock32 = NULL;
FARPROC g_lpWinSock32Functions[WSOCK32_FUNCTIONS_COUNT];

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        WCHAR pszBuffer[WSOCK32_DIRECTORY_SIZE];
        GetSystemDirectoryW(pszBuffer, WSOCK32_DIRECTORY_SIZE);
        wcscat_s(pszBuffer, WSOCK32_DIRECTORY_SIZE, L"\\WSOCK32.dll");

        g_hWinSock32 = LoadLibraryW(pszBuffer);
        if (g_hWinSock32 == NULL)
        {
            return FALSE;
        }

        g_lpWinSock32Functions[0]  = GetProcAddress(g_hWinSock32, "__WSAFDIsSet");
        g_lpWinSock32Functions[1]  = GetProcAddress(g_hWinSock32, "accept");
        g_lpWinSock32Functions[2]  = GetProcAddress(g_hWinSock32, "AcceptEx");
        g_lpWinSock32Functions[3]  = GetProcAddress(g_hWinSock32, "bind");
        g_lpWinSock32Functions[4]  = GetProcAddress(g_hWinSock32, "closesocket");
        g_lpWinSock32Functions[5]  = GetProcAddress(g_hWinSock32, "connect");
        g_lpWinSock32Functions[6]  = GetProcAddress(g_hWinSock32, "dn_expand");
        g_lpWinSock32Functions[7]  = GetProcAddress(g_hWinSock32, "EnumProtocolsA");
        g_lpWinSock32Functions[8]  = GetProcAddress(g_hWinSock32, "EnumProtocolsW");
        g_lpWinSock32Functions[9]  = GetProcAddress(g_hWinSock32, "GetAcceptExSockaddrs");
        g_lpWinSock32Functions[10] = GetProcAddress(g_hWinSock32, "GetAddressByNameA");
        g_lpWinSock32Functions[11] = GetProcAddress(g_hWinSock32, "GetAddressByNameW");
        g_lpWinSock32Functions[12] = GetProcAddress(g_hWinSock32, "gethostbyaddr");
        g_lpWinSock32Functions[13] = GetProcAddress(g_hWinSock32, "gethostbyname");
        g_lpWinSock32Functions[14] = GetProcAddress(g_hWinSock32, "gethostname");
        g_lpWinSock32Functions[15] = GetProcAddress(g_hWinSock32, "GetNameByTypeA");
        g_lpWinSock32Functions[16] = GetProcAddress(g_hWinSock32, "GetNameByTypeW");
        g_lpWinSock32Functions[17] = GetProcAddress(g_hWinSock32, "getnetbyname");
        g_lpWinSock32Functions[18] = GetProcAddress(g_hWinSock32, "getpeername");
        g_lpWinSock32Functions[19] = GetProcAddress(g_hWinSock32, "getprotobyname");
        g_lpWinSock32Functions[20] = GetProcAddress(g_hWinSock32, "getprotobynumber");
        g_lpWinSock32Functions[21] = GetProcAddress(g_hWinSock32, "getservbyname");
        g_lpWinSock32Functions[22] = GetProcAddress(g_hWinSock32, "getservbyport");
        g_lpWinSock32Functions[23] = GetProcAddress(g_hWinSock32, "GetServiceA");
        g_lpWinSock32Functions[24] = GetProcAddress(g_hWinSock32, "GetServiceW");
        g_lpWinSock32Functions[25] = GetProcAddress(g_hWinSock32, "getsockname");
        g_lpWinSock32Functions[26] = GetProcAddress(g_hWinSock32, "getsockopt");
        g_lpWinSock32Functions[27] = GetProcAddress(g_hWinSock32, "GetTypeByNameA");
        g_lpWinSock32Functions[28] = GetProcAddress(g_hWinSock32, "GetTypeByNameW");
        g_lpWinSock32Functions[29] = GetProcAddress(g_hWinSock32, "htonl");
        g_lpWinSock32Functions[30] = GetProcAddress(g_hWinSock32, "htons");
        g_lpWinSock32Functions[31] = GetProcAddress(g_hWinSock32, "inet_addr");
        g_lpWinSock32Functions[32] = GetProcAddress(g_hWinSock32, "inet_network");
        g_lpWinSock32Functions[33] = GetProcAddress(g_hWinSock32, "inet_ntoa");
        g_lpWinSock32Functions[34] = GetProcAddress(g_hWinSock32, "ioctlsocket");
        g_lpWinSock32Functions[35] = GetProcAddress(g_hWinSock32, "listen");
        g_lpWinSock32Functions[36] = GetProcAddress(g_hWinSock32, "MigrateWinsockConfiguration");
        g_lpWinSock32Functions[37] = GetProcAddress(g_hWinSock32, "NPLoadNameSpaces");
        g_lpWinSock32Functions[38] = GetProcAddress(g_hWinSock32, "ntohl");
        g_lpWinSock32Functions[39] = GetProcAddress(g_hWinSock32, "ntohs");
        g_lpWinSock32Functions[40] = GetProcAddress(g_hWinSock32, "rcmd");
        g_lpWinSock32Functions[41] = GetProcAddress(g_hWinSock32, "recv");
        g_lpWinSock32Functions[42] = GetProcAddress(g_hWinSock32, "recvfrom");
        g_lpWinSock32Functions[43] = GetProcAddress(g_hWinSock32, "rexec");
        g_lpWinSock32Functions[44] = GetProcAddress(g_hWinSock32, "rresvport");
        g_lpWinSock32Functions[45] = GetProcAddress(g_hWinSock32, "s_perror");
        g_lpWinSock32Functions[46] = GetProcAddress(g_hWinSock32, "select");
        g_lpWinSock32Functions[47] = GetProcAddress(g_hWinSock32, "send");
        g_lpWinSock32Functions[48] = GetProcAddress(g_hWinSock32, "sendto");
        g_lpWinSock32Functions[49] = GetProcAddress(g_hWinSock32, "sethostname");
        g_lpWinSock32Functions[50] = GetProcAddress(g_hWinSock32, "SetServiceA");
        g_lpWinSock32Functions[51] = GetProcAddress(g_hWinSock32, "SetServiceW");
        g_lpWinSock32Functions[52] = GetProcAddress(g_hWinSock32, "setsockopt");
        g_lpWinSock32Functions[53] = GetProcAddress(g_hWinSock32, "shutdown");
        g_lpWinSock32Functions[54] = GetProcAddress(g_hWinSock32, "socket");
        g_lpWinSock32Functions[55] = GetProcAddress(g_hWinSock32, "TransmitFile");
        g_lpWinSock32Functions[56] = GetProcAddress(g_hWinSock32, "WEP");
        g_lpWinSock32Functions[57] = GetProcAddress(g_hWinSock32, "WSAAsyncGetHostByAddr");
        g_lpWinSock32Functions[58] = GetProcAddress(g_hWinSock32, "WSAAsyncGetHostByName");
        g_lpWinSock32Functions[59] = GetProcAddress(g_hWinSock32, "WSAAsyncGetProtoByName");
        g_lpWinSock32Functions[60] = GetProcAddress(g_hWinSock32, "WSAAsyncGetProtoByNumber");
        g_lpWinSock32Functions[61] = GetProcAddress(g_hWinSock32, "WSAAsyncGetServByName");
        g_lpWinSock32Functions[62] = GetProcAddress(g_hWinSock32, "WSAAsyncGetServByPort");
        g_lpWinSock32Functions[63] = GetProcAddress(g_hWinSock32, "WSAAsyncSelect");
        g_lpWinSock32Functions[64] = GetProcAddress(g_hWinSock32, "WSACancelAsyncRequest");
        g_lpWinSock32Functions[65] = GetProcAddress(g_hWinSock32, "WSACancelBlockingCall");
        g_lpWinSock32Functions[66] = GetProcAddress(g_hWinSock32, "WSACleanup");
        g_lpWinSock32Functions[67] = GetProcAddress(g_hWinSock32, "WSAGetLastError");
        g_lpWinSock32Functions[68] = GetProcAddress(g_hWinSock32, "WSAIsBlocking");
        g_lpWinSock32Functions[69] = GetProcAddress(g_hWinSock32, "WSApSetPostRoutine");
        g_lpWinSock32Functions[70] = GetProcAddress(g_hWinSock32, "WSARecvEx");
        g_lpWinSock32Functions[71] = GetProcAddress(g_hWinSock32, "WSASetBlockingHook");
        g_lpWinSock32Functions[72] = GetProcAddress(g_hWinSock32, "WSASetLastError");
        g_lpWinSock32Functions[73] = GetProcAddress(g_hWinSock32, "WSAStartup");
        g_lpWinSock32Functions[74] = GetProcAddress(g_hWinSock32, "WSAUnhookBlockingHook");
    }

    if (fdwReason == DLL_PROCESS_DETACH)
    {
        if(g_hWinSock32 != NULL)
        {
            FreeLibrary(g_hWinSock32);
        }
    }

    return TRUE;
}

#define WINSOCK32_DEF_STUB(number, name) \
__declspec(naked) void WINAPI _WSOCK_EXPORT_ ## name() \
{ \
    __asm \
    { \
        jmp g_lpWinSock32Functions[number * 4] \
    } \
};\

WINSOCK32_DEF_STUB(0, __WSAFDIsSet);
WINSOCK32_DEF_STUB(1, accept);
WINSOCK32_DEF_STUB(2, AcceptEx);
WINSOCK32_DEF_STUB(3, bind);
WINSOCK32_DEF_STUB(4, closesocket);
WINSOCK32_DEF_STUB(5, connect);
WINSOCK32_DEF_STUB(6, dn_expand);
WINSOCK32_DEF_STUB(7, EnumProtocolsA);
WINSOCK32_DEF_STUB(8, EnumProtocolsW);
WINSOCK32_DEF_STUB(9, GetAcceptExSockaddrs);
WINSOCK32_DEF_STUB(10, GetAddressByNameA);
WINSOCK32_DEF_STUB(11, GetAddressByNameW);
WINSOCK32_DEF_STUB(12, gethostbyaddr);
WINSOCK32_DEF_STUB(13, gethostbyname);
WINSOCK32_DEF_STUB(14, gethostname);
WINSOCK32_DEF_STUB(15, GetNameByTypeA);
WINSOCK32_DEF_STUB(16, GetNameByTypeW);
WINSOCK32_DEF_STUB(17, getnetbyname);
WINSOCK32_DEF_STUB(18, getpeername);
WINSOCK32_DEF_STUB(19, getprotobyname);
WINSOCK32_DEF_STUB(20, getprotobynumber);
WINSOCK32_DEF_STUB(21, getservbyname);
WINSOCK32_DEF_STUB(22, getservbyport);
WINSOCK32_DEF_STUB(23, GetServiceA);
WINSOCK32_DEF_STUB(24, GetServiceW);
WINSOCK32_DEF_STUB(25, getsockname);
WINSOCK32_DEF_STUB(26, getsockopt);
WINSOCK32_DEF_STUB(27, GetTypeByNameA);
WINSOCK32_DEF_STUB(28, GetTypeByNameW);
WINSOCK32_DEF_STUB(29, htonl);
WINSOCK32_DEF_STUB(30, htons);
WINSOCK32_DEF_STUB(31, inet_addr);
WINSOCK32_DEF_STUB(32, inet_network);
WINSOCK32_DEF_STUB(33, inet_ntoa);
WINSOCK32_DEF_STUB(34, ioctlsocket);
WINSOCK32_DEF_STUB(35, listen);
WINSOCK32_DEF_STUB(36, MigrateWinsockConfiguration);
WINSOCK32_DEF_STUB(37, NPLoadNameSpaces);
WINSOCK32_DEF_STUB(38, ntohl);
WINSOCK32_DEF_STUB(39, ntohs);
WINSOCK32_DEF_STUB(40, rcmd);
WINSOCK32_DEF_STUB(41, recv);
WINSOCK32_DEF_STUB(42, recvfrom);
WINSOCK32_DEF_STUB(43, rexec);
WINSOCK32_DEF_STUB(44, rresvport);
WINSOCK32_DEF_STUB(45, s_perror);
WINSOCK32_DEF_STUB(46, select);
WINSOCK32_DEF_STUB(47, send);
WINSOCK32_DEF_STUB(48, sendto);
WINSOCK32_DEF_STUB(49, sethostname);
WINSOCK32_DEF_STUB(50, SetServiceA);
WINSOCK32_DEF_STUB(51, SetServiceW);
WINSOCK32_DEF_STUB(52, setsockopt);
WINSOCK32_DEF_STUB(53, shutdown);
WINSOCK32_DEF_STUB(54, socket);
WINSOCK32_DEF_STUB(55, TransmitFile);
WINSOCK32_DEF_STUB(56, WEP);
WINSOCK32_DEF_STUB(57, WSAAsyncGetHostByAddr);
WINSOCK32_DEF_STUB(58, WSAAsyncGetHostByName);
WINSOCK32_DEF_STUB(59, WSAAsyncGetProtoByName);
WINSOCK32_DEF_STUB(60, WSAAsyncGetProtoByNumber);
WINSOCK32_DEF_STUB(61, WSAAsyncGetServByName);
WINSOCK32_DEF_STUB(62, WSAAsyncGetServByPort);
WINSOCK32_DEF_STUB(63, WSAAsyncSelect);
WINSOCK32_DEF_STUB(64, WSACancelAsyncRequest);
WINSOCK32_DEF_STUB(65, WSACancelBlockingCall);
WINSOCK32_DEF_STUB(66, WSACleanup);
WINSOCK32_DEF_STUB(67, WSAGetLastError);
WINSOCK32_DEF_STUB(68, WSAIsBlocking);
WINSOCK32_DEF_STUB(69, WSApSetPostRoutine);
WINSOCK32_DEF_STUB(70, WSARecvEx);
WINSOCK32_DEF_STUB(71, WSASetBlockingHook);
WINSOCK32_DEF_STUB(72, WSASetLastError);
WINSOCK32_DEF_STUB(73, WSAStartup);
WINSOCK32_DEF_STUB(74, WSAUnhookBlockingHook);

#undef WINSOCK32_DEF_STUB