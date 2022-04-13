// RestartApp.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <functional>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

// размер буфера
#define MAX_WINDOW_TITLE_LEN 1024
#define RTN_OK 0
#define RTN_USAGE 1
#define RTN_ERROR 13

#define MDEBUG_MODE 0

#pragma warning( disable : 4127 )

using namespace std;

typedef struct _FINDWINDOWHANDLESTRUCT
{
    HANDLE hProcess;
    HWND hWndFound;
}FINDWINDOWHANDLESTRUCT;

const string WHITESPACE = " \"\n\r\t\f\v\\";

// token handle
// Privilege to enable/disable
// TRUE to enable.  FALSE to disable
BOOL SetPrivilege( HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege );

static void out_help_short_string()
{
	setlocale(LC_ALL, "Russian");
	cout << "RestartApp.exe -n <EXE file name> -m <Windows message> -p <Path EXE file> -r<restart> -a <parameters>" << endl;
}

static void out_help_string()
{
    setlocale(LC_ALL, "Russian");
    cout << "Программа для выгрузки/перезапуска исполняемого модуля(программы), необходимы права администратора." << endl;
    cout << "RestartApp.exe -n <программа> -m <сообщение Windows> -p <путь> -r<если перезапуск> -a <параметры>" << endl << endl;
    cout << "Пример запуска:" << endl;
    cout << "перезапуск приложения myApp.exe из папки C:\\MyFolder с параметрами командной строки myAppParams." << endl;
    cout << "RestartApp.exe -n myApp.exe -m 16 -l C:\\MyFolder -r -a myAppParams" << endl;
    cout << " -n : имя исполняемой программы для выгрузки/перезапуска, необходимый параметр." << endl;
    cout << " -m : сообщение посылаемое окну программы myApp.exe, если оно есть, например 16 для WM_CLOSE." << endl;
    cout << " -p : путь исполняемой программы myApp.exe, если путь не совпадает с указанным" << endl;
    cout << "      после параметра -l программа не закрывается и не перезапускается." << endl;
    cout << "      Если параметр не задан, проверка пути не производится выгружается/перезапускается" << endl;
    cout << "      первое найденное в списке приложение." << endl;
    cout << " -r : ключ указывает на необходимость перезапустить программу, после выгрузки." << endl;
    cout << " -a : параметры с которыми производится перезапуск программы myApp.exe." << endl;
    cout << " -s : не выводить на консоль сообщения программы." << endl;
    cout << " -f : вывод списка процессов, остальные параметры игнорируются." << endl << endl;
    cout << "Пример запуска:" << endl;
    cout << "выгрузка службы ss_conn_service.exe, для служб некорректно, правильно использовать команду:" << endl;
    cout << "net stop <имя службы>" << endl;
    cout << "в данном случае:" << endl;
    cout << "net stop \"SAMSUNG Mobile Connectivity Service\"" << endl;
    cout << "RestartApp.exe -p ss_conn_service.exe" << endl << endl;
    cout << "Пример запуска:" << endl;
    cout << "вывод списка процессов в системе" << endl;
    cout << "RestartApp.exe -l" << endl;
    cout << "RestartApp.exe --list" << endl;
}

HMODULE GetRemoteModuleHandle(DWORD lpProcessId, LPCSTR lpModule)
{
    HMODULE hResult = NULL;
    HANDLE hSnapshot;
    MODULEENTRY32 me32;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, lpProcessId);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        me32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &me32))
        {
            do
            {
                if (!_stricmp(me32.szModule, lpModule))
                {
                    hResult = me32.hModule;
                    break;
                }
            }
            while (Module32Next(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);
    }
    return hResult;
}

bool TerminateProccessByModuleName(string pName, string location)
{
    unsigned long dwExitCode = 0;
    unsigned long aProcesses[MAX_WINDOW_TITLE_LEN], cbNeeded, cProcesses;
    wchar_t wbuffer[MAX_WINDOW_TITLE_LEN];
    char buffer[MAX_WINDOW_TITLE_LEN];
    string mstr;
    size_t ic = 0;

    // получаем идентификаторы всех процессов в системе в массив aProcesses
    if(!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return false;

    cProcesses = cbNeeded / sizeof(unsigned long);
    for(unsigned int i = 0; i < cProcesses; i++)
    {
        if(aProcesses[i] == 0)
            continue;

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ, 0, aProcesses[i]);

        memset(buffer, 0, MAX_WINDOW_TITLE_LEN);

        // берем имя файла модуля процесса
        GetModuleBaseNameW(hProcess, 0, wbuffer, MAX_WINDOW_TITLE_LEN);
        wcstombs_s( &ic, buffer, (size_t)MAX_WINDOW_TITLE_LEN, wbuffer, (size_t)MAX_WINDOW_TITLE_LEN );
        mstr = buffer;

        std::transform(pName.begin(), pName.end(), pName.begin(), toupper);
        std::transform(mstr.begin(), mstr.end(), mstr.begin(), toupper);

        if( mstr == pName )
        {
            size_t pos;
            string module_fullpath;
            string module_location;

            // берем полуный путь модуля
            GetModuleFileNameEx(hProcess, 0, buffer, MAX_WINDOW_TITLE_LEN);
            module_fullpath = buffer;
            // находим первый прямой слеш
            pos = module_fullpath.find_last_of('\\');
            // получаем путь к модулю
            module_location = module_fullpath.substr(0, pos);

            std::transform(module_location.begin(), module_location.end(), module_location.begin(), toupper);
            std::transform(location.begin(), location.end(), location.begin(), toupper);

            if(module_location == location)
            {
                GetExitCodeProcess(hProcess, &dwExitCode);

                TerminateProcess(hProcess, dwExitCode);

                CloseHandle(hProcess);
            }
            return true;
        }

        CloseHandle(hProcess);
    }
    return false;
}

void listProcessToConsole()
{
    unsigned long aProcesses[MAX_WINDOW_TITLE_LEN], cbNeeded, cProcesses;
    wchar_t wbuffer[MAX_WINDOW_TITLE_LEN];
    char buffer[MAX_WINDOW_TITLE_LEN];
    string mstr;
    stringstream ss;
    DWORD dw_access_mode;
    size_t ic = 0;
    size_t max_len = 0;

    // получаем идентификаторы всех процессов в системе в массив aProcesses
    if(!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return;

    // вычисляем количество процессов в системе
    cProcesses = cbNeeded / sizeof(unsigned long);

    if(MDEBUG_MODE) cout << "num process :" << cProcesses << endl;

    // цикл по всем процессам в системе
    for(unsigned int i = 0; i < cProcesses; i++)
    {
        if(aProcesses[i] == 0) continue;

        dw_access_mode = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

        HANDLE hProcess = OpenProcess(dw_access_mode, 0, aProcesses[i]);

        if (hProcess != NULL )
        {
            HMODULE hMod;
            DWORD cbNeeded;
            if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeeded) )
            {
                // берем полуный путь модуля
                GetModuleBaseNameW(hProcess, 0, wbuffer, MAX_WINDOW_TITLE_LEN);
                wcstombs_s( &ic, buffer, (size_t)MAX_WINDOW_TITLE_LEN, wbuffer, (size_t)MAX_WINDOW_TITLE_LEN );
                mstr = buffer;
                std::transform(mstr.begin(), mstr.end(), mstr.begin(), toupper);

                if(mstr.length() > max_len)
                    max_len = mstr.length();
            }
        }
        CloseHandle(hProcess);
    }

    for(unsigned int i = 0; i < cProcesses; i++)
    {
        if(aProcesses[i] == 0)
            continue;

        dw_access_mode = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        HANDLE hProcess = OpenProcess(dw_access_mode, 0, aProcesses[i]);
        if (hProcess != NULL )
        {
            HMODULE hMod;
            DWORD cbNeeded;
            if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeeded) )
            {
                string module_name;
                // берем полуный путь модуля
                GetModuleBaseNameW(hProcess, 0, wbuffer, MAX_WINDOW_TITLE_LEN);
                wcstombs_s( &ic, buffer, (size_t)MAX_WINDOW_TITLE_LEN, wbuffer, (size_t)MAX_WINDOW_TITLE_LEN );
                module_name = mstr = buffer;
                std::transform(mstr.begin(), mstr.end(), mstr.begin(), toupper);
                
                size_t len_mstr = mstr.length();

                for(size_t j = 0; j < max_len - len_mstr + 3; j++)
                    mstr += ' ';

                cout << mstr << "  " << setw(5) << aProcesses[i] << "  ";

                GetModuleFileNameExW(hProcess, 0, wbuffer, MAX_WINDOW_TITLE_LEN);
                wcstombs_s( &ic, buffer, (size_t)MAX_WINDOW_TITLE_LEN, wbuffer, (size_t)MAX_WINDOW_TITLE_LEN );
                mstr = buffer;
                std::transform(mstr.begin(), mstr.end(), mstr.begin(), toupper);
    
                HMODULE hModule = GetRemoteModuleHandle(aProcesses[i], module_name.c_str());
                MODULEINFO mi;

                memset(&mi, 0, sizeof(MODULEINFO));

                GetModuleInformation(hProcess, hModule, &mi, sizeof(mi));

                cout << "  " << setw(6) << mi.SizeOfImage / 1000 << " ";

                size_t pos;
                // находим первый прямой слеш
                pos = mstr.find_last_of('\\');
                // получаем путь к модулю
                string location = mstr.substr(0, pos);

                cout << location << endl;
            }
        }
    }
}

bool isRunningModuleRun(string pName, string& location)
{
    unsigned long aProcesses[MAX_WINDOW_TITLE_LEN], cbNeeded, cProcesses;
    wchar_t wbuffer[MAX_WINDOW_TITLE_LEN];
    char buffer[MAX_WINDOW_TITLE_LEN];
    string mstr;
    stringstream ss;
    DWORD dw_access_mode;
    size_t ic = 0;

    if(!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return false;

    cProcesses = cbNeeded / sizeof(unsigned long);

    if(MDEBUG_MODE) cout << "num process :" << cProcesses << endl;

    for(unsigned int i = 0; i < cProcesses; i++)
    {
        if(aProcesses[i] == 0)
            continue;

        dw_access_mode = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        HANDLE hProcess = OpenProcess(dw_access_mode, 0, aProcesses[i]);

        if (hProcess != NULL )
        {
            HMODULE hMod;
            DWORD cbNeeded;

            if(MDEBUG_MODE) cout << "debug:p:0:1" << endl;

            if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeeded) )
            {
                memset(wbuffer, 0, 2*MAX_WINDOW_TITLE_LEN);
                // берем имя файла модуля процесса
                ic = GetModuleBaseNameW(hProcess, 0, wbuffer, MAX_WINDOW_TITLE_LEN);
            }
        }
        else
            if(MDEBUG_MODE) cout << "debug:p:0:0" << endl;

        if(MDEBUG_MODE)
        {
            for( unsigned long i = 0; i < ic && i < MAX_WINDOW_TITLE_LEN; i++ )
                ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (unsigned short)(wbuffer[i]);
            cout << ss.str().c_str() << endl;
            ss.str("");
        }

        wcstombs_s( &ic, buffer, (size_t)MAX_WINDOW_TITLE_LEN, wbuffer, (size_t)MAX_WINDOW_TITLE_LEN );
        mstr = buffer;

        std::transform(pName.begin(), pName.end(), pName.begin(), toupper);
        std::transform(mstr.begin(), mstr.end(), mstr.begin(), toupper);

        if( pName == mstr )
        {
            size_t pos;
            string module_fullpath;
            // берем полуный путь модуля
            GetModuleFileNameEx(hProcess, 0, buffer, MAX_WINDOW_TITLE_LEN);
            module_fullpath = buffer;
            // находим первый прямой слеш
            pos = module_fullpath.find_last_of('\\');
            // получаем путь к модулю
            location = module_fullpath.substr(0, pos);

            CloseHandle(hProcess);
            if(MDEBUG_MODE) cout << mstr << endl;
            if(MDEBUG_MODE) cout << "debug:p:1" << endl;
            return true;
        }
        CloseHandle(hProcess);
        if(MDEBUG_MODE) cout << mstr << endl;
    }

    if(MDEBUG_MODE) cout << mstr << endl;

    if(MDEBUG_MODE) cout << "debug:p:2" << endl;
    
    return false;
}

BOOL CALLBACK EnumWindowsProc( HWND hwnd, LPARAM lParam )
{
    DWORD ProcessId;
    HANDLE hHandle;
    string module_name1;
    string module_name2;

    char mbuf_process_name[MAX_WINDOW_TITLE_LEN];

    GetWindowThreadProcessId ( hwnd, &ProcessId );

    hHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId);

    // имя исполняемого файла и полный путь к нему
    GetModuleFileNameEx(hHandle, 0, mbuf_process_name, MAX_WINDOW_TITLE_LEN);
    module_name1 = mbuf_process_name;

    CloseHandle(hHandle);

    // имя исполняемого файла и полный путь к нему
    GetModuleFileNameEx(((FINDWINDOWHANDLESTRUCT*)lParam)->hProcess, 0, mbuf_process_name, MAX_WINDOW_TITLE_LEN);
    module_name2 = mbuf_process_name;

    std::transform(module_name1.begin(), module_name1.end(), module_name1.begin(), toupper);
    std::transform(module_name2.begin(), module_name2.end(), module_name2.begin(), toupper);

    if(module_name1 == module_name2)
    {
        ((FINDWINDOWHANDLESTRUCT*)lParam)->hWndFound = hwnd;
        // а вот по этому функция EnumWindows перестает перебирать окна
        // и заканчивает вызывать EnumWindowsProc
        return false;
    }

    return true;
}

bool isWindow(string pName, HWND& hwnd)
{
    unsigned long aProcesses[MAX_WINDOW_TITLE_LEN], cbNeeded, cProcesses;
    char buffer[MAX_WINDOW_TITLE_LEN];
    FINDWINDOWHANDLESTRUCT fwhs;
    HANDLE hProcess;
    bool isfound;
    string mstr;

    memset(&fwhs, 0, sizeof(FINDWINDOWHANDLESTRUCT));

    // перечисляем все процессы в системе
    if(!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return false;

    isfound = false;

    cProcesses = cbNeeded / sizeof(unsigned long);
    for(unsigned int i = 0; i < cProcesses; i++)
    {
        if(aProcesses[i] == 0)
            continue;

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, aProcesses[i]);

        memset(buffer, 0, MAX_WINDOW_TITLE_LEN);

        GetModuleBaseName(hProcess, 0, buffer, MAX_WINDOW_TITLE_LEN);

        mstr = buffer;

        std::transform(pName.begin(), pName.end(), pName.begin(), toupper);
        std::transform(mstr.begin(), mstr.end(), mstr.begin(), toupper);

        if( pName == mstr )
        {
            fwhs.hProcess = hProcess;

            isfound = true;

            break;
        }

        CloseHandle(hProcess);
    }
    // если не нашли выходим
    if(!isfound) return false;

    // запускаем функцию перечисления всех окон в системе
    EnumWindows(EnumWindowsProc, (LPARAM)&fwhs);

    CloseHandle(hProcess);

    if(fwhs.hWndFound != NULL)
    {
        hwnd = fwhs.hWndFound;
        return true;
    }

    return false;
}

// 
int main(int argc, char* argv[])
{
    int r_arg = 0;
    bool restart_program;
    bool silence_console;
    bool list_process;
    string module_name = "";
    string window_message = "";
    string module_location = "";
    string location = "";
    string module_arg = "";
    DWORD msg;
    HWND hwnd;

    restart_program = false;
    silence_console = false;
    list_process    = false;

    static int verbose_flag;

    static struct option long_options[] =
    {
        /* These options set a flag. */
        {"verbose", no_argument,       &verbose_flag, 1},
        {"brief",   no_argument,       &verbose_flag, 0},
        /* These options don’t set a flag.
         We distinguish them by their indices. */
        {"list",     no_argument,       0, 'l'},
        {"restart",  no_argument,       0, 'r'},
        {"help",     no_argument,       0, 'h'},
        {"h",        no_argument,       0, 'h'},
        {"?",        no_argument,       0, '?'},
        {"silence",  no_argument,       0, 's'},
        {"name",     required_argument, 0, 'n'},
        {"message",  required_argument, 0, 'm'},
        {"path",     required_argument, 0, 'p'},
        {"arg",      required_argument, 0, 'a'},
        {0,                          0, 0,  0 }
    };

	if(argc == 1)
	{
		out_help_short_string();
		return 0;
	}

    /* getopt_long stores the option index here. */
    int option_index = 0;

    while((r_arg = getopt_long (argc, argv, "lrhsn:m:p:a:", long_options, &option_index)) != -1)
    {
        switch(r_arg)
        {
            case 'l':
                list_process = true;
                break;
            case 'n':
                module_name = optarg;
                break;
            case 'm':
                window_message = optarg;
                break;
            case 'p':
				size_t end_c;
				module_location = optarg;
				// trim WHITESPACE symbols
				end_c = module_location.find_last_not_of(WHITESPACE);
				module_location = (end_c == string::npos) ? "" : module_location.substr(0, end_c + 1);
                break;
            case 's':
                silence_console = true;
                break;
            case 'r':
                restart_program = true;
                break;
            case 'a':
                module_arg = optarg;
                break;
            case 'h':
                out_help_string();
                return 0;
            case '?':
                out_help_string();
                return 0;
            default:
                return 1;
        }
    }

    if(!silence_console)
    {
        if(!module_name.empty())     cout << "module : "         << module_name     << endl;
        if(!window_message.empty())  cout << "window message : " << window_message  << endl;
        if(!module_location.empty()) cout << "location : "       << module_location << endl;
        if(!module_arg.empty())      cout << "program params : " << module_arg      << endl;
    }

    HANDLE hToken;

    if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
    {
        if (GetLastError() == ERROR_NO_TOKEN)
        {
            if (!ImpersonateSelf(SecurityImpersonation))
                return RTN_ERROR;

            if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
            {
                cout << "OpenThreadToken" << endl;
                return RTN_ERROR;
            }
        }
        else
            return RTN_ERROR;
    }

    // enable SeDebugPrivilege
    if(!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
    {
        cout << "error: SetPrivilege" << endl;
        CloseHandle(hToken); // close token handle
        return RTN_ERROR; // indicate failure
    }

    if(list_process)
    {
        listProcessToConsole();
        return 0;
    }

    // проверяем запущен ли модуль, и берем его путь
    if(isRunningModuleRun(module_name, location))
    {
        if(!silence_console) cout << argv[2] << " was found." << endl;

        // если установлен параметр "путь к модулю", проверяем
        // совпадает ли запущенный модуль с тем который мы собираемся
        // перезапустить/остановить
        if(!module_location.empty())
        {
            std::transform(location.begin(), location.end(), location.begin(), toupper);
            std::transform(module_location.begin(), module_location.end(), module_location.begin(), toupper);

            // если не совпадает возвращаем ошибку
            if(location != module_location)
                return RTN_ERROR;
        }

        hwnd = NULL;
        // проверяем есть ли у процесса окно
        if(isWindow(module_name, hwnd))
        {
            if(!silence_console) cout << argv[2] << " has window." << endl;
            if(!window_message.empty())
            {
                msg = atoi(window_message.c_str());

                SendMessage(hwnd, msg, 0, 0);

                if( isRunningModuleRun(module_name, location) )
                    TerminateProccessByModuleName(module_name, location);
            }
            else
            {
                TerminateProccessByModuleName(module_name, location);
            }
        }
        else
        {
            TerminateProccessByModuleName(module_name, location);
        }
    }
    else
    {
        if(!silence_console) cout << argv[2] << " was't found." << endl;
    }

    STARTUPINFO cif;
    ZeroMemory(&cif,sizeof(STARTUPINFO));
    PROCESS_INFORMATION pi;
    BOOL IsRun = FALSE;

    if(restart_program)
    {
        Sleep(10);

        if(!module_location.empty())
        {
            module_name = module_location + "\\" + module_name + " " + module_arg;
            location = module_location;
        }
        else
        {
            module_name = location + "\\" + module_name + " " + module_arg;
        }

        IsRun = CreateProcess( NULL,
                               (LPSTR)(module_name.c_str()),
                               NULL,
                               NULL,
                               FALSE,
                               NULL,
                               NULL,
                               location.c_str(),
                               &cif,
                               &pi);
    }

	return RTN_OK;
}

// token handle
// Privilege to enable/disable
// TRUE to enable.  FALSE to disable
BOOL SetPrivilege( HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege )
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious=sizeof(TOKEN_PRIVILEGES);

    if(!LookupPrivilegeValue( NULL, Privilege, &luid )) return FALSE;

    // first pass.  get current privilege setting
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = 0;

    AdjustTokenPrivileges( hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious );

    if (GetLastError() != ERROR_SUCCESS) return FALSE;

    // second pass.  set privilege based on previous setting
    tpPrevious.PrivilegeCount       = 1;
    tpPrevious.Privileges[0].Luid   = luid;

    if(bEnablePrivilege) {
        tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    }
    else {
        tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
            tpPrevious.Privileges[0].Attributes);
    }

    AdjustTokenPrivileges( hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL );

    if (GetLastError() != ERROR_SUCCESS) return FALSE;

    return TRUE;
}
