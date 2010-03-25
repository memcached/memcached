/* ntservice.c
 *
 *  Copyright (c) 2006 Germán Méndez Bravo (Kronuz) <kronuz@users.sf.net>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. All advertising materials mentioning features or use of this software
 *     must display the following acknowledgement:
 *        This product includes software developed by Kronuz.
 *  4. The name of the author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 *  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "config.h"
#include "ntservice.h"

#include <windows.h>
#include <stdio.h>

/* Extern callbacks to manage the server */
svcFunc runServer = NULL;
svcFunc pauseServer = NULL;
svcFunc continueServer = NULL;
svcFunc stopServer = NULL;

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;

void ServiceSetFunc(svcFunc runFunc, svcFunc pauseFunc, svcFunc continueFunc, svcFunc stopFunc)
{
    runServer = runFunc;
    pauseServer = pauseFunc;
    continueServer = continueFunc;
    stopServer = stopFunc;
}

static void WINAPI ServiceControlHandler(DWORD controlCode)
{
    switch(controlCode) {
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_STOP:
            /* set the service curent status */
            serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(serviceStatusHandle, &serviceStatus);

            if(stopServer) stopServer();
            return;

        case SERVICE_CONTROL_PAUSE:
            /* set the service curent status */
            serviceStatus.dwCurrentState = SERVICE_PAUSE_PENDING;
            SetServiceStatus(serviceStatusHandle, &serviceStatus);

            if(pauseServer) pauseServer();
            break;

        case SERVICE_CONTROL_CONTINUE:
            /* set the service curent status */
            serviceStatus.dwCurrentState = SERVICE_CONTINUE_PENDING;
            SetServiceStatus(serviceStatusHandle, &serviceStatus);

            if(continueServer) continueServer();
            break;

        case SERVICE_CONTROL_INTERROGATE:
            break;
    }

    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

static void WINAPI ServiceMain(DWORD dwNumServicesArgs, LPSTR *lpServiceArgVectors)
{
    /* initialise service status */
    serviceStatus.dwServiceType = SERVICE_WIN32;
    serviceStatus.dwCurrentState = SERVICE_STOPPED;
    serviceStatus.dwControlsAccepted = 0;
    serviceStatus.dwWin32ExitCode = NO_ERROR;
    serviceStatus.dwServiceSpecificExitCode = NO_ERROR;
    serviceStatus.dwCheckPoint = 0;
    serviceStatus.dwWaitHint = 0;

    serviceStatusHandle = RegisterServiceCtrlHandler(PACKAGE_NAME, ServiceControlHandler);

    if(serviceStatusHandle) {
        /* set the service curent status as starting */
        serviceStatus.dwCurrentState = SERVICE_START_PENDING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        /* set the service curent status as running and accepting shutdown */
        serviceStatus.dwControlsAccepted |= (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
        serviceStatus.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        /* execute the main code */
        if(runServer) runServer();

        /* set the service curent status as stopping */
        serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        /* set the service curent status as stopped and not accepting shutdown*/
        serviceStatus.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
    }
}

static int ServiceWait(SC_HANDLE service, DWORD pending, DWORD complete)
{
    SERVICE_STATUS serviceStatus;
    int counter = 0;
    do {
        Sleep(1000);
        if(counter++>10 || QueryServiceStatus(service, &serviceStatus)==0)
            return FALSE;
    } while(serviceStatus.dwCurrentState == pending);
    return (serviceStatus.dwCurrentState == complete);
}

int ServiceRun(void)
{
    SERVICE_TABLE_ENTRY serviceTable[] =
    {
        { PACKAGE_NAME, ServiceMain },
        { 0, 0 }
    };

    StartServiceCtrlDispatcher(serviceTable);
    return 0;
}

int ServiceInstall(void)
{
    int ok = 0;
    SC_HANDLE service;
    SERVICE_DESCRIPTION sdBuf;
    SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);

    if(serviceControlManager) {
        char exe_path[MAX_PATH + 1];
        if(GetModuleFileName(0, exe_path, sizeof(exe_path)) > 0) {
            char launch_cmd[MAX_PATH + 50];
            sprintf(launch_cmd, "\"%s\" -d runservice", exe_path);
            service = CreateService(serviceControlManager,
                            PACKAGE_NAME, PACKAGE_NAME,
                            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                            SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, launch_cmd,
                            0, 0, 0, 0, 0);
            if(service) {
                sdBuf.lpDescription = PACKAGE_DESCRIPTION;
                ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &sdBuf);
                CloseServiceHandle(service);
                ok = 1;
            }
        }
        CloseServiceHandle(serviceControlManager);
    }
    return ok;
}

int ServiceUninstall(void)
{
    int ok = 0;
    SC_HANDLE service;
    SERVICE_STATUS serviceStatus;
    SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

    if(serviceControlManager) {
        service = OpenService(serviceControlManager,
            PACKAGE_NAME, SERVICE_QUERY_STATUS | DELETE);
        if(service) {
            if(QueryServiceStatus(service, &serviceStatus)) {
                if(serviceStatus.dwCurrentState == SERVICE_STOPPED)
                    if(DeleteService(service))
                        ok = 1;
            }
            CloseServiceHandle(service);
        }
        CloseServiceHandle(serviceControlManager);
    }
    return ok;
}

int ServiceStart(void)
{
    int ok = 0;
    SC_HANDLE service;
    SERVICE_STATUS serviceStatus;
    SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

    if(serviceControlManager) {
        service = OpenService(serviceControlManager,
            PACKAGE_NAME, SERVICE_QUERY_STATUS | SERVICE_START);
        if(service) {
            if(QueryServiceStatus(service, &serviceStatus)) {
                if(serviceStatus.dwCurrentState == SERVICE_STOPPED) {
                    StartService(service, 0, NULL);
                    if(ServiceWait(service, SERVICE_START_PENDING, SERVICE_RUNNING))
                        ok = 1;
                } else if(serviceStatus.dwCurrentState == SERVICE_RUNNING) ok = 1;
            }
            CloseServiceHandle(service);
        }
        CloseServiceHandle(serviceControlManager);
    }
    return ok;
}

int ServiceStop(void)
{
    int ok = 0;
    SC_HANDLE service;
    SERVICE_STATUS serviceStatus;
    SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

    if(serviceControlManager) {
        service = OpenService(serviceControlManager,
            PACKAGE_NAME, SERVICE_QUERY_STATUS | SERVICE_STOP);
        if(service) {
            if(QueryServiceStatus(service, &serviceStatus)) {
                if(serviceStatus.dwCurrentState == SERVICE_RUNNING) {
                    ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus);
                    if(ServiceWait(service, SERVICE_STOP_PENDING, SERVICE_STOPPED))
                        ok = 1;
                    CloseServiceHandle(service);
                } else if(serviceStatus.dwCurrentState == SERVICE_STOPPED) ok = 1;
            }
        }
        CloseServiceHandle(serviceControlManager);
    }
    return ok;
}

int ServiceRestart(void)
{
    int ok = 0;
    SC_HANDLE service;
    SERVICE_STATUS serviceStatus;
    SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

    if(serviceControlManager) {
        service = OpenService(serviceControlManager,
            PACKAGE_NAME, SERVICE_QUERY_STATUS | SERVICE_STOP);
        if(service) {
            ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus);
            if(ServiceWait(service, SERVICE_STOP_PENDING, SERVICE_STOPPED)) {
                StartService(service, 0, NULL);
                if(ServiceWait(service, SERVICE_START_PENDING, SERVICE_RUNNING))
                    ok = 1;
            }
            CloseServiceHandle(service);
        }
        CloseServiceHandle(serviceControlManager);
    }
    return ok;
}
