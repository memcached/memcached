/* ntservice.h
 *
 *  Copyright (c) 2006 Germán Méndez Bravo (Kronuz) <kronuz@users.sf.net>
 *  All rights reserved.
 *
 */

#ifndef SERVICE_H
#define SERVICE_H

typedef void (*svcFunc) (void);

int ServiceStart(void);
int ServiceStop(void);
int ServiceRestart(void);
int ServiceUninstall(void);
int ServiceInstall(void);
int ServiceRun(void);

void ServiceSetFunc(svcFunc runFunc, svcFunc pauseFunc, svcFunc continueFunc, svcFunc stopFunc);

#endif
