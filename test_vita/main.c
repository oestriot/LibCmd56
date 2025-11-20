#include <stdio.h>
#include <stdarg.h>
#include <vitasdkkern.h>
#include <taihen.h>

#include "sha256.h"
#include "../cmd56/gc.h"
#include "../cmd56/vita.h"
#include "../cmd56/log.h"


//#define VERIFY_GC_C 1 // hardware validation of gc part of algorithm
#define VERIFY_VITA_C 1 // hardware validation of vita part of the algorithm 


#ifdef VERIFY_GC_C

// smart as ...
static cmd56_keys keys = { { 0x12, 0x53, 0x56, 0x29, 0x00, 0x31, 0x00, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x42, 0x21, 0x00, 0x00, 0x00, 0x42, 0x02, 0x00, 0x56, 0x29, 0x05, 0x03, 0x31, 0x3D, 0x20, 0x11, 0x00, 0x00, 0x00, 0x00 },
						   { 0x7B, 0x2B, 0xA1, 0xF1, 0xB7, 0x57, 0xF0, 0x35, 0xFA, 0x93, 0x94, 0x0D, 0x1A, 0xB4, 0xD9, 0x1A, 0x18, 0x54, 0xD6, 0xC3, 0xCD, 0xCD, 0x5B, 0x67, 0xE1, 0x07, 0x70, 0xA4, 0x2B, 0x4F, 0xA9, 0x0A } };

static gc_cmd56_state gc_state;

static uint8_t VITA_PACKET[0x200];
static uint8_t GC_PACKET[0x200];

static int sendHook = -1;
static tai_hook_ref_t sendHookRef;

static int recvHook = -1;
static tai_hook_ref_t recvHookRef;

static int kernelGetSysTime = -1;
static tai_hook_ref_t kernelGetSysTimeRef;

uint64_t sceKernelGetSystemTimeWide_Patched() {
  return 0;
}

int ksceSdifWriteCmd56_Patched(void* instance, char* buffer, int bufferSz) {
	memcpy(VITA_PACKET, buffer, bufferSz);
	gc_cmd56_run(&gc_state, VITA_PACKET, GC_PACKET);
	LOG("VITA: ");
	LOG_BUFFER(VITA_PACKET, sizeof(VITA_PACKET));
	return 0;
}	

int ksceSdifReadCmd56_Patched(void* instance, char* buffer, int bufferSz) {
	memcpy(buffer, GC_PACKET, bufferSz);	
	LOG("GC: ");
	LOG_BUFFER(GC_PACKET, sizeof(GC_PACKET));
	return 0;
}
#endif

#ifdef VERIFY_VITA_C
static vita_cmd56_state vita_state;
static SceSdifDeviceContext* ctx;

static int authHook = -1;
static tai_hook_ref_t authHookRef;

static int getCartSecretHook = -1;
static tai_hook_ref_t getCartSecretHookRef;

static int clearCartSecretHook = -1;
static tai_hook_ref_t clearCartSecretHookRef;

int ksceSblGcAuthMgrDrmBBGetCartSecret_Patched(uint8_t* secret) {
	LOG("ksceSblGcAuthMgrDrmBBGetCartSecret\n");
	
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (uint8_t*)&vita_state.per_cart_keys, sizeof(cmd56_keys));
	sha256_final(&ctx, secret);
	
	LOG("cart_secret: ");
	LOG_BUFFER(secret, 0x20);
	
	return 0;
}

int ksceSblGcAuthMgrDrmBBClearCartSecret_Patched() {
	LOG("ksceSblGcAuthMgrDrmBBClearCartSecret\n");
	memset(&vita_state, 0x00, sizeof(vita_state));
	return 0;
}


void gc_send(const uint8_t* buf, uint32_t size) {
	LOG("gc_send: ");
	LOG_BUFFER(buf, size);
	
	ksceSdifWriteCmd56(ctx, buf, size);
}

void gc_recv(uint8_t* buf, uint32_t size) {
	LOG("gc_recv: ");
	LOG_BUFFER(buf, size);
	
	ksceSdifReadCmd56(ctx, buf, size);
}

int ksceSblGcAuthMgrGcAuthCartAuthentication_Patched(uint16_t key_id) {
	ksceSblGcAuthMgrDrmBBClearCartSecret_Patched();
	ctx = ksceSdifGetSdContextPartValidateMmc(1);
	LOG("key_id: %x\n", key_id);
	if(ctx != NULL) {
		vita_cmd56_init(&vita_state, gc_send, gc_recv); // initalize VITA emu 
		int ret = vita_cmd56_run(&vita_state);
		
		if(ret == GC_AUTH_OK) {
			LOG("vita_state.per_cart_keys.packet18_key\n");
			LOG_BUFFER(vita_state.per_cart_keys.packet18_key, sizeof(vita_state.per_cart_keys.packet18_key));

			LOG("vita_state.per_cart_keys.packet20_key\n");
			LOG_BUFFER(vita_state.per_cart_keys.packet20_key, sizeof(vita_state.per_cart_keys.packet20_key));		
			return ret;
		}
		else{
			LOG("ret = 0x%x\n", ret);
			ksceSblGcAuthMgrDrmBBClearCartSecret_Patched();
		}
	}
	return -1;
}

#endif

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{
#ifdef VERIFY_GC_C	
	LOG("[started] GcAuthMgrEmu -- GC mode\n");

	gc_cmd56_init(&gc_state, &keys); // initalize fake GC

	sendHook = taiHookFunctionImportForKernel(KERNEL_PID,
		&sendHookRef, 
		"SceSblGcAuthMgr",
		0x96D306FA, // SceSdifForDriver
		0xB0996641, // ksceSdifWriteCmd56
		ksceSdifWriteCmd56_Patched);
	LOG("[started] %x %x\n", sendHook, sendHookRef);
		
	recvHook = taiHookFunctionImportForKernel(KERNEL_PID,
		&recvHookRef, 
		"SceSblGcAuthMgr",
		0x96D306FA, // SceSdifForDriver
		0x134E06C4, // ksceSdifReadCmd56
		ksceSdifReadCmd56_Patched);
	LOG("[started] %x %x\n", recvHook, recvHookRef);

	// undo cobra blackfin patch
	kernelGetSysTime = taiHookFunctionImportForKernel(KERNEL_PID,
		&kernelGetSysTimeRef, 
		"SceSblGcAuthMgr",
		0xE2C40624, // SceThreadmgrForDriver
		0xF4EE4FA9, // sceKernelGetSystemTimeWide
		sceKernelGetSystemTimeWide_Patched);
	LOG("[started] %x %x\n", kernelGetSysTime, kernelGetSysTimeRef);
#endif

#ifdef VERIFY_VITA_C
	LOG("[started] GcAuthMgrEmu -- VITA mode\n");
	
	authHook = taiHookFunctionExportForKernel(KERNEL_PID,
		&authHookRef, 
		"SceSblGcAuthMgr",
		0xC6627F5E, // SceSblGcAuthMgrGcAuthForDriver
		0x68781760, // ksceSblGcAuthMgrGcAuthCartAuthentication	
		ksceSblGcAuthMgrGcAuthCartAuthentication_Patched);
	LOG("[started] %x %x\n", authHook, authHookRef);

	getCartSecretHook = taiHookFunctionExportForKernel(KERNEL_PID,
		&getCartSecretHookRef, 
		"SceSblGcAuthMgr",
		0x1926B182, // SceSblGcAuthMgrDrmBBForDriver
		0xBB70DDC0, // ksceSblGcAuthMgrDrmBBGetCartSecret	
		ksceSblGcAuthMgrDrmBBGetCartSecret_Patched);
	LOG("[started] %x %x\n", getCartSecretHook, getCartSecretHookRef);

	clearCartSecretHook = taiHookFunctionExportForKernel(KERNEL_PID,
		&clearCartSecretHookRef, 
		"SceSblGcAuthMgr",
		0x1926B182, // SceSblGcAuthMgrDrmBBForDriver
		0xBB451E83, // ksceSblGcAuthMgrDrmBBClearCartSecret	
		ksceSblGcAuthMgrDrmBBClearCartSecret_Patched);
	LOG("[started] %x %x\n", clearCartSecretHook, clearCartSecretHookRef);

#endif

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	
#ifdef VERIFY_GC_C	
	if (recvHook >= 0)			taiHookReleaseForKernel(recvHook, recvHookRef);
	if (sendHook >= 0)			taiHookReleaseForKernel(sendHook, sendHookRef);
	if (kernelGetSysTime >= 0)  taiHookReleaseForKernel(kernelGetSysTime, kernelGetSysTimeRef);
#endif 
#ifdef VERIFY_GC_C
	if (authHook >= 0)			taiHookReleaseForKernel(authHook, authHookRef);
#endif
		
	return SCE_KERNEL_STOP_SUCCESS;
}
