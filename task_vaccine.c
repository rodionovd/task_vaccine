// task_vaccine.c
// Copyright (c) 2014 Dmitry Rodionov
// https://github.com/rodionovd/task_vaccine
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

#include <dlfcn.h>
#include <syslog.h>
#include <assert.h>
#include <sys/sysctl.h>
#include <mach/mach_vm.h>

#include "task_vaccine.h"
#include "submodules/liblorgnette/lorgnette.h"

#define kVaccineRemoteStackSize (50*1024)
#define kVaccineJumpToDlopenReturnValue (0xabad1dea)
#define kVaccineFinishReturnValue       (0xdead1dea)

#define VaccineReturnNegativeTwoOnError(func) \
	do { \
		if (err != KERN_SUCCESS) { \
			syslog(LOG_NOTICE, "[%d] "#func"() failed: %d (%s)\n", __LINE__-3, \
			        err, mach_error_string(err)); \
			return (-2); \
		} \
	} while (0)

// From xnu-2782.1.97/bsd/uxkern/ux_exception.c
typedef struct {
    mach_msg_header_t Head;
    /* start of the kernel processed data */
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    /* end of the kernel processed data */
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    mach_exception_data_t code;
    /* some times RCV_TO_LARGE probs */
    char pad[512];
} exc_msg_t;

/**
 *
 */
static
thread_state_flavor_t task_thread_flavor(task_t target)
{
	assert(target);

	pid_t pid;
	int err = pid_for_task(target, &pid);
	if (err != KERN_SUCCESS) return (-1);

	int mib[4] = {
        CTL_KERN, KERN_PROC, KERN_PROC_PID, pid
    };
    struct kinfo_proc info;
    size_t size = sizeof(info);

    err = sysctl(mib, 4, &info, &size, NULL, 0);
    if (err != KERN_SUCCESS) {
    	return (-1);
    }

    if (info.kp_proc.p_flag & P_LP64) {
    	return x86_THREAD_STATE64;
    } else {
    	return x86_THREAD_STATE32;
    }
}

/**
 *
 */
static
thread_act_t vaccine_thread32(task_t target, mach_vm_address_t stack,
                                   mach_vm_address_t dlopen_arg)
{
	assert(target), assert(stack), assert(dlopen_arg);

	stack += kVaccineRemoteStackSize/2;
	// Allocate some place for a dummy pthread struct
	mach_vm_address_t dummy = 0;
	int err = mach_vm_allocate(target, &dummy, sizeof(struct _opaque_pthread_t),
	                           VM_FLAGS_ANYWHERE);
	VaccineReturnNegativeTwoOnError(mach_vm_allocate);
	// Place a fake return address and this dummy struct into the stack
	uint32_t local_stack[] = {
		 kVaccineJumpToDlopenReturnValue, (uint32_t)dummy
	};
	size_t local_stack_size = sizeof(local_stack);
	err = mach_vm_write(target, stack,
	                    (vm_offset_t)local_stack, local_stack_size);
	VaccineReturnNegativeTwoOnError(mach_vm_write);
	// Initialize an i386 thread state
	x86_thread_state32_t state;
	memset(&state, 0, sizeof(state));
	// We can only create a raw Mach thread inside a target task. But many
	// functions (such as dlopen()) rely on pthread stuff (locks, etc), so we
	// have to initialize a pthread first and only then execute dlopen() for
	// loading the payload.

	// As for OS X 10.9/10.10 there're two system libraries containing
	// _pthread_set_self symbol:
	// (1) libsystem_kernel.dylib and (2) libsystem_pthread.dylib.
	// In the former one is a no-op function (not exported actually) while the
	// latter holds the real (exported) symbol.
	// Since liblorgnette doesn't care about symbols publicity we have to
	// explicitly specify the source image for a symbol here. Otherwise it can
	// return an address of the no-op variant.
	uint32_t entrypoint = lorgnette_lookup_image(target, "_pthread_set_self",
	                                             "libsystem_pthread.dylib");
	if (entrypoint == 0) err = KERN_FAILURE;
	VaccineReturnNegativeTwoOnError(entrypoint);
	state.__eip = entrypoint;
	// (ESP) <- stack pointer
	state.__esp = stack;
	// (EBX) <- dlopen_arg
	state.__ebx = dlopen_arg;

	thread_act_t thread;
	err = thread_create(target, &thread);
	VaccineReturnNegativeTwoOnError(thread_create);
	err = thread_set_state(thread, x86_THREAD_STATE32, (thread_state_t)&state,
	                       x86_THREAD_STATE32_COUNT);
	VaccineReturnNegativeTwoOnError(thread_set_state);

	return thread;
}

/**
 *
 */
static
thread_act_t vaccine_thread64(task_t target, mach_vm_address_t stack,
                                   mach_vm_address_t dlopen_arg)
{
	assert(target), assert(stack), assert(dlopen_arg);

	stack += kVaccineRemoteStackSize;
	// Allocate some place for a dummy pthread struct
	mach_vm_address_t dummy = 0;
	int err = mach_vm_allocate(target, &dummy, sizeof(struct _opaque_pthread_t),
	                           VM_FLAGS_ANYWHERE);
	VaccineReturnNegativeTwoOnError(mach_vm_allocate);
	// Place a fake return address onto the stack
	uint64_t local_stack[] = {
		kVaccineJumpToDlopenReturnValue
	};
	size_t local_stack_size = sizeof(local_stack);
	err = mach_vm_write(target, (stack - local_stack_size),
	                    (vm_offset_t)local_stack, local_stack_size);
	VaccineReturnNegativeTwoOnError(mach_vm_write);
	// Iinitilize an x86_64 thread state
	x86_thread_state64_t state;
	memset(&state, 0, sizeof(state));
	// See a comment in vaccine_thread32() about why we refer to some strange
	// pthread thing instead of dlopen() here.

	// See a long comment in vaccine_thread32() about why we need to explicitly
	// specify the source image name here
	uint64_t entrypoint = lorgnette_lookup_image(target, "_pthread_set_self",
	                                             "libsystem_pthread.dylib");
	if (entrypoint == 0) err = KERN_FAILURE;
	VaccineReturnNegativeTwoOnError(entrypoint);
	state.__rip = entrypoint;
	// (RDI) <- dummy pthread struct
	state.__rdi = dummy;
	// (RSP) <- stack pointer
	// we simulate a ret instruction, so descrease the stack
	state.__rsp = stack - 8;
	// (RBX) <- dlopen_arg
	state.__rbx = dlopen_arg;

	thread_act_t thread;
	err = thread_create(target, &thread);
	VaccineReturnNegativeTwoOnError(thread_create);
	err = thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t)&state,
	                       x86_THREAD_STATE64_COUNT);
	VaccineReturnNegativeTwoOnError(thread_set_state);

	return thread;
}

/**
 * Waits for a single exception on |exception_port| and returns.
 * For return value see mach_msg_server_once().
 */
static
kern_return_t vaccine_catch_exception(mach_port_t exception_port)
{
	assert(exception_port);

	extern boolean_t exc_server(mach_msg_header_t *request,
	                            mach_msg_header_t *reply);
	kern_return_t err = mach_msg_server_once(exc_server, sizeof(exc_msg_t),
	                                         exception_port, 0);
	return err;
}

/**
 * Verifies that the given |thread| was suspended.
 * Writes (1) into |status| if it was, (0) otherwise.
 *
 * @return a positive number if thread_info() fails for |thread|
 * @return KERN_SUCCESS otherwise
 */
static
kern_return_t thread_was_suspended(thread_act_t thread, int *status)
{
	assert(thread), assert(status);

	thread_basic_info_data_t basic_info;
	mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;
	int err = thread_info(thread, THREAD_BASIC_INFO, (thread_info_t)&basic_info,
	                      &info_count);
	if (err != KERN_SUCCESS) return err;

	*status = (basic_info.suspend_count > 0);
	return KERN_SUCCESS;
}

/**
 * Fetches a value of |EAX| (or |RAX|) register from the given |thread|'s state.
 * It's flavor is defined by |flavor| argument: it should be either
 * x86_THREAD_STATE32 or x86_THREAD_STATE64.
 */
static
int64_t thread_get_ax_register(thread_act_t thread, thread_state_flavor_t flavor)
{
	assert(thread), assert(flavor);

	int64_t ax = 0;
	int err = KERN_FAILURE;

	if (flavor == x86_THREAD_STATE32) {
			x86_thread_state32_t state;
			mach_msg_type_number_t count = x86_THREAD_STATE32_COUNT;
			err = thread_get_state(thread, x86_THREAD_STATE32,
			                       (thread_state_t)&state, &count);
			VaccineReturnNegativeTwoOnError(thread_get_state);
			int32_t tmp = (int32_t)state.__eax;
			ax = tmp;
		} else {
			x86_thread_state64_t state;
			mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
			err = thread_get_state(thread, x86_THREAD_STATE64,
			                       (thread_state_t)&state, &count);
			VaccineReturnNegativeTwoOnError(thread_get_state);
			int64_t tmp = (int64_t)state.__rax;
			ax = tmp;
		}

	return ax;
}

/**
 * Loads a dynamic library at |shared_library_path| into the given |target|.
 *
 * @discussion
 * It calls  dlopen() inside a target by creating a remote thread, setting an
 * expection handler on it and catching any (expected) exceptions for rewinding
 * the thread.
 *
 * @return see dlopen() return value.
 */
static
int64_t task_loadlib(task_t target, const char *shared_library_path)
{
	assert(target), assert(shared_library_path);

	// Allocate enough memory for dlopen()'s first argument
	size_t remote_path_len = strlen(shared_library_path);
	remote_path_len += 1; // the terminator, I do remember about you!
	mach_vm_address_t remote_path = 0;
	int err = mach_vm_allocate(target, &remote_path, remote_path_len,
	                           VM_FLAGS_ANYWHERE);
	VaccineReturnNegativeTwoOnError(mach_vm_allocate);
	// Copy the payload path string into the target address space
	err = mach_vm_write(target, remote_path, (vm_offset_t)shared_library_path,
	                    (mach_msg_type_number_t)remote_path_len);
	VaccineReturnNegativeTwoOnError(mach_vm_write);
	// Allocate a remote stack (see kVaccineRemoteStackSize)
	mach_vm_address_t remote_stack = 0;
	err = mach_vm_allocate(target, &remote_stack, kVaccineRemoteStackSize,
	                       VM_FLAGS_ANYWHERE);
	VaccineReturnNegativeTwoOnError(mach_vm_allocate);
	// Configure a remote thread
	thread_act_t remote_thread = {0};
	thread_state_flavor_t flavor = task_thread_flavor(target);
	if (flavor == -1) err = KERN_FAILURE;
	VaccineReturnNegativeTwoOnError(task_thread_flavor);

	if (flavor == x86_THREAD_STATE32) {
		remote_thread = vaccine_thread32(target, remote_stack, remote_path);
	} else {
		remote_thread = vaccine_thread64(target, remote_stack, remote_path);
	}
	if (!remote_thread) err = KERN_FAILURE;
	VaccineReturnNegativeTwoOnError(task_vaccine_threadXX);

	// Setup an exception port for the thread
	mach_port_t exception_port = 0;
	err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
	                         &exception_port);
	VaccineReturnNegativeTwoOnError(mach_port_allocate);
	err = mach_port_insert_right(mach_task_self(), exception_port,
                                 exception_port, MACH_MSG_TYPE_MAKE_SEND);
	VaccineReturnNegativeTwoOnError(mach_port_insert_right);
	err = thread_set_exception_ports(remote_thread, EXC_MASK_BAD_ACCESS,
	                                 exception_port, EXCEPTION_STATE_IDENTITY,
	                                 flavor);
	VaccineReturnNegativeTwoOnError(thread_set_exception_ports);

	err = thread_resume(remote_thread);
	VaccineReturnNegativeTwoOnError(thread_resume);

	// Run the exception handling loop
	int64_t return_value = 0;
	while (1) {
		err = vaccine_catch_exception(exception_port);
		VaccineReturnNegativeTwoOnError(vaccine_catch_exception);
		int suspended = 0;
		err = thread_was_suspended(remote_thread, &suspended);
		VaccineReturnNegativeTwoOnError(thread_was_suspended);
		if (!suspended) continue;

		// OK, so our remote thread is done and we can grab a dlopen()
		// return value from |eax/rax| register then.
		return_value = thread_get_ax_register(remote_thread, flavor);
		// aaaaaand we've done our trip! Let's clean everything up
		err = thread_terminate(remote_thread);
		VaccineReturnNegativeTwoOnError(thread_terminate);
		err = mach_vm_deallocate(target, remote_path, remote_path_len);
		VaccineReturnNegativeTwoOnError(mach_vm_deallocate);
		err = mach_vm_deallocate(target, remote_stack, kVaccineRemoteStackSize);
		VaccineReturnNegativeTwoOnError(mach_vm_deallocate);
		err = mach_port_deallocate(mach_task_self(), exception_port);
		VaccineReturnNegativeTwoOnError(mach_port_deallocate);
		// bye!
		break;
	}

	return return_value;
}

/**
 * Injects a dynamic library at |payload_path| into the given |target|.
 *
 * @return KERN_SUCCESS
 *     The payload was loaded successfully into the target task.
 * @return KERN_FAILURE
 *     Something gone totally wrong on a task_vaccine’s side.
 * @return KERN_INVALID_TASK
 *     dlopen() was unable to load the given library into the given target
 *     (because of invalid library path, invalid target architecture, etc).
 */
kern_return_t task_vaccine(task_t target, const char *payload_path)
{
	assert(target);
	assert(payload_path);

	int64_t return_value = task_loadlib(target, payload_path);
	// dlopen() should return a library handle pointer which is greater than zero
	if (return_value > 0) {
		return KERN_SUCCESS;
	} else if (return_value == 0) {
		// dlopen() retruns zero when it can't load a library
		return KERN_INVALID_TASK;
	}

	return KERN_FAILURE;
}

/**
 * Catches an i386 thread exception and reconfigurates it to either call
 * dlopen() on it or suspend it, so task_vaccine() can finish it's job.
 *
 * @return general Mach exception handler errors:
 *
 * KERN_SUCCESS indicates that we've reset a thread's state and it's ready to
 * be resumed.
 *
 * MIG_NO_REPLY indicates that we've terminated or suspended the thread, so the
 * kernel won't handle it anymore. This one also breaks our exception handling
 * loop, so we able to finish the injection process.
 *
 * KERN_FAILURE indicates that we weren't expecting this kind of exception and
 * the kernel should take care of it.
 */
static
kern_return_t catch_i386_exception(task_t task, mach_port_t thread,
                                   x86_thread_state32_t *in_state,
                                   x86_thread_state32_t *out_state)
{
	assert(task), assert(thread), assert(in_state), assert(out_state);

	if (in_state->__eip == kVaccineFinishReturnValue) {
		// OK, Glass, finish here
		thread_suspend(thread);
		return MIG_NO_REPLY;
	} else if (in_state->__eip != kVaccineJumpToDlopenReturnValue) {
		// Oops, we broke something up
		return KERN_FAILURE;
	}
	// Well, setup a thread to execute dlopen() with a given library path
	memcpy(out_state, in_state, sizeof(*in_state));
	uint32_t dlopen_addr = lorgnette_lookup(task, "dlopen");
	out_state->__eip = dlopen_addr;
	out_state->__esp = ({
		// Our previous function added 4 to our stck pointer, discard this
		mach_vm_address_t stack = in_state->__esp - (sizeof(uint32_t));
		// simulate the call instruction
		stack -= 4;
		int mode = RTLD_NOW | RTLD_LOCAL;
		uint32_t local_stack[] = {
			kVaccineFinishReturnValue,
			in_state->__ebx, // we hold a library path here
			mode
		};
		int err = mach_vm_write(task, stack, (mach_vm_offset_t)local_stack,
		                       sizeof(local_stack));
		if (err != KERN_SUCCESS) {
			syslog(LOG_NOTICE, "[%d] mach_vm_write() failed: %d (%s)\n",
			                   __LINE__-4, err, mach_error_string(err));
			return KERN_FAILURE;
		}
		stack;
	});

	return KERN_SUCCESS;
}

/**
 * @see catch_i386_exception()
 */
static
kern_return_t catch_x86_64_exception(task_t task, mach_port_t thread,
                                     x86_thread_state64_t *in_state,
                                     x86_thread_state64_t *out_state)
{
	assert(task), assert(thread), assert(in_state), assert(out_state);

	if (in_state->__rip == kVaccineFinishReturnValue) {
		// OK, Glass, finish here
		thread_suspend(thread);
		return MIG_NO_REPLY;
	} else if (in_state->__rip != kVaccineJumpToDlopenReturnValue) {
		// Oops, we broke something up
		return KERN_FAILURE;
	}
	// Well, setup a thread to execute dlopen() with a given library path
	memcpy(out_state, in_state, sizeof(*in_state));
	uint64_t dlopen_addr = lorgnette_lookup(task, "dlopen");
	out_state->__rip = dlopen_addr;
	out_state->__rsi = RTLD_NOW | RTLD_LOCAL;
	out_state->__rdi = in_state->__rbx; // we hold a library path here
	out_state->__rsp = ({
		mach_vm_address_t stack = in_state->__rsp - 8;
		vm_offset_t new_ret_value_ptr = (vm_offset_t)&(uint64_t){
			kVaccineFinishReturnValue
		};
		int err = mach_vm_write(task, stack, new_ret_value_ptr,
		                        sizeof(kVaccineFinishReturnValue));
		if (err != KERN_SUCCESS) {
			syslog(LOG_NOTICE, "[%d] mach_vm_write() failed: %d (%s)\n",
			                   __LINE__-5, err, mach_error_string(err));
			return KERN_FAILURE;
		}
		stack;
	});

	return KERN_SUCCESS;
}

/**
 * see catch_i386_exception() and catch_x86_64_exception()
 */
__attribute__((visibility("default")))
kern_return_t
catch_exception_raise_state_identity(mach_port_t exception_port,
                                     mach_port_t thread,
                                     mach_port_t task,
                                     exception_type_t exception,
                                     exception_data_t code,
                                     mach_msg_type_number_t code_count,
                                     int *flavor, thread_state_t in_state,
                                     mach_msg_type_number_t in_state_count,
                                     thread_state_t out_state,
                                     mach_msg_type_number_t *out_state_count)
{
#pragma unused (exception_port, exception, code, code_count)
#pragma unused (in_state_count, out_state, out_state_count)

	if (*flavor == x86_THREAD_STATE64) {
		x86_thread_state64_t *in_state64 = (x86_thread_state64_t *)in_state;
		x86_thread_state64_t *out_state64 = (x86_thread_state64_t *)out_state;

		*out_state_count = x86_THREAD_STATE64_COUNT;
		return catch_x86_64_exception(task, thread, in_state64, out_state64);

	} else if (*flavor == x86_THREAD_STATE32) {
		x86_thread_state32_t *in_state32 = (x86_thread_state32_t *)in_state;
		x86_thread_state32_t *out_state32 = (x86_thread_state32_t *)out_state;

		*out_state_count = x86_THREAD_STATE32_COUNT;
		return catch_i386_exception(task, thread, in_state32, out_state32);
	}

	// Don't care about non-Intel. Let the kernel handle it.
	return KERN_FAILURE;
}
