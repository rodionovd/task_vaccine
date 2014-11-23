// task_vaccine.h
// Copyright (c) 2014 Dmitry Rodionov
// https://github.com/rodionovd/task_vaccines
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

#pragma once
#include <mach/mach.h>

#ifdef __cplusplus
	extern "C" {
#endif
/**
 * Injects the |target| task with a shared library at |payload_path|.
 *
 * @param target
 * An identifier of the target process.
 * @param payload_path
 * A full or relative path to the library you want to load into the given
 * target. The library should be compatible with the target task. In order to be
 * meaningful, this library should also contain a constructor function that will
 * be executed on load.
 *
 * @return KERN_SUCCESS
 * The payload was loaded successfully into the target task.
 * @return KERN_INVALID_TASK
 * dlopen() failed to load the given library (e.g. target architecture doesn't
 * match the payload).
 * @return KERN_FAILURE
 * Something gone totally wrong on a task_vaccine’s side. Please open an issue
 * on GitHub.
 */
kern_return_t task_vaccine(task_t target, const char *payload_path);

#ifdef __cplusplus
	}
#endif
