// task_vaccine.h
// Copyright (c) 2014 Dmitry Rodionov
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.
//
#pragma once
#include <mach/mach.h>

#ifdef __cplusplus
	extern "C" {
#endif
/**
 * [task_vaccine description]
 * @param  target       [description]
 * @param  payload_path [description]
 * @return              [description]
 */
kern_return_t task_vaccine(task_t target, const char *payload_path);

#ifdef __cplusplus
	}
#endif
