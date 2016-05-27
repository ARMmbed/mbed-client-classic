/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef M2M_THREAD_WRAPPER_H__
#define M2M_THREAD_WRAPPER_H__

#include <Thread.h>
#include "rtos.h"

namespace rtos {

// Wrapper for more complex function as thread targets
template <typename T, void (*F)(T *)>
static void __thread_pointer_wrapper(const void *data)
{
    F((T*)data);
}

template <typename T, void (*F)(T *)>
static Thread *create_thread(T *arg=NULL,
                             osPriority priority=osPriorityNormal,
                             uint32_t stack_size=DEFAULT_STACK_SIZE,
                             unsigned char *stack_pointer=NULL)
{
    return new Thread(__thread_pointer_wrapper<F,T>, (void *)arg,
                      priority, stack_size, stack_pointer);
}

template <class T, void (T::*M)()>
static void __thread_class_wrapper(const void *data)
{
    (((T*)data)->*M)();
}

template <class T, void (T::*M)()>
static Thread *create_thread(T *obj,
                             osPriority priority=osPriorityNormal,
                             uint32_t stack_size=DEFAULT_STACK_SIZE,
                             unsigned char *stack_pointer=NULL)
{
    return new Thread(__thread_class_wrapper<T,M>, (void *)obj,
                      priority, stack_size, stack_pointer);
}

}
                                          
#endif //M2M_OBJECT_THREAD_H__
