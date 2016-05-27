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
#include "mbed-client-classic/m2mtimerpimpl.h"
#include "mbed-client/m2mtimerobserver.h"
#include <cstdio>
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "mClt"

void timer_run_c( void const* arg)
{
    if(arg) {
        M2MTimerPimpl *pimpl = (M2MTimerPimpl*)arg;
        pimpl->timer_run();
    }
}

M2MTimerPimpl::M2MTimerPimpl(M2MTimerObserver& observer)
: _observer(observer),
  _single_shot(true),
  _interval(0),
  _type(M2MTimerObserver::Notdefined),
  _intermediate_interval(0),
  _total_interval(0),
  _status(0),
  _dtls_type(false),
  _final_thread(0),
  _timer(0)
{

}

M2MTimerPimpl::~M2MTimerPimpl()
{
    stop_timer();
    if(_timer) {
        delete _timer;
    }
    if(_final_thread) {
        delete _final_thread;
    }
}

void M2MTimerPimpl::start_timer(uint64_t interval,
                                M2MTimerObserver::Type type,
                                bool single_shot)
{
    if(_timer) {
        delete _timer;
        _timer = NULL;
    }
    _dtls_type = false;
    _intermediate_interval = 0;
    _total_interval = 0;
    _status = 0;
    _single_shot = single_shot;
    _interval = interval;
    _type = type;
    _running = true;
    os_timer_type timer_type = osTimerPeriodic;
    if(single_shot) {
        timer_type = osTimerOnce;
    }
    _timer = new RtosTimer(timer_run_c, timer_type, (void*)this);
    _timer->start(_interval);
}

void M2MTimerPimpl::start_dtls_timer(uint64_t intermediate_interval, uint64_t total_interval, M2MTimerObserver::Type type)
{
    if(_timer) {
        delete _timer;
        _timer = NULL;
    }
    _dtls_type = true;
    _intermediate_interval = intermediate_interval;
    _total_interval = total_interval;
    _status = 0;
    _type = type;
    _running = true;
    _timer = new RtosTimer(timer_run_c, osTimerOnce, (void*)this);
}

void M2MTimerPimpl::stop_timer()
{
    _running = false;
    if(_timer) {
        _timer->stop();
    }
}

void M2MTimerPimpl::timer_expired()
{
    _observer.timer_expired(_type);
}

void M2MTimerPimpl::timer_run()
{    
    if (!_dtls_type) {
        if(_final_thread) {
            delete _final_thread;
            _final_thread = NULL;
        }
        _final_thread = rtos::create_thread<M2MTimerPimpl, &M2MTimerPimpl::timer_expired>(this);
    } else {
        if(_status == 0) {
            _status++;

            tr_debug("M2MTimerPimpl::timer_run - Start Final Timer");
            _timer->start(_total_interval - _intermediate_interval);
        } else if(_status == 1) {
            tr_debug("M2MTimerPimpl::timer_run - Final Timer Expired");
            if(_final_thread) {
                delete _final_thread;
                _final_thread = NULL;
            }
            _final_thread = rtos::create_thread<M2MTimerPimpl, &M2MTimerPimpl::timer_expired>(this);
        }
    }
}

bool M2MTimerPimpl::is_intermediate_interval_passed()
{
    if (_status > 0) {
        return true;
    }
    return false;
}

bool M2MTimerPimpl::is_total_interval_passed()
{
    if (_status > 1) {
        return true;
    }
    return false;
}
