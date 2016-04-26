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
#include "mbed-client-classic/m2mconnectionhandlerpimpl.h"
#include "mbed-client/m2mconnectionobserver.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mconnectionhandler.h"

#include "threadwrapper.h"
#include "mbed_error.h"

#include "NetworkInterface.h"
#include "UDPSocket.h"
#include "TCPSocket.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "mClt"

M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl(M2MConnectionHandler* base, M2MConnectionObserver &observer,
                                                     M2MConnectionSecurity* sec,
                                                     M2MInterface::BindingMode mode,
                                                     M2MInterface::NetworkStack stack)
:_base(base),
 _observer(observer),
 _security_impl(sec),
 _use_secure_connection(false),
 _binding_mode(mode),
 _network_stack(stack),
 _socket(0),
 _is_handshaking(false),
 _listening(false),
 _server_type(M2MConnectionObserver::LWM2MServer),
 _server_port(0),
 _listen_port(0),
 _socket_thread(0),
 _running(false),
 _network_interface(0),
 _socket_event(ESocketIdle),
 _socket_address(0)
{
    memset(&_address_buffer, 0, sizeof _address_buffer);
    memset(&_address, 0, sizeof _address);
    _address._address = _address_buffer;

    if (_network_stack != M2MInterface::LwIP_IPv4) {
        error("ConnectionHandler: Unsupported network stack, only IPv4 is currently supported");
    }
    _running = true;
    tr_debug("M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl() - Initializing thread");
    _socket_thread = new rtos::Thread(M2MConnectionHandlerPimpl::thread_handler,this,
                          osPriorityNormal, 4*1250);
}

M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl()
{
    if (_socket_thread) {
        delete _socket_thread;
        _socket_thread = 0;
    }
    if (_socket) {
        delete _socket;
        _socket = 0;
    }
    _network_interface = 0;
    delete _security_impl;
}

bool M2MConnectionHandlerPimpl::bind_connection(const uint16_t listen_port)
{
    _listen_port = listen_port;
    return true;
}

bool M2MConnectionHandlerPimpl::resolve_server_address(const String& server_address,
                                                       const uint16_t server_port,
                                                       M2MConnectionObserver::ServerType server_type,
                                                       const M2MSecurity* security)
{
    if (!_network_interface) {
        return false;
    }
    if(_socket) {
        delete _socket;
        _socket = NULL;
    }

    _socket_address = new SocketAddress(_network_interface,server_address.c_str(), server_port);
    if(M2MInterface::TCP == _binding_mode ||
       M2MInterface::TCP_QUEUE == _binding_mode) {
       tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - Using TCP");        
        _socket = new TCPSocket(_network_interface);
        if (((TCPSocket*)_socket)->connect(*_socket_address) < 0) {
            return false;
        }
        ((TCPSocket*)_socket)->attach_send(this,&M2MConnectionHandlerPimpl::send_event);
        ((TCPSocket*)_socket)->attach_recv(this, &M2MConnectionHandlerPimpl::receive_event);
    } else {
       tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - Using UDP");
        _socket = new UDPSocket(_network_interface);
        ((UDPSocket*)_socket)->bind(_listen_port);
        ((UDPSocket*)_socket)->attach_send(this,&M2MConnectionHandlerPimpl::send_event);
        ((UDPSocket*)_socket)->attach_recv(this, &M2MConnectionHandlerPimpl::receive_event);
    }
    _socket->set_blocking(false);

    _address._address = (void*)_socket_address->get_ip_address();
    tr_debug("IP Address %s",_socket_address->get_ip_address());
    tr_debug("Port %d",_socket_address->get_port());
    _address._length = strlen((char*)_address._address);
    _address._port = _socket_address->get_port();
    _address._stack = _network_stack;


    _running = true;

    if (security) {
        if (security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Certificate ||
            security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Psk) {
            if( _security_impl != NULL ){
                _security_impl->reset();
                _security_impl->init(security);
                _is_handshaking = true;
                tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - connect DTLS");
                if(_security_impl->start_connecting_non_blocking(_base) < 0 ){
                    //TODO: Socket error in SSL handshake,
                    // Define error code.
                    _is_handshaking = false;
                    _observer.socket_error(4);
                    return false;
                }
            }
        }
    }

    if(!_is_handshaking) {
        _observer.address_ready(_address,
                                server_type,
                                _address._port);
    }
    return true;
}

void M2MConnectionHandlerPimpl::send_handler()
{
    tr_debug("M2MConnectionHandlerPimpl::send_handler()");
    _observer.data_sent();
}

bool M2MConnectionHandlerPimpl::send_data(uint8_t *data,
                                          uint16_t data_len,
                                          sn_nsdl_addr_s *address)
{
    tr_debug("M2MConnectionHandlerPimpl::send_data()");
    if (address == NULL || data == NULL) {
        return false;
    }
    bool success = false;
    if(data){
        if( _use_secure_connection ){
            if( _security_impl->send_message(data, data_len) > 0){
                success = true;
            }
        } else {
            if(address) {
                int32_t ret = -1;
                if(M2MInterface::TCP == _binding_mode ||
                   M2MInterface::TCP_QUEUE == _binding_mode){
                    //We need to "shim" the length in front
                    uint16_t d_len = data_len+4;
                    uint8_t* d = (uint8_t*)malloc(data_len+4);

                    d[0] = (data_len >> 24 )& 0xff;
                    d[1] = (data_len >> 16 )& 0xff;
                    d[2] = (data_len >> 8 )& 0xff;
                    d[3] = data_len & 0xff;
                    memmove(d+4, data, data_len);
                    ret = ((TCPSocket*)_socket)->send(d,d_len);
                    free(d);
                }else {
                    ret = ((UDPSocket*)_socket)->sendto(*_socket_address,data, data_len);
                }
                if (ret > 0) {
                    success = true;
                }
            }
        }
    }
    return success;
 }

void M2MConnectionHandlerPimpl::thread_handler(void const *argument)
{
    M2MConnectionHandlerPimpl *pimpl = NULL;
    if(argument) {
    pimpl = (M2MConnectionHandlerPimpl*)(argument);
    while(pimpl->_running) {
        if(ESocketIdle == pimpl->_socket_event) {
            tr_debug("M2MConnectionHandlerPimpl::thread_handler  - ESocketIdle");
        } else if(ESocketReadytoRead == pimpl->_socket_event) {
            tr_debug("M2MConnectionHandlerPimpl::thread_handler  - ESocketReadytoRead");
            pimpl->_socket_event = ESocketIdle;
            if(pimpl->_is_handshaking) {
                pimpl->receive_handshake_handler();
            } else {
                pimpl->receive_handler();
            }
        } else if(ESocketWritten == pimpl->_socket_event) {
            tr_debug("M2MConnectionHandlerPimpl::thread_handler  - ESocketWritten");
            pimpl->_socket_event = ESocketIdle;
            if(!pimpl->_is_handshaking) {
                pimpl->send_handler();
            }
        }
        rtos::Thread::signal_wait(0x08);
    }
    }
}

void M2MConnectionHandlerPimpl::receive_event()
{
    tr_debug("M2MConnectionHandlerPimpl::receive_event()");
    _socket_event = ESocketReadytoRead;
    tr_debug("M2MConnectionHandlerPimpl::receive_event _ Get Thread State %d",(int)_socket_thread->get_state());
    _socket_thread->signal_set(0x08);
}

void M2MConnectionHandlerPimpl::send_event()
{
    tr_debug("M2MConnectionHandlerPimpl::send_event()");
    _socket_event = ESocketWritten;
    tr_debug("M2MConnectionHandlerPimpl::send_event _ Get Thread State %d",(int)_socket_thread->get_state());
    _socket_thread->signal_set(0x08);
}


bool M2MConnectionHandlerPimpl::start_listening_for_data()
{
    tr_debug("M2MConnectionHandlerPimpl::start_listening_for_data()");
    // Boolean return required for other platforms,
    // not needed in mbed OS Socket.
    _listening = true;
    return _listening;
}

void M2MConnectionHandlerPimpl::stop_listening()
{
    tr_debug("M2MConnectionHandlerPimpl::stop_listening()");
    _listening = false;
}

int M2MConnectionHandlerPimpl::send_to_socket(const unsigned char *buf, size_t len)
{
    tr_debug("M2MConnectionHandlerPimpl::send_to_socket len - %d", len);
    int size = -1;
    if(_binding_mode == M2MInterface::TCP ||
       _binding_mode == M2MInterface::TCP_QUEUE) {
        size = ((TCPSocket*)_socket)->send(buf,len);
    } else {
        size = ((UDPSocket*)_socket)->sendto(*_socket_address,buf,len);
    }
    tr_debug("M2MConnectionHandlerPimpl::send_to_socket size - %d", size);
    if(NSAPI_ERROR_WOULD_BLOCK == size){
        return M2MConnectionHandler::CONNECTION_ERROR_WANTS_WRITE;
    }else if(size < 0){
        return -1;
    }else{
        return size;
    }
}

int M2MConnectionHandlerPimpl::receive_from_socket(unsigned char *buf, size_t len)
{
    tr_debug("M2MConnectionHandlerPimpl::receive_from_socket");
    int recv = -1;
    if(_binding_mode == M2MInterface::TCP ||
       _binding_mode == M2MInterface::TCP_QUEUE) {
        recv = ((TCPSocket*)_socket)->recv(buf, len);
    } else {
        recv = ((UDPSocket*)_socket)->recvfrom(NULL,buf, len);
    }
    tr_debug("M2MConnectionHandlerPimpl::receive_from_socket recv size %d", recv);
    if(NSAPI_ERROR_WOULD_BLOCK == recv){
        return M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }else if(recv < 0){
        return -1;
    }else{
        return recv;
    }
}

void M2MConnectionHandlerPimpl::handle_connection_error(int /*error*/)
{
    tr_debug("M2MConnectionHandlerPimpl::handle_connection_error");
    _observer.socket_error(4);
}

void M2MConnectionHandlerPimpl::set_platform_network_handler(void *handler)
{
    tr_debug("M2MConnectionHandlerPimpl::set_platform_network_handler");
    _network_interface = (NetworkInterface*)handler;
}

void M2MConnectionHandlerPimpl::receive_handshake_handler()
{
    tr_debug("M2MConnectionHandlerPimpl::receive_handshake_handler()");
    if( _is_handshaking ){
        int ret = _security_impl->continue_connecting();
        tr_debug("M2MConnectionHandlerPimpl::receive_handshake_handler() - ret %d", ret);
        if( ret == M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ ){ //We wait for next readable event
            tr_debug("M2MConnectionHandlerPimpl::receive_handshake_handler() - We wait for next readable event");
            return;
        } else if( ret == 0 ){
            _is_handshaking = false;
            _use_secure_connection = true;
            _observer.address_ready(_address,
                                    _server_type,
                                    _server_port);
        }else if( ret < 0 ){
            //TODO: Socket error in SSL handshake,
            // Define error code.           
            _is_handshaking = false;            
            _observer.socket_error(4);
        }
    }
}

void M2MConnectionHandlerPimpl::receive_handler()
{
    tr_debug("M2MConnectionHandlerPimpl::receive_handler()");
    memset(_recv_buffer, 0, 1024);
    size_t receive_length = sizeof(_recv_buffer);

    if( _use_secure_connection ){
        int rcv_size = _security_impl->read(_recv_buffer, receive_length);
        if(rcv_size >= 0){
            _observer.data_available((uint8_t*)_recv_buffer,
                                     rcv_size, _address);
        } else if (M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ != rcv_size) {
            _observer.socket_error(1);
            return;
        }
    }else{
        int recv = -1;
        if(_binding_mode == M2MInterface::TCP ||
           _binding_mode == M2MInterface::TCP_QUEUE){
            recv = ((TCPSocket*)_socket)->recv(_recv_buffer, receive_length);

        }else{
            recv = ((UDPSocket*)_socket)->recvfrom(NULL,_recv_buffer, receive_length);
        }
        if (recv > 0) {
            // Send data for processing.
            if(_binding_mode == M2MInterface::TCP ||
               _binding_mode == M2MInterface::TCP_QUEUE){
                //We need to "shim" out the length from the front
                if( receive_length > 4 ){
                    uint64_t len = (_recv_buffer[0] << 24 & 0xFF000000) + (_recv_buffer[1] << 16 & 0xFF0000);
                    len += (_recv_buffer[2] << 8 & 0xFF00) + (_recv_buffer[3] & 0xFF);
                    if(len > 0) {
                        uint8_t* buf = (uint8_t*)malloc(len);
                        if(buf) {
                            memmove(buf, _recv_buffer+4, len);
                            // Observer for TCP plain mode
                            _observer.data_available(buf,len,_address);
                            free(buf);
                        }
                    }
                }else{
                    _observer.socket_error(1);
                }
            } else { // Observer for UDP plain mode
                tr_debug("M2MConnectionHandlerPimpl::receive_handler - data received %d", recv);
                _observer.data_available((uint8_t*)_recv_buffer,
                                         recv, _address);
            }
        } else {
            // Socket error in receiving
            _observer.socket_error(1);
        }
    }
}

void M2MConnectionHandlerPimpl::claim_mutex()
{
    //TODO: Implement mutex alongwith new SocketAPI migration work
}

void M2MConnectionHandlerPimpl::release_mutex()
{
    //TODO: Implement mutex alongwith new SocketAPI migration work
}


