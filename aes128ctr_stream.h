/**
 * Copyright (C) 2017  Clay Freeman.
 * This file is part of clayfreeman/aes2.
 *
 * clayfreeman/aes2 is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * clayfreeman/aes2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with clayfreeman/aes2; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __AES128_BUFFER_H
#define __AES128_BUFFER_H

#include <stddef.h>

#ifdef __APPLE__
  #include <OpenCL/opencl.h>
#else
  #include <CL/opencl.h>
#endif

typedef struct {
  /**
   * Variables pertaining to the ring buffer that is used to hold intermediary
   * AES128 CTR data that is to be XOR'ed with plain text.
   */
  unsigned char*  buffer; // Ring buffer memory space
  size_t           radix; // Block radix of the ring buffer
  size_t           index; // The current block read index
  size_t          offset; // The offset into the current block
  size_t           count; // The number of readable blocks

  /**
   * Variables pertaining to the execution context of the AES128 CTR OpenCL
   * kernel that is responsible for generating the XOR data stream.
   */
  cl_device_id    device;
  cl_context     context;
  cl_command_queue queue;
  cl_program     program;
  cl_kernel       kernel;

  /**
   * Variables used for the AES128 algorithm in the OpenCL kernel.
   */
  cl_mem             _st; // The globally accessible, host-mapped dumping ground
  cl_mem             _sb; // The AES character-indexed substitution box
  cl_mem             _g2; // The "times 2" Galois field 2**8
  cl_mem              _k; // The prepared key space for each AES round
  cl_mem              _n; // The constant nonce value used for CTR mode

  /**
   * Variables used to copy back results from the OpenCL device.
   */
  unsigned char*  result; // Host-mapped OpenCL-accessible pinned memory
  size_t         pending; // The number of blocks in the current kernel range
} aes128ctr_stream_t;

extern aes128ctr_stream_t aes128ctr_stream_create(cl_device_id device,
  size_t buffer_block_size, aes128_key_t key, aes128_nonce_t nonce);

#endif
