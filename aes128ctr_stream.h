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

#define AES128CTR_STREAM_MAX_KERNELS 1UL << 20

typedef struct {
  /**
   * Variables pertaining to the ring buffer that is used to hold intermediary
   * AES128 CTR data that is to be XOR'ed with plain text.
   */
  unsigned char*   start; // Pointer to the beginning of the ring buffer
  unsigned char*     end; // Pointer to the end of the ring buffer
  unsigned char*    read; // The current read pointer in the buffer
  unsigned char*   write; // The current write pointer in the buffer
  size_t            size; // The number of bytes in the buffer
  size_t          length; // The number of readable bytes
  size_t           index; // The next AES128 CTR block index

  /**
   * Variables pertaining to the execution context of the AES128 CTR OpenCL
   * kernel that is responsible for generating the XOR data stream.
   */
  cl_device_id    device; // The OpenCL device ID
  cl_context     context; // The OpenCL execution context
  cl_command_queue queue; // The command queue for the execution context
  cl_program     program; // The compiled program containing the kernel
  cl_kernel       kernel; // The kernel to be ran on the OpenCL device

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
  size_t         pending; // The size of pending data in this kernel range
} aes128ctr_stream_t;

extern cl_int aes128ctr_stream_map_buffer(void** const map,
  cl_command_queue* const queue, cl_mem* const buffer,
  const cl_map_flags flags, const size_t offset, const size_t length);

extern cl_int aes128ctr_stream_init(aes128ctr_stream_t* const stream,
  const size_t device, const size_t buffer_block_size,
  const aes128_key_t* const key, const aes128_nonce_t* const nonce);

extern cl_int aes128ctr_stream_refill(aes128ctr_stream_t* const stream);

#endif
