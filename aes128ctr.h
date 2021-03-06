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
   * Variables pertaining to the execution context of the AES128 CTR OpenCL
   * kernel that is responsible for encrypting input data.
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
  uint64_t         limit; // The maximum number of concurrent blocks allowed
  uint64_t         index; // The next block index to be encrypted
} aes128ctr_context_t;

extern cl_int aes128ctr_init(aes128ctr_context_t* const context,
  const uint64_t device, const uint64_t limit,
  const aes128_key_t* const key, const aes128_nonce_t* const nonce);

extern void aes128ctr_destroy(aes128ctr_context_t* const context);

extern uint64_t aes128ctr_crypt_blocks(aes128ctr_context_t* const context,
  aes128_state_t* data, uint64_t count);

#endif
