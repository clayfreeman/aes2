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

#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
  #include <OpenCL/opencl.h>
#else
  #include <CL/opencl.h>
#endif

#include "aes128.h"
#include "aes128ctr_stream.h"

#define MIN(a,b) \
  ({ __typeof__ (a) _a = (a); \
     __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b; })

const char DCPU32[] = "aes128ctr.cpu32.bc";
const char DCPU64[] = "aes128ctr.cpu64.bc";
const char DGPU32[] = "aes128ctr.gpu32.bc";
const char DGPU64[] = "aes128ctr.gpu64.bc";

/**
 * Creates an OpenCL device memory buffer.
 *
 * @param   buffer   An output parameter used to store the buffer.
 * @param   context  The OpenCL context for which to create a buffer.
 * @param   flags    Flags to modify how the buffer is created.
 * @param   size     The size of the buffer (or host pointer).
 * @param   ptr      A host pointer used to initialize the buffer.
 *
 * @return           See documentation for OpenCL's `clCreateBuffer()`.
 */
cl_int aes128ctr_stream_create_buffer(cl_mem* const buffer,
    cl_context* const context, const cl_mem_flags flags,
    const size_t size, void* ptr) {
  // Allocate storage for an error code and attempt to create the buffer
  cl_int status = CL_SUCCESS;
  (*buffer) = clCreateBuffer(*context, flags, size, ptr, &status);
  return status;
}

/**
 * Creates an OpenCL command queue for a specific context and device.
 *
 * @param   queue    An output parameter used to store the command queue.
 * @param   context  The OpenCL context for which to create a command queue.
 * @param   device   The OpenCL device ID for which to create a command queue.
 *
 * @return           See documentation for OpenCL's `clCreateCommandQueue()`.
 */
cl_int aes128ctr_stream_create_command_queue(cl_command_queue* const queue,
    cl_context* const context, cl_device_id* const device) {
  // Allocate storage for an error code and attempt to create the command queue
  cl_int status = CL_SUCCESS;
  (*queue) = clCreateCommandQueue(*context, *device, 0, &status);
  return status;
}

/**
 * Creates an OpenCL execution context for a specific device.
 *
 * @param   context  An output parameter used to store the context.
 * @param   device   The OpenCL device ID of the desired device.
 *
 * @return           See documentation for OpenCL's `clCreateContext()`.
 */
cl_int aes128ctr_stream_create_context(cl_context* const context,
    const cl_device_id* const device) {
  // Allocate storage for an error code and attempt to create the context
  cl_int status = CL_SUCCESS;
  (*context) = clCreateContext(NULL, 1, device, NULL, NULL, &status);
  return status;
}

/**
 * Creates an OpenCL kernel from an OpenCL program.
 *
 * @param   kernel   An output parameter used to store the kernel.
 * @param   program  The OpenCL program for which to create a kernel.
 *
 * @return           See documentation for OpenCL's `clCreateKernel()`.
 */
cl_int aes128ctr_stream_create_kernel(cl_kernel* const kernel,
    cl_program* const program) {
  // Allocate storage for an error code and attempt to create the kernel
  cl_int status = CL_SUCCESS;
  (*kernel) = clCreateKernel(*program, "aes128ctr_encrypt", &status);
  return status;
}

/**
 * Creates and builds the AES128 CTR program for a specific device.
 *
 * @param   program  An output parameter used to store the built program.
 * @param   context  The OpenCL context for which to create a program.
 * @param   device   The OpenCL device ID for which to create a program.
 *
 * @return           See documentation for OpenCL's
 *                   `clCreateProgramWithBinary()` and `clBuildProgram()`.
 */
cl_int aes128ctr_stream_create_program(cl_program* const program,
    cl_context* const context, cl_device_id* const device) {
  // Create some temporary variables used to create the program
  const char*     path = NULL;
  size_t      path_len = 0;
  cl_uint         bits = 0;
  cl_device_type  type = 0;
  cl_int binary_status = CL_SUCCESS;
  cl_int        status = CL_INVALID_DEVICE;
  // Fetch the device category and bit length information
  clGetDeviceInfo(*device, CL_DEVICE_ADDRESS_BITS, sizeof(bits), &bits, NULL);
  clGetDeviceInfo(*device, CL_DEVICE_TYPE,         sizeof(type), &type, NULL);
  // Determine the bytecode that should be used for this device
  if (type & CL_DEVICE_TYPE_CPU) {
    if (bits == 32) {
      path = DCPU32;
    } else if (bits == 64) {
      path = DCPU64;
    }
  } else if (type & CL_DEVICE_TYPE_GPU) {
    if (bits == 32) {
      path = DGPU32;
    } else if (bits == 64) {
      path = DGPU64;
    }
  }
  // Only continue if the binary path could be determined
  if (path != NULL) {
    // Calculate the string length of the binary path
    path_len   = strlen(path);
    // Create an OpenCL kernel for this context and device
    (*program) = clCreateProgramWithBinary(*context, 1, device, &path_len,
      (const unsigned char**)&path, &binary_status, &status);
    // Check that the program was loaded successfully
    if (status == CL_SUCCESS && binary_status == CL_SUCCESS) {
      // Build the program for the device
      return clBuildProgram(*program, 1, device, NULL, NULL, NULL);
    } else {
      // Skip the regular status code if successful
      return status == CL_SUCCESS ? binary_status : status;
    }
  }
  return status;
}

/**
 * Fetches an OpenCL device ID based on its index.
 *
 * @param   device  An output parameter used to store the device ID.
 * @param   index   The index of the desired OpenCL device.
 *
 * @return          `CL_SUCCESS`           (0) on success, or
 *                  `CL_DEVICE_NOT_FOUND` (19) if no such device.
 */
cl_int aes128ctr_stream_get_device_by_index(cl_device_id* const device,
    const size_t index) {
  // Allocate storage space for required variables
  cl_uint  device_count =    0;
  cl_device_id* devices = NULL;
  // Fetch the total number of devices for this platform
  clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, 0, NULL, &device_count);
  if (index < device_count) {
    // Allocate some memory to hold information about each device
    devices = (cl_device_id*)malloc(sizeof(cl_device_id) * device_count);
    // Fetch the ID of all available devices for this platform
    clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, device_count, devices, NULL);
    (*device) = devices[index];
    // Free the memory used for fetching devices
    free(devices);
    return CL_SUCCESS;
  } else {
    // The requested device doesn't exist
    return CL_DEVICE_NOT_FOUND;
  }
}

/**
 * Enqueue a blocking memory mapping to a device buffer.
 *
 * @param   map     An output parameter used to store the mapped address.
 * @param   queue   The command queue used to enqueue the mapping.
 * @param   buffer  The memory buffer for which to create a mapping.
 * @param   flags   Flags to modify how the mapping is created.
 * @param   offset  The desired offset within the memory buffer at which to
 *                  begin the mapping.
 * @param   length  The desired length of the mapping.
 *
 * @return          See documentation for OpenCL's `clEnqueueMapBuffer()`.
 */
cl_int aes128ctr_stream_map_buffer(void** const map,
    cl_command_queue* const queue, cl_mem* const buffer,
    const cl_map_flags flags, const size_t offset, const size_t length) {
  // Allocate storage for an error code and attempt to create the kernel
  cl_int status = CL_SUCCESS;
  (*map) = (unsigned char*)clEnqueueMapBuffer(*queue, *buffer, CL_TRUE, flags,
    offset, length, 0, NULL, NULL, &status);
  return status;
}

/**
 * Initializes an AES128 CTR data stream instance for a specific OpenCL device.
 *
 * @param   stream             The zero-index of the desired OpenCL device.
 * @param   device             The zero-index of the desired OpenCL device.
 * @param   buffer_block_size  The amount of 128-bit ciphertext blocks in the
 *                             buffer pool used to encrypt data.
 * @param   key                The key used to encrypt the plaintext input.
 * @param   nonce              The nonce used for the CTR block cipher mode.
 *
 * @return                     An OpenCL status (error) code.
 */
cl_int aes128ctr_stream_init(aes128ctr_stream_t* const stream,
    const size_t device, const size_t buffer_block_size,
    const aes128_key_t* const key, const aes128_nonce_t* const nonce) {
  // Create a temporary status variable for error checking
  cl_int status   = CL_SUCCESS;
  // Allocate the bytes required to store the requested number of blocks
  stream->size    = buffer_block_size << 4;
  stream->start   = (unsigned char*)malloc(stream->size);
  if (stream->start == NULL) return CL_MEM_OBJECT_ALLOCATION_FAILURE;
  // Initialize the remainder of pointers for the stream
  stream->end     = stream->start + stream->size;
  stream->read    = stream->start;
  stream->write   = stream->start;
  // Zero-initialize the length, block index and pending bytes count
  stream->length  = 0;
  stream->index   = 0;
  stream->pending = 0;
  // Attempt to fetch the OpenCL device ID of the preferred device by index
  status = aes128ctr_stream_get_device_by_index(&stream->device, device);
  if (status != CL_SUCCESS) return status;
  // Attempt to create an OpenCL execution context with the device
  status = aes128ctr_stream_create_context(&stream->context, &stream->device);
  if (status != CL_SUCCESS) return status;
  // Attempt to create a command queue for this context and device
  status = aes128ctr_stream_create_command_queue(&stream->queue,
    &stream->context, &stream->device);
  if (status != CL_SUCCESS) return status;
  // Attempt to create a program for this context and device
  status = aes128ctr_stream_create_program(&stream->program,
    &stream->context, &stream->device);
  if (status != CL_SUCCESS) return status;
  // Attempt to create a kernel for this program
  status = aes128ctr_stream_create_kernel(&stream->kernel, &stream->program);
  if (status != CL_SUCCESS) return status;
  // Attempt to create a pinned memory buffer for storing results
  status = aes128ctr_stream_create_buffer(&stream->_st, &stream->context,
    CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
    MIN(AES128CTR_STREAM_MAX_KERNELS, stream->size), NULL);
  if (status != CL_SUCCESS) return status;
  // Attempt to create a constant memory buffer for the substitution box
  status = aes128ctr_stream_create_buffer(&stream->_sb, &stream->context,
    CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(aes_sbox), (void*)aes_sbox);
  if (status != CL_SUCCESS) return status;
  // Attempt to create a constant memory buffer for the 2x Galois field of 2**8
  status = aes128ctr_stream_create_buffer(&stream->_g2, &stream->context,
    CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(aes_gal2), (void*)aes_gal2);
  if (status != CL_SUCCESS) return status;
  // Attempt to create a constant memory buffer for the key
  status = aes128ctr_stream_create_buffer(&stream->_k, &stream->context,
    CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(*key), (void*)key);
  if (status != CL_SUCCESS) return status;
  // Attempt to create a constant memory buffer for the nonce
  status = aes128ctr_stream_create_buffer(&stream->_n, &stream->context,
    CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(*nonce), (void*)nonce);
  if (status != CL_SUCCESS) return status;
  // Assign each memory buffer argument to the kernel
  status = clSetKernelArg(stream->kernel, 0,
    sizeof(stream->_st), (void*)&stream->_st);
  if (status != CL_SUCCESS) return status;
  status = clSetKernelArg(stream->kernel, 1,
    sizeof(stream->_sb), (void*)&stream->_sb);
  if (status != CL_SUCCESS) return status;
  status = clSetKernelArg(stream->kernel, 2,
    sizeof(stream->_g2), (void*)&stream->_g2);
  if (status != CL_SUCCESS) return status;
  status = clSetKernelArg(stream->kernel, 3,
    sizeof(stream->_k ), (void*)&stream->_k );
  if (status != CL_SUCCESS) return status;
  status = clSetKernelArg(stream->kernel, 4,
    sizeof(stream->_n ), (void*)&stream->_n );
  if (status != CL_SUCCESS) return status;
  return status;
}

cl_int aes128ctr_stream_refill(aes128ctr_stream_t* const stream) {
  cl_int status = CL_SUCCESS;
  // Determine the number of kernels that should be launched to refill
  stream->pending = MIN(AES128CTR_STREAM_MAX_KERNELS,
    (stream->size - stream->length) >> 4) << 4;
  // Calculate the number of kernels that should be executed
  size_t count = stream->pending >> 4;
  // Only attempt to refill the buffer if not already full
  if (count > 0) {
    // Set the block index offset kernel argument
    status = clSetKernelArg(stream->kernel, 5,
      sizeof(stream->index), &stream->index);
    if (status != CL_SUCCESS) return status;
    // Enqueue the pending number of kernels to the OpenCL device for execution
    status = clEnqueueNDRangeKernel(stream->queue, stream->kernel, 1,
      NULL, &count, NULL, 0, NULL, NULL);
    if (status != CL_SUCCESS) return status;
    // Map the result buffer to the OpenCL device state output
    status = aes128ctr_stream_map_buffer(&stream->result, &stream->queue,
      &stream->_st, CL_MAP_READ, 0, stream->pending);
    if (status != CL_SUCCESS) return status;
    // Wait until the queue is flushed before continuing
    status = clFinish(stream->queue);
    if (status != CL_SUCCESS) return status;
    // Increment the next block index based on the kernel count
    stream->index += count;
    // Determine if this refill crosses the boundary of the buffer
    if (stream->write + stream->pending > stream->end) {
      // Perform the first copy operation following the write pointer
      size_t partial = stream->end - stream->write;
      memcpy(stream->write, stream->result, partial);
      stream->write    = stream->start;
      stream->result  += partial;
      stream->length  += partial;
      stream->pending -= partial;
    }
    // Perform the final copy operation to refill the buffer
    memcpy(stream->write, stream->result, stream->pending);
    stream->write   = stream->start;
    stream->result += stream->pending;
    stream->length += stream->pending;
    stream->pending = 0;
    // Unmap the pinned memory region of the OpenCL device state
    status = (cl_int)clEnqueueUnmapMemObject(stream->queue, stream->_st,
      stream->result, 0, NULL, NULL);
    if (status != CL_SUCCESS) return status;
    stream->result = NULL;
  }
  return status;
}
