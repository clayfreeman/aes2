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

#define _LARGEFILE64_SOURCE
#define _POSIX_C_SOURCE 199309L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <OpenCL/OpenCL.h>

#include "aes128_key.h"
#include "aes128ctr_stream.h"

typedef struct {
  uint8_t val[8];
} aes128_nonce_t;

const char DCPU32[] = "aes128ctr.cpu32.bc";
const char DCPU64[] = "aes128ctr.cpu64.bc";
const char DGPU32[] = "aes128ctr.gpu32.bc";
const char DGPU64[] = "aes128ctr.gpu64.bc";

aes128_key_t     key;
aes128_nonce_t nonce;

int  check_device(uint64_t device);
cl_device_id get_device(uint64_t idx);
cl_program prepare_program(cl_context context, cl_device_id device);
void print_devices();
void timespec_diff(const struct timespec* start, struct timespec* end);
void usage(int argc, char* argv[]);

int main(int argc, char* argv[]) {
  FILE*              fp = NULL;
  size_t           size =    0;
  uint64_t       device =    0;

  // Ensure that the minimum of three arguments was provided
  if (argc < 5) {
    fprintf(stderr, "error: Not enough arguments.\n");
    usage(argc, argv);
    return 1;
  }

  errno = 0;
  // Attempt to open the FILE at the path held by the first argument
  if ((fp = fopen(argv[1], "r+b")) == NULL) {
    perror("file: fopen()");
    usage(argc, argv);
    return 2;
  }
  // Determine the size of the file
  fseek(fp, 0, SEEK_END); size = ftell(fp); fclose(fp); fp = NULL;

  errno = 0;
  // Attempt to read the DEVICE held by the second argument
  device = strtoull(argv[2], NULL, 10);
  if (errno != 0) {
    perror("device: strtoull()");
    usage(argc, argv);
    return 3;
  }
  if (!check_device(device)) {
    fprintf(stderr, "error: requested device number does not exist\n");
    usage(argc, argv);
    return 4;
  }

  // Ensure that the provided KEY argument is the correct length
  if (strlen(argv[3]) != 32) {
    fprintf(stderr, "error: key must be 32 hexadecimal characters\n");
    usage(argc, argv);
    return 5;
  }
  errno = 0;
  // Attempt to read the low portion of the key first
  { uint64_t tmp = htonll(strtoull(argv[3] + 16, NULL, 16));
  memcpy(key.val + 8, &tmp, 8); tmp = 0; }
  // Replace the first byte of the low portion with a NULL character
  argv[3][16] = 0;
  // Finally, attempt to read the high portion of the key
  { uint64_t tmp = htonll(strtoull(argv[3],      NULL, 16));
  memcpy(key.val,     &tmp, 8); tmp = 0; }
  // Check for an error during either HIGH/LOW strtoull() operation
  if (errno != 0) {
    perror("key: strtoull()");
    usage(argc, argv);
    return 6;
  }

  // Ensure that the provided NONCE argument is the correct length
  if (strlen(argv[4]) != 16) {
    fprintf(stderr, "error: nonce must be 16 hexadecimal characters\n");
    usage(argc, argv);
    return 7;
  }
  errno = 0;
  // Attempt to read the NONCE held by the second argument
  { uint64_t tmp = htonll(strtoull(argv[4], NULL, 16));
  memcpy(nonce.val, &tmp, 8); tmp = 0; }
  if (errno != 0) {
    perror("nonce: strtoull()");
    usage(argc, argv);
    return 8;
  }

  // Create some state to store the status and duration of the ops
  size_t status = 0;
  struct timespec start = {0, 0}, end = {0, 0};
  // Attempt to initialize the key and crypt the file
  aes128_key_init(&key);
  // Setup the execution environment for OpenCL
  const size_t     count = (1 << 25);
  cl_device_id   _device = get_device(device);
  cl_context     context = clCreateContext(NULL, 1, &_device, NULL, NULL, NULL);
  cl_command_queue queue = clCreateCommandQueue(context, _device, 0, NULL);
  cl_program     program = prepare_program(context, _device);
  cl_kernel       kernel = clCreateKernel(program, "aes128ctr_encrypt", NULL);
  // Copy the AES substitution box, Galois field multiplication lookup, key and
  // nonce into the device memory for faster kernel execution
  cl_mem             _st = clCreateBuffer(context, CL_MEM_READ_WRITE |
    CL_MEM_ALLOC_HOST_PTR, (count << 4),      NULL,           NULL);
  cl_mem             _sb = clCreateBuffer(context, CL_MEM_READ_ONLY  |
    CL_MEM_COPY_HOST_PTR,  sizeof(aes_sbox), (void*)aes_sbox, NULL);
  cl_mem             _g2 = clCreateBuffer(context, CL_MEM_READ_ONLY  |
    CL_MEM_COPY_HOST_PTR,  sizeof(aes_gal2), (void*)aes_gal2, NULL);
  cl_mem              _k = clCreateBuffer(context, CL_MEM_READ_ONLY  |
    CL_MEM_COPY_HOST_PTR,  sizeof(key),      (void*)&key,     NULL);
  cl_mem              _n = clCreateBuffer(context, CL_MEM_READ_ONLY  |
    CL_MEM_COPY_HOST_PTR,  sizeof(nonce),    (void*)&nonce,   NULL);
  unsigned long       _b = 0;
  // Assign arguments to the kernel
  clSetKernelArg(kernel, 0, sizeof(_st), (void*)&_st);
  clSetKernelArg(kernel, 1, sizeof(_sb), (void*)&_sb);
  clSetKernelArg(kernel, 2, sizeof(_g2), (void*)&_g2);
  clSetKernelArg(kernel, 3, sizeof(_k ), (void*)&_k );
  clSetKernelArg(kernel, 4, sizeof(_n ), (void*)&_n );
  clSetKernelArg(kernel, 5, sizeof(_b ), (void*)&_b );
  // Begin tracking time required to execute
  clock_gettime(CLOCK_MONOTONIC, &start);
  clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &count, NULL, 0, NULL, NULL);
  // Block until the command queue is finished
  clFinish(queue);
  // Finish tracking time required to execute
  clock_gettime(CLOCK_MONOTONIC, &end);
  // ### DEBUG
  unsigned char* buf = (unsigned char*)clEnqueueMapBuffer(queue, _st, CL_TRUE,
    CL_MAP_READ, 0, (count << 4), 0, NULL, NULL, NULL);
  for (size_t i = 0; i < (count << 4); ++i)
    fprintf(stderr, "%s%02x", (i % 16 == 0 ?
      (i == 0 ? "" : "\n") : " "), buf[i]);
  fprintf(stderr, "\n");
  // ### DEBUG
  // Release the memory held by the kernel object
  clReleaseKernel(kernel);
  // Release the memory held by the compiled program binary
  clReleaseProgram(program);
  // Release all device memory buffers
  clReleaseMemObject(_st);
  clReleaseMemObject(_sb);
  clReleaseMemObject(_g2);
  clReleaseMemObject(_k);
  clReleaseMemObject(_n);
  // Release the memory held by the command queue
  clReleaseCommandQueue(queue);
  // Release the memory held by the execution context
  clReleaseContext(context);
  timespec_diff(&start, &end);
  double duration = ((double)end.tv_sec + (end.tv_nsec / 1E9f));
  // Zero-initialize the nonce and key for security
  memset(nonce.val, 0, sizeof(nonce.val));
  memset(  key.val, 0, sizeof(  key.val));
  // Check the status of the cryption operation
  if (status != size) {
    fprintf(stderr, "error: Cryption failed\n");
    return 127;
  }
  fprintf(stderr, "success: Crypted %f MB in %f sec (%f MB/s)\n",
    (status / (double)(1 << 20)),  duration,
    (status / (double)(1 << 20)) / duration);

  return 0;
}

int check_device(uint64_t device) {
  cl_uint deviceCount = 0;
  // Fetch the total number of devices for this platform
  clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, 0, NULL, &deviceCount);
  return device < deviceCount;
}
/*
void enqueue_crypt(cl_command_queue queue, cl_kernel kernel) {
  //
}
*/

size_t file_get_contents(const char* path, unsigned char** out) {
  // Open the file path for binary read
  FILE* fh = fopen(path, "rb");
  // Determine the size of the file
  size_t fs = 0;
  fseek(fh, 0, SEEK_END);
  fs = ftell(fh);
  fseek(fh, 0, SEEK_SET);
  // Allocate some memory to store the resulting file contents
  (*out) = (unsigned char*)malloc(fs);
  // Read the entire file into the buffer
  size_t fr = fread(out, fs, 1, fh);
  fclose(fh);
  return fr;
}

cl_device_id get_device(uint64_t idx) {
  // Allocate storage space for required variables
  cl_uint deviceCount =    0;
  cl_device_id*   tmp = NULL;
  cl_device_id device = NULL;
  // Fetch the total number of devices for this platform
  clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, 0, NULL, &deviceCount);
  // Allocate some memory to hold information about each device
  tmp = (cl_device_id*)malloc(sizeof(cl_device_id) * deviceCount);
  // Fetch information for all available devices for this platform
  clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, deviceCount, tmp, NULL);
  device = tmp[idx];
  // Free the memory used for fetching devices
  free(tmp);
  return device;
}

cl_program prepare_program(cl_context context, cl_device_id device) {
  cl_uint        bits = 0;
  cl_device_type type = 0;
  // Fetch the device category and bit length information
  clGetDeviceInfo(device, CL_DEVICE_ADDRESS_BITS, sizeof(bits), &bits, NULL);
  clGetDeviceInfo(device, CL_DEVICE_TYPE,         sizeof(type), &type, NULL);
  // Determine the appropriate binary to load for execution
  const char* binary = NULL;
  if (type & CL_DEVICE_TYPE_CPU) {
    if (bits == 32) {
      binary = DCPU32;
    } else if (bits == 64) {
      binary = DCPU64;
    }
  } else if (type & CL_DEVICE_TYPE_GPU) {
    if (bits == 32) {
      binary = DGPU32;
    } else if (bits == 64) {
      binary = DGPU64;
    }
  }
  // Attempt to load the binary into a string
  if (binary != NULL) {
    // Attempt to create a program from the selected binary
    size_t         len = strlen(binary);
    cl_program program = clCreateProgramWithBinary(context, 1, &device, &len,
      (const unsigned char**)&binary, NULL, NULL);
    // Attempt to build the program for the device
    clBuildProgram(program, 1, &device, NULL, NULL, NULL);
    return program;
  }
  return NULL;
}

void print_devices() {
  // Allocate storage space for required variables
  size_t     valueSize =    0;
  cl_uint  deviceCount =    0;
  char*          value = NULL;
  cl_device_id* device = NULL;

  // Fetch the total number of devices for this platform
  clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, 0, NULL, &deviceCount);
  // Allocate some memory to hold information about each device
  device = (cl_device_id*)malloc(sizeof(cl_device_id) * deviceCount);
  // Fetch information for all available devices for this platform
  clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, deviceCount, device, NULL);
  fprintf(stderr, "\nList of OpenCL devices:\n");
  for (cl_uint i = 0; i < deviceCount; ++i) {
    // Fetch the length of the name for this device
    clGetDeviceInfo(device[i], CL_DEVICE_NAME, 0, NULL, &valueSize);
    value = (char*)malloc(valueSize);
    clGetDeviceInfo(device[i], CL_DEVICE_NAME, valueSize, value, NULL);
    fprintf(stderr, "  %d. %s\n", i, value);
    free(value);
  }
  free(device);
}

void timespec_diff(const struct timespec* start, struct timespec* end) {
  if ((end->tv_nsec - start->tv_nsec) < 0) {
    end->tv_sec  -= start->tv_sec  - 1;
    end->tv_nsec -= start->tv_nsec + 1000000000;
  } else {
    end->tv_sec  -= start->tv_sec;
    end->tv_nsec -= start->tv_nsec;
  }
}

void usage(int argc, char* argv[]) {
  if (argc > 0) {
    print_devices();
    fprintf(stderr, "\nUsage: %s <file> <device> <key> <nonce>\n", argv[0]);
    fprintf(stderr, "  * file   is a file path to in-place (de|en)crypt\n"
                    "  * device is a numeric index from above\n"
                    "  * key    is a 128-bit hexadecimal value\n"
                    "  * nonce  is a  64-bit hexadecimal value\n");
  } else {
    fprintf(stderr, "error: argc <= 0\n");
  }
}
