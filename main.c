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

#include "aes128.h"
#include "aes128ctr.h"

aes128_key_t     key;
aes128_nonce_t nonce;

void print_devices();
void timespec_diff(const struct timespec* start, struct timespec* end);
void usage(int argc, char* argv[]);

int main(int argc, char* argv[]) {
  FILE*        fp = NULL;
  uint64_t   size =    0;
  uint64_t device =    0;
  uint64_t  limit =    0;

  // Ensure that the minimum number of arguments was provided
  if (argc < 6) {
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

  errno = 0;
  // Attempt to read the LIMIT held by the third argument
  limit = strtoull(argv[3], NULL, 10);
  if (errno != 0) {
    perror("limit: strtoull()");
    usage(argc, argv);
    return 4;
  }

  // Ensure that the provided KEY argument is the correct length
  if (strlen(argv[4]) != 32) {
    fprintf(stderr, "error: key must be 32 hexadecimal characters\n");
    usage(argc, argv);
    return 5;
  }
  errno = 0;
  // Attempt to read the low portion of the key first
  { uint64_t tmp = htonll(strtoull(argv[4] + 16, NULL, 16));
  memcpy(key.val + 8, &tmp, 8); tmp = 0; }
  // Replace the first byte of the low portion with a NULL character
  argv[4][16] = 0;
  // Finally, attempt to read the high portion of the key
  { uint64_t tmp = htonll(strtoull(argv[4],      NULL, 16));
  memcpy(key.val,     &tmp, 8); tmp = 0; }
  // Check for an error during either HIGH/LOW strtoull() operation
  if (errno != 0) {
    perror("key: strtoull()");
    usage(argc, argv);
    return 6;
  }

  // Ensure that the provided NONCE argument is the correct length
  if (strlen(argv[5]) != 16) {
    fprintf(stderr, "error: nonce must be 16 hexadecimal characters\n");
    usage(argc, argv);
    return 7;
  }
  errno = 0;
  // Attempt to read the NONCE held by the fifth argument
  { uint64_t tmp = htonll(strtoull(argv[5], NULL, 16));
  memcpy(nonce.val, &tmp, 8); tmp = 0; }
  if (errno != 0) {
    perror("nonce: strtoull()");
    usage(argc, argv);
    return 8;
  }

  // Create some state to store the status and duration of the ops
  uint64_t status = 0;
  struct timespec start = {0, 0}, end = {0, 0};

  // Create a buffer used to encrypt the file contents
  unsigned char* buf = (unsigned char*)malloc(limit << 4);

  // Attempt to initialize the AES128 key
  aes128_key_init(&key);
  // Attempt to initialize the AES128 CTR context
  aes128ctr_context_t context;
  cl_int code = aes128ctr_init(&context, device, limit, &key, &nonce);
  if (code != CL_SUCCESS) {
    fprintf(stderr, "OpenCL error: %d\n", code);
    usage(argc, argv);
    return 9;
  }

  // Attempt to open the FILE at the path held by the first argument
  FILE* ifp = NULL; FILE* ofp = NULL;
  if ((ifp = fopen(argv[1], "rb" )) == NULL ||
      (ofp = fopen(argv[1], "r+b")) == NULL) {
    perror("file: fopen()");
    usage(argc, argv);
    return 10;
  }

  // Begin tracking time required to execute
  clock_gettime(CLOCK_MONOTONIC, &start);

  while (!feof(ifp) && !ferror(ifp) && !ferror(ofp)) {
    // Attempt to read as many blocks for this worker as max kernels
    uint64_t  length = fread(buf, 16, limit, ifp) << 4;
    // Check to see that the requested number of blocks could not be read
    if (length < (limit << 4)) {
      fseek(ifp, status + length, SEEK_SET);
      // Attempt to read a partial block into the next block
      uint64_t bytes = fread(buf + length, 1, 16, ifp);
      // If we read non-zero bytes, then increment the length
      if (bytes > 0) length += bytes;
    }
    // Enqueue the kernel for execution on the OpenCL device
    aes128ctr_crypt_blocks(&context, (aes128_state_t*)buf,
      (length >> 4) + ((length & 15) > 0 ? 1 : 0));
    // Write the total encrypted length to the output file
    status += fwrite(buf, 1, length, ofp);
  }

  // Finish tracking time required to execute
  clock_gettime(CLOCK_MONOTONIC, &end);

  // #define DEBUG

  // Close the provided file to flush its contents
  fclose(ifp); fclose(ofp); ifp = ofp = NULL;
  // Destroy the AES128 CTR context
  aes128ctr_destroy(&context);
  #ifndef DEBUG
  // Free the buffer used for file encryption
  free(buf);
  #endif

  #ifdef DEBUG
  // Print the memory buffer to show the most recent data
  for (uint64_t i = 0; i < 256; ++i)
    fprintf(stderr, "%s%02x", (i % 16 == 0 ?
      (i == 0 ? "" : "\n") : " "), ((unsigned char*)buf)[i]);
  fprintf(stderr, "\n");
  // Free the buffer used for file encryption
  free(buf);
  #endif

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

void print_devices() {
  // Allocate storage space for required variables
  unsigned long valueSize =    0;
  cl_uint     deviceCount =    0;
  char*             value = NULL;
  cl_device_id*    device = NULL;

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
    fprintf(stderr, "\nUsage: %s <file> <device> <limit> <key> "
      "<nonce>\n", argv[0]);
    fprintf(stderr, "  * file   is a file path to in-place (de|en)crypt\n"
                    "  * device is a numeric index from above\n"
                    "  * limit  is a maximum number of kernels\n"
                    "  * key    is a 128-bit hexadecimal value\n"
                    "  * nonce  is a  64-bit hexadecimal value\n");
  } else {
    fprintf(stderr, "error: argc <= 0\n");
  }
}
