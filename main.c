/**
 * Copyright (C) 2017  Clay Freeman.
 * This file is part of clayfreeman/aes.
 *
 * clayfreeman/aes is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * clayfreeman/aes is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with clayfreeman/aes; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <OpenCL/opencl.h>

#include "aes128_key.h"

// Define global storage for the encryption key
aes128_key_t key;

void print_devices() {
  // Allocate storage space for required variables
  size_t     valueSize =    0;
  cl_uint  deviceCount =    0;
  char*          value = NULL;
  cl_device_id* device = NULL;

  // Fetch the total number of devices for this platform
  clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, 0, NULL, &deviceCount);
  // Allocate some memory to hold information about each device
  device = (cl_device_id*) malloc(sizeof(cl_device_id) * deviceCount);
  // Fetch information for all available devices for this platform
  clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, deviceCount, device, NULL);
  for (cl_uint i = 0; i < deviceCount; ++i) {
    // Fetch the length of the name for this device
    clGetDeviceInfo(device[i], CL_DEVICE_NAME, 0, NULL, &valueSize);
    value = (char*)malloc(valueSize);
    clGetDeviceInfo(device[i], CL_DEVICE_NAME, valueSize, value, NULL);
    printf("%d. %s\n", i, value);
    free(value);
  }
  free(device);
}

void usage(const char* binary) {
  printf("\nUsage: %s deviceNum 0xKEY 0xNONCE file\n", binary);
  exit(1);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    puts("Please select a device:\n");
    print_devices();
    usage(argv[0]);
  } else {
    // Parse the provided device number

    if (argc < 3) {
      puts("Please specify an encryption key.");
      usage(argv[0]);
    } else {
      // Attempt to initialize the key
      aes128_key_init(&key);
    }
  }

  // Zero-wipe the key for security
  memset(key.val, 0, sizeof(key.val));

  return 0;
}
