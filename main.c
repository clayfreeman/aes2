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

#include "aes128_key.h"

int main() {
  // Setup the initial state for the operation
  aes128_key_t  key = {"SOME 128 BIT KEY"};
  // Attempt to initialize the key
  aes128_key_init(&key);

  for (size_t i = 0; i < sizeof(key.val); ++i)
    printf("%s%02x", i % 16 == 0 ? "\n" : (i > 0 ? " " : ""), key.val[i]);
  printf("\n\n");



  // Zero-wipe the key for security
  memset(key.val, 0, sizeof(key.val));

  return 0;
}
