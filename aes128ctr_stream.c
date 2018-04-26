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

#include "aes128ctr_stream.h"

aes128ctr_stream_t aes128ctr_get_stream(size_t block_count) {
  aes128ctr_stream_t s;
  // Zero-initialize the index and block count
  s.index  = 0;
  s.count  = 0;
  // Set the radix of the ring buffer
  s.radix  = block_count;
  // Allocate the bytes required to store this radix of blocks
  s.buffer = (unsigned char*)malloc(s.radix << 4);
  return s;
}
