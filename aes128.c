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

#include <string.h>

#include "aes.h"
#include "aes128.h"

void aes128_key_advance(const unsigned char* in, unsigned char* out,
    const unsigned char round_num) {
  // Create a pointer to the last row of the input key
  const unsigned char _in[4] = { 13, 14, 15, 12 };
  // Assign the round constant to the first byte
  out[0] = aes_rcon[round_num];
  // Iterate over and copy each input byte to the output byte
  for (unsigned char i = 0; i < 16; ++i) {
    // XOR this output byte with ...
    out[i] ^= in[i] ^ (i < 4 ?
      // ... the forward S-box substitution of in[13, 14, 15, 12] ...
      aes_sbox[in[_in[i]]] :
      // ... or the previous word's matching byte of output
      out[i - 4]);
  }
}

extern void aes128_key_init(aes128_key_t* key) {
  // Zero all key slots after the first
  memset(key->val + 16, 0, sizeof(key->val) - 16);
  // Calculate the full key schedule from the original key
  for (unsigned char i = 0, j = 1; i < 10; ++i, ++j)
    // Use the previous round's key to incrementally advance the key
    aes128_key_advance(key->val + (i << 4), key->val + (j << 4), j);
}
