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

/**
 * An unrolled, instruction optimized AES128 CTR encryption kernel.
 *
 * This kernel encrypts a nonce concatenated with a ciphertext block index that
 * is calculated by adding a base index parameter and the kernel's global ID.
 *
 * This kernel was developed using my reference implementation of AES128 CTR
 * for pthread on CPU. This implementation can be found on GitHub at
 * clayfreeman/aes.
 *
 * @param  st  An output parameter used to store the results.
 * @param  sb  The byte-value keyed substitution box of AES.
 * @param  g2  The byte-value keyed Galois Field of 2**8.
 * @param  _k  The user-specified 128-bit key buffer.
 * @param  _n  The user-specified 64-bit nonce buffer.
 * @param  _b  The last ciphertext block offset before this batch began.
 */
__kernel void aes128ctr_encrypt(        __global   unsigned char* st,
    __constant unsigned char* const sb, __constant unsigned char* const g2,
    __constant unsigned char* const _k, __constant unsigned char* const _n,
               unsigned long        _b  ) {
  _b += get_global_id(0);
  st += get_global_id(0) << 4;
  unsigned char* _c = (unsigned char*)&_b;
  unsigned char  _t[ 16];
  #ifdef __ENDIAN_LITTLE__
    _c[0] ^= _c[7];
    _c[7] ^= _c[0];
    _c[0] ^= _c[7];
    _c[1] ^= _c[6];
    _c[6] ^= _c[1];
    _c[1] ^= _c[6];
    _c[2] ^= _c[5];
    _c[5] ^= _c[2];
    _c[2] ^= _c[5];
    _c[3] ^= _c[4];
    _c[4] ^= _c[3];
    _c[3] ^= _c[4];
  #endif
  st[ 0]   = _n[ 0];
  st[ 1]   = _n[ 1];
  st[ 2]   = _n[ 2];
  st[ 3]   = _n[ 3];
  st[ 4]   = _n[ 4];
  st[ 5]   = _n[ 5];
  st[ 6]   = _n[ 6];
  st[ 7]   = _n[ 7];
  st[ 8]   = _c[ 0];
  st[ 9]   = _c[ 1];
  st[10]   = _c[ 2];
  st[11]   = _c[ 3];
  st[12]   = _c[ 4];
  st[13]   = _c[ 5];
  st[14]   = _c[ 6];
  st[15]   = _c[ 7];
  _t[ 0]   = sb[_k[  0] ^ st[ 0]];
  _t[ 1]   = sb[_k[  5] ^ st[ 5]];
  _t[ 2]   = sb[_k[ 10] ^ st[10]];
  _t[ 3]   = sb[_k[ 15] ^ st[15]];
  _t[ 4]   = sb[_k[  4] ^ st[ 4]];
  _t[ 5]   = sb[_k[  9] ^ st[ 9]];
  _t[ 6]   = sb[_k[ 14] ^ st[14]];
  _t[ 7]   = sb[_k[  3] ^ st[ 3]];
  _t[ 8]   = sb[_k[  8] ^ st[ 8]];
  _t[ 9]   = sb[_k[ 13] ^ st[13]];
  _t[10]   = sb[_k[  2] ^ st[ 2]];
  _t[11]   = sb[_k[  7] ^ st[ 7]];
  _t[12]   = sb[_k[ 12] ^ st[12]];
  _t[13]   = sb[_k[  1] ^ st[ 1]];
  _t[14]   = sb[_k[  6] ^ st[ 6]];
  _t[15]   = sb[_k[ 11] ^ st[11]];
  st[ 0]   = sb[_k[ 16] ^ _t[ 1] ^ g2[_t[ 0]] ^ g2[_t[ 1]] ^ _t[ 2] ^ _t[ 3]];
  st[13]   = sb[_k[ 17] ^ _t[ 2] ^ _t[ 0] ^ g2[_t[ 1]] ^ g2[_t[ 2]] ^ _t[ 3]];
  st[10]   = sb[_k[ 18] ^ _t[ 3] ^ _t[ 0] ^ _t[ 1] ^ g2[_t[ 2]] ^ g2[_t[ 3]]];
  st[ 7]   = sb[_k[ 19] ^ _t[ 0] ^ g2[_t[ 0]] ^ _t[ 1] ^ _t[ 2] ^ g2[_t[ 3]]];
  st[ 4]   = sb[_k[ 20] ^ _t[ 5] ^ g2[_t[ 4]] ^ g2[_t[ 5]] ^ _t[ 6] ^ _t[ 7]];
  st[ 1]   = sb[_k[ 21] ^ _t[ 6] ^ _t[ 4] ^ g2[_t[ 5]] ^ g2[_t[ 6]] ^ _t[ 7]];
  st[14]   = sb[_k[ 22] ^ _t[ 7] ^ _t[ 4] ^ _t[ 5] ^ g2[_t[ 6]] ^ g2[_t[ 7]]];
  st[11]   = sb[_k[ 23] ^ _t[ 4] ^ g2[_t[ 4]] ^ _t[ 5] ^ _t[ 6] ^ g2[_t[ 7]]];
  st[ 8]   = sb[_k[ 24] ^ _t[ 9] ^ g2[_t[ 8]] ^ g2[_t[ 9]] ^ _t[10] ^ _t[11]];
  st[ 5]   = sb[_k[ 25] ^ _t[10] ^ _t[ 8] ^ g2[_t[ 9]] ^ g2[_t[10]] ^ _t[11]];
  st[ 2]   = sb[_k[ 26] ^ _t[11] ^ _t[ 8] ^ _t[ 9] ^ g2[_t[10]] ^ g2[_t[11]]];
  st[15]   = sb[_k[ 27] ^ _t[ 8] ^ g2[_t[ 8]] ^ _t[ 9] ^ _t[10] ^ g2[_t[11]]];
  st[12]   = sb[_k[ 28] ^ _t[13] ^ g2[_t[12]] ^ g2[_t[13]] ^ _t[14] ^ _t[15]];
  st[ 9]   = sb[_k[ 29] ^ _t[14] ^ _t[12] ^ g2[_t[13]] ^ g2[_t[14]] ^ _t[15]];
  st[ 6]   = sb[_k[ 30] ^ _t[15] ^ _t[12] ^ _t[13] ^ g2[_t[14]] ^ g2[_t[15]]];
  st[ 3]   = sb[_k[ 31] ^ _t[12] ^ g2[_t[12]] ^ _t[13] ^ _t[14] ^ g2[_t[15]]];
  _t[ 0]   = sb[_k[ 32] ^ st[ 1] ^ g2[st[ 0]] ^ g2[st[ 1]] ^ st[ 2] ^ st[ 3]];
  _t[13]   = sb[_k[ 33] ^ st[ 2] ^ st[ 0] ^ g2[st[ 1]] ^ g2[st[ 2]] ^ st[ 3]];
  _t[10]   = sb[_k[ 34] ^ st[ 3] ^ st[ 0] ^ st[ 1] ^ g2[st[ 2]] ^ g2[st[ 3]]];
  _t[ 7]   = sb[_k[ 35] ^ st[ 0] ^ g2[st[ 0]] ^ st[ 1] ^ st[ 2] ^ g2[st[ 3]]];
  _t[ 4]   = sb[_k[ 36] ^ st[ 5] ^ g2[st[ 4]] ^ g2[st[ 5]] ^ st[ 6] ^ st[ 7]];
  _t[ 1]   = sb[_k[ 37] ^ st[ 6] ^ st[ 4] ^ g2[st[ 5]] ^ g2[st[ 6]] ^ st[ 7]];
  _t[14]   = sb[_k[ 38] ^ st[ 7] ^ st[ 4] ^ st[ 5] ^ g2[st[ 6]] ^ g2[st[ 7]]];
  _t[11]   = sb[_k[ 39] ^ st[ 4] ^ g2[st[ 4]] ^ st[ 5] ^ st[ 6] ^ g2[st[ 7]]];
  _t[ 8]   = sb[_k[ 40] ^ st[ 9] ^ g2[st[ 8]] ^ g2[st[ 9]] ^ st[10] ^ st[11]];
  _t[ 5]   = sb[_k[ 41] ^ st[10] ^ st[ 8] ^ g2[st[ 9]] ^ g2[st[10]] ^ st[11]];
  _t[ 2]   = sb[_k[ 42] ^ st[11] ^ st[ 8] ^ st[ 9] ^ g2[st[10]] ^ g2[st[11]]];
  _t[15]   = sb[_k[ 43] ^ st[ 8] ^ g2[st[ 8]] ^ st[ 9] ^ st[10] ^ g2[st[11]]];
  _t[12]   = sb[_k[ 44] ^ st[13] ^ g2[st[12]] ^ g2[st[13]] ^ st[14] ^ st[15]];
  _t[ 9]   = sb[_k[ 45] ^ st[14] ^ st[12] ^ g2[st[13]] ^ g2[st[14]] ^ st[15]];
  _t[ 6]   = sb[_k[ 46] ^ st[15] ^ st[12] ^ st[13] ^ g2[st[14]] ^ g2[st[15]]];
  _t[ 3]   = sb[_k[ 47] ^ st[12] ^ g2[st[12]] ^ st[13] ^ st[14] ^ g2[st[15]]];
  st[ 0]   = sb[_k[ 48] ^ _t[ 1] ^ g2[_t[ 0]] ^ g2[_t[ 1]] ^ _t[ 2] ^ _t[ 3]];
  st[13]   = sb[_k[ 49] ^ _t[ 2] ^ _t[ 0] ^ g2[_t[ 1]] ^ g2[_t[ 2]] ^ _t[ 3]];
  st[10]   = sb[_k[ 50] ^ _t[ 3] ^ _t[ 0] ^ _t[ 1] ^ g2[_t[ 2]] ^ g2[_t[ 3]]];
  st[ 7]   = sb[_k[ 51] ^ _t[ 0] ^ g2[_t[ 0]] ^ _t[ 1] ^ _t[ 2] ^ g2[_t[ 3]]];
  st[ 4]   = sb[_k[ 52] ^ _t[ 5] ^ g2[_t[ 4]] ^ g2[_t[ 5]] ^ _t[ 6] ^ _t[ 7]];
  st[ 1]   = sb[_k[ 53] ^ _t[ 6] ^ _t[ 4] ^ g2[_t[ 5]] ^ g2[_t[ 6]] ^ _t[ 7]];
  st[14]   = sb[_k[ 54] ^ _t[ 7] ^ _t[ 4] ^ _t[ 5] ^ g2[_t[ 6]] ^ g2[_t[ 7]]];
  st[11]   = sb[_k[ 55] ^ _t[ 4] ^ g2[_t[ 4]] ^ _t[ 5] ^ _t[ 6] ^ g2[_t[ 7]]];
  st[ 8]   = sb[_k[ 56] ^ _t[ 9] ^ g2[_t[ 8]] ^ g2[_t[ 9]] ^ _t[10] ^ _t[11]];
  st[ 5]   = sb[_k[ 57] ^ _t[10] ^ _t[ 8] ^ g2[_t[ 9]] ^ g2[_t[10]] ^ _t[11]];
  st[ 2]   = sb[_k[ 58] ^ _t[11] ^ _t[ 8] ^ _t[ 9] ^ g2[_t[10]] ^ g2[_t[11]]];
  st[15]   = sb[_k[ 59] ^ _t[ 8] ^ g2[_t[ 8]] ^ _t[ 9] ^ _t[10] ^ g2[_t[11]]];
  st[12]   = sb[_k[ 60] ^ _t[13] ^ g2[_t[12]] ^ g2[_t[13]] ^ _t[14] ^ _t[15]];
  st[ 9]   = sb[_k[ 61] ^ _t[14] ^ _t[12] ^ g2[_t[13]] ^ g2[_t[14]] ^ _t[15]];
  st[ 6]   = sb[_k[ 62] ^ _t[15] ^ _t[12] ^ _t[13] ^ g2[_t[14]] ^ g2[_t[15]]];
  st[ 3]   = sb[_k[ 63] ^ _t[12] ^ g2[_t[12]] ^ _t[13] ^ _t[14] ^ g2[_t[15]]];
  _t[ 0]   = sb[_k[ 64] ^ st[ 1] ^ g2[st[ 0]] ^ g2[st[ 1]] ^ st[ 2] ^ st[ 3]];
  _t[13]   = sb[_k[ 65] ^ st[ 2] ^ st[ 0] ^ g2[st[ 1]] ^ g2[st[ 2]] ^ st[ 3]];
  _t[10]   = sb[_k[ 66] ^ st[ 3] ^ st[ 0] ^ st[ 1] ^ g2[st[ 2]] ^ g2[st[ 3]]];
  _t[ 7]   = sb[_k[ 67] ^ st[ 0] ^ g2[st[ 0]] ^ st[ 1] ^ st[ 2] ^ g2[st[ 3]]];
  _t[ 4]   = sb[_k[ 68] ^ st[ 5] ^ g2[st[ 4]] ^ g2[st[ 5]] ^ st[ 6] ^ st[ 7]];
  _t[ 1]   = sb[_k[ 69] ^ st[ 6] ^ st[ 4] ^ g2[st[ 5]] ^ g2[st[ 6]] ^ st[ 7]];
  _t[14]   = sb[_k[ 70] ^ st[ 7] ^ st[ 4] ^ st[ 5] ^ g2[st[ 6]] ^ g2[st[ 7]]];
  _t[11]   = sb[_k[ 71] ^ st[ 4] ^ g2[st[ 4]] ^ st[ 5] ^ st[ 6] ^ g2[st[ 7]]];
  _t[ 8]   = sb[_k[ 72] ^ st[ 9] ^ g2[st[ 8]] ^ g2[st[ 9]] ^ st[10] ^ st[11]];
  _t[ 5]   = sb[_k[ 73] ^ st[10] ^ st[ 8] ^ g2[st[ 9]] ^ g2[st[10]] ^ st[11]];
  _t[ 2]   = sb[_k[ 74] ^ st[11] ^ st[ 8] ^ st[ 9] ^ g2[st[10]] ^ g2[st[11]]];
  _t[15]   = sb[_k[ 75] ^ st[ 8] ^ g2[st[ 8]] ^ st[ 9] ^ st[10] ^ g2[st[11]]];
  _t[12]   = sb[_k[ 76] ^ st[13] ^ g2[st[12]] ^ g2[st[13]] ^ st[14] ^ st[15]];
  _t[ 9]   = sb[_k[ 77] ^ st[14] ^ st[12] ^ g2[st[13]] ^ g2[st[14]] ^ st[15]];
  _t[ 6]   = sb[_k[ 78] ^ st[15] ^ st[12] ^ st[13] ^ g2[st[14]] ^ g2[st[15]]];
  _t[ 3]   = sb[_k[ 79] ^ st[12] ^ g2[st[12]] ^ st[13] ^ st[14] ^ g2[st[15]]];
  st[ 0]   = sb[_k[ 80] ^ _t[ 1] ^ g2[_t[ 0]] ^ g2[_t[ 1]] ^ _t[ 2] ^ _t[ 3]];
  st[13]   = sb[_k[ 81] ^ _t[ 2] ^ _t[ 0] ^ g2[_t[ 1]] ^ g2[_t[ 2]] ^ _t[ 3]];
  st[10]   = sb[_k[ 82] ^ _t[ 3] ^ _t[ 0] ^ _t[ 1] ^ g2[_t[ 2]] ^ g2[_t[ 3]]];
  st[ 7]   = sb[_k[ 83] ^ _t[ 0] ^ g2[_t[ 0]] ^ _t[ 1] ^ _t[ 2] ^ g2[_t[ 3]]];
  st[ 4]   = sb[_k[ 84] ^ _t[ 5] ^ g2[_t[ 4]] ^ g2[_t[ 5]] ^ _t[ 6] ^ _t[ 7]];
  st[ 1]   = sb[_k[ 85] ^ _t[ 6] ^ _t[ 4] ^ g2[_t[ 5]] ^ g2[_t[ 6]] ^ _t[ 7]];
  st[14]   = sb[_k[ 86] ^ _t[ 7] ^ _t[ 4] ^ _t[ 5] ^ g2[_t[ 6]] ^ g2[_t[ 7]]];
  st[11]   = sb[_k[ 87] ^ _t[ 4] ^ g2[_t[ 4]] ^ _t[ 5] ^ _t[ 6] ^ g2[_t[ 7]]];
  st[ 8]   = sb[_k[ 88] ^ _t[ 9] ^ g2[_t[ 8]] ^ g2[_t[ 9]] ^ _t[10] ^ _t[11]];
  st[ 5]   = sb[_k[ 89] ^ _t[10] ^ _t[ 8] ^ g2[_t[ 9]] ^ g2[_t[10]] ^ _t[11]];
  st[ 2]   = sb[_k[ 90] ^ _t[11] ^ _t[ 8] ^ _t[ 9] ^ g2[_t[10]] ^ g2[_t[11]]];
  st[15]   = sb[_k[ 91] ^ _t[ 8] ^ g2[_t[ 8]] ^ _t[ 9] ^ _t[10] ^ g2[_t[11]]];
  st[12]   = sb[_k[ 92] ^ _t[13] ^ g2[_t[12]] ^ g2[_t[13]] ^ _t[14] ^ _t[15]];
  st[ 9]   = sb[_k[ 93] ^ _t[14] ^ _t[12] ^ g2[_t[13]] ^ g2[_t[14]] ^ _t[15]];
  st[ 6]   = sb[_k[ 94] ^ _t[15] ^ _t[12] ^ _t[13] ^ g2[_t[14]] ^ g2[_t[15]]];
  st[ 3]   = sb[_k[ 95] ^ _t[12] ^ g2[_t[12]] ^ _t[13] ^ _t[14] ^ g2[_t[15]]];
  _t[ 0]   = sb[_k[ 96] ^ st[ 1] ^ g2[st[ 0]] ^ g2[st[ 1]] ^ st[ 2] ^ st[ 3]];
  _t[13]   = sb[_k[ 97] ^ st[ 2] ^ st[ 0] ^ g2[st[ 1]] ^ g2[st[ 2]] ^ st[ 3]];
  _t[10]   = sb[_k[ 98] ^ st[ 3] ^ st[ 0] ^ st[ 1] ^ g2[st[ 2]] ^ g2[st[ 3]]];
  _t[ 7]   = sb[_k[ 99] ^ st[ 0] ^ g2[st[ 0]] ^ st[ 1] ^ st[ 2] ^ g2[st[ 3]]];
  _t[ 4]   = sb[_k[100] ^ st[ 5] ^ g2[st[ 4]] ^ g2[st[ 5]] ^ st[ 6] ^ st[ 7]];
  _t[ 1]   = sb[_k[101] ^ st[ 6] ^ st[ 4] ^ g2[st[ 5]] ^ g2[st[ 6]] ^ st[ 7]];
  _t[14]   = sb[_k[102] ^ st[ 7] ^ st[ 4] ^ st[ 5] ^ g2[st[ 6]] ^ g2[st[ 7]]];
  _t[11]   = sb[_k[103] ^ st[ 4] ^ g2[st[ 4]] ^ st[ 5] ^ st[ 6] ^ g2[st[ 7]]];
  _t[ 8]   = sb[_k[104] ^ st[ 9] ^ g2[st[ 8]] ^ g2[st[ 9]] ^ st[10] ^ st[11]];
  _t[ 5]   = sb[_k[105] ^ st[10] ^ st[ 8] ^ g2[st[ 9]] ^ g2[st[10]] ^ st[11]];
  _t[ 2]   = sb[_k[106] ^ st[11] ^ st[ 8] ^ st[ 9] ^ g2[st[10]] ^ g2[st[11]]];
  _t[15]   = sb[_k[107] ^ st[ 8] ^ g2[st[ 8]] ^ st[ 9] ^ st[10] ^ g2[st[11]]];
  _t[12]   = sb[_k[108] ^ st[13] ^ g2[st[12]] ^ g2[st[13]] ^ st[14] ^ st[15]];
  _t[ 9]   = sb[_k[109] ^ st[14] ^ st[12] ^ g2[st[13]] ^ g2[st[14]] ^ st[15]];
  _t[ 6]   = sb[_k[110] ^ st[15] ^ st[12] ^ st[13] ^ g2[st[14]] ^ g2[st[15]]];
  _t[ 3]   = sb[_k[111] ^ st[12] ^ g2[st[12]] ^ st[13] ^ st[14] ^ g2[st[15]]];
  st[ 0]   = sb[_k[112] ^ _t[ 1] ^ g2[_t[ 0]] ^ g2[_t[ 1]] ^ _t[ 2] ^ _t[ 3]];
  st[13]   = sb[_k[113] ^ _t[ 2] ^ _t[ 0] ^ g2[_t[ 1]] ^ g2[_t[ 2]] ^ _t[ 3]];
  st[10]   = sb[_k[114] ^ _t[ 3] ^ _t[ 0] ^ _t[ 1] ^ g2[_t[ 2]] ^ g2[_t[ 3]]];
  st[ 7]   = sb[_k[115] ^ _t[ 0] ^ g2[_t[ 0]] ^ _t[ 1] ^ _t[ 2] ^ g2[_t[ 3]]];
  st[ 4]   = sb[_k[116] ^ _t[ 5] ^ g2[_t[ 4]] ^ g2[_t[ 5]] ^ _t[ 6] ^ _t[ 7]];
  st[ 1]   = sb[_k[117] ^ _t[ 6] ^ _t[ 4] ^ g2[_t[ 5]] ^ g2[_t[ 6]] ^ _t[ 7]];
  st[14]   = sb[_k[118] ^ _t[ 7] ^ _t[ 4] ^ _t[ 5] ^ g2[_t[ 6]] ^ g2[_t[ 7]]];
  st[11]   = sb[_k[119] ^ _t[ 4] ^ g2[_t[ 4]] ^ _t[ 5] ^ _t[ 6] ^ g2[_t[ 7]]];
  st[ 8]   = sb[_k[120] ^ _t[ 9] ^ g2[_t[ 8]] ^ g2[_t[ 9]] ^ _t[10] ^ _t[11]];
  st[ 5]   = sb[_k[121] ^ _t[10] ^ _t[ 8] ^ g2[_t[ 9]] ^ g2[_t[10]] ^ _t[11]];
  st[ 2]   = sb[_k[122] ^ _t[11] ^ _t[ 8] ^ _t[ 9] ^ g2[_t[10]] ^ g2[_t[11]]];
  st[15]   = sb[_k[123] ^ _t[ 8] ^ g2[_t[ 8]] ^ _t[ 9] ^ _t[10] ^ g2[_t[11]]];
  st[12]   = sb[_k[124] ^ _t[13] ^ g2[_t[12]] ^ g2[_t[13]] ^ _t[14] ^ _t[15]];
  st[ 9]   = sb[_k[125] ^ _t[14] ^ _t[12] ^ g2[_t[13]] ^ g2[_t[14]] ^ _t[15]];
  st[ 6]   = sb[_k[126] ^ _t[15] ^ _t[12] ^ _t[13] ^ g2[_t[14]] ^ g2[_t[15]]];
  st[ 3]   = sb[_k[127] ^ _t[12] ^ g2[_t[12]] ^ _t[13] ^ _t[14] ^ g2[_t[15]]];
  _t[ 0]   = sb[_k[128] ^ st[ 1] ^ g2[st[ 0]] ^ g2[st[ 1]] ^ st[ 2] ^ st[ 3]];
  _t[13]   = sb[_k[129] ^ st[ 2] ^ st[ 0] ^ g2[st[ 1]] ^ g2[st[ 2]] ^ st[ 3]];
  _t[10]   = sb[_k[130] ^ st[ 3] ^ st[ 0] ^ st[ 1] ^ g2[st[ 2]] ^ g2[st[ 3]]];
  _t[ 7]   = sb[_k[131] ^ st[ 0] ^ g2[st[ 0]] ^ st[ 1] ^ st[ 2] ^ g2[st[ 3]]];
  _t[ 4]   = sb[_k[132] ^ st[ 5] ^ g2[st[ 4]] ^ g2[st[ 5]] ^ st[ 6] ^ st[ 7]];
  _t[ 1]   = sb[_k[133] ^ st[ 6] ^ st[ 4] ^ g2[st[ 5]] ^ g2[st[ 6]] ^ st[ 7]];
  _t[14]   = sb[_k[134] ^ st[ 7] ^ st[ 4] ^ st[ 5] ^ g2[st[ 6]] ^ g2[st[ 7]]];
  _t[11]   = sb[_k[135] ^ st[ 4] ^ g2[st[ 4]] ^ st[ 5] ^ st[ 6] ^ g2[st[ 7]]];
  _t[ 8]   = sb[_k[136] ^ st[ 9] ^ g2[st[ 8]] ^ g2[st[ 9]] ^ st[10] ^ st[11]];
  _t[ 5]   = sb[_k[137] ^ st[10] ^ st[ 8] ^ g2[st[ 9]] ^ g2[st[10]] ^ st[11]];
  _t[ 2]   = sb[_k[138] ^ st[11] ^ st[ 8] ^ st[ 9] ^ g2[st[10]] ^ g2[st[11]]];
  _t[15]   = sb[_k[139] ^ st[ 8] ^ g2[st[ 8]] ^ st[ 9] ^ st[10] ^ g2[st[11]]];
  _t[12]   = sb[_k[140] ^ st[13] ^ g2[st[12]] ^ g2[st[13]] ^ st[14] ^ st[15]];
  _t[ 9]   = sb[_k[141] ^ st[14] ^ st[12] ^ g2[st[13]] ^ g2[st[14]] ^ st[15]];
  _t[ 6]   = sb[_k[142] ^ st[15] ^ st[12] ^ st[13] ^ g2[st[14]] ^ g2[st[15]]];
  _t[ 3]   = sb[_k[143] ^ st[12] ^ g2[st[12]] ^ st[13] ^ st[14] ^ g2[st[15]]];
  st[ 0]   = sb[_k[144] ^ _t[ 1] ^ g2[_t[ 0]] ^ g2[_t[ 1]] ^ _t[ 2] ^ _t[ 3]];
  st[13]   = sb[_k[145] ^ _t[ 2] ^ _t[ 0] ^ g2[_t[ 1]] ^ g2[_t[ 2]] ^ _t[ 3]];
  st[10]   = sb[_k[146] ^ _t[ 3] ^ _t[ 0] ^ _t[ 1] ^ g2[_t[ 2]] ^ g2[_t[ 3]]];
  st[ 7]   = sb[_k[147] ^ _t[ 0] ^ g2[_t[ 0]] ^ _t[ 1] ^ _t[ 2] ^ g2[_t[ 3]]];
  st[ 4]   = sb[_k[148] ^ _t[ 5] ^ g2[_t[ 4]] ^ g2[_t[ 5]] ^ _t[ 6] ^ _t[ 7]];
  st[ 1]   = sb[_k[149] ^ _t[ 6] ^ _t[ 4] ^ g2[_t[ 5]] ^ g2[_t[ 6]] ^ _t[ 7]];
  st[14]   = sb[_k[150] ^ _t[ 7] ^ _t[ 4] ^ _t[ 5] ^ g2[_t[ 6]] ^ g2[_t[ 7]]];
  st[11]   = sb[_k[151] ^ _t[ 4] ^ g2[_t[ 4]] ^ _t[ 5] ^ _t[ 6] ^ g2[_t[ 7]]];
  st[ 8]   = sb[_k[152] ^ _t[ 9] ^ g2[_t[ 8]] ^ g2[_t[ 9]] ^ _t[10] ^ _t[11]];
  st[ 5]   = sb[_k[153] ^ _t[10] ^ _t[ 8] ^ g2[_t[ 9]] ^ g2[_t[10]] ^ _t[11]];
  st[ 2]   = sb[_k[154] ^ _t[11] ^ _t[ 8] ^ _t[ 9] ^ g2[_t[10]] ^ g2[_t[11]]];
  st[15]   = sb[_k[155] ^ _t[ 8] ^ g2[_t[ 8]] ^ _t[ 9] ^ _t[10] ^ g2[_t[11]]];
  st[12]   = sb[_k[156] ^ _t[13] ^ g2[_t[12]] ^ g2[_t[13]] ^ _t[14] ^ _t[15]];
  st[ 9]   = sb[_k[157] ^ _t[14] ^ _t[12] ^ g2[_t[13]] ^ g2[_t[14]] ^ _t[15]];
  st[ 6]   = sb[_k[158] ^ _t[15] ^ _t[12] ^ _t[13] ^ g2[_t[14]] ^ g2[_t[15]]];
  st[ 3]   = sb[_k[159] ^ _t[12] ^ g2[_t[12]] ^ _t[13] ^ _t[14] ^ g2[_t[15]]];
  st[ 0]  ^=    _k[160];
  st[ 1]  ^=    _k[161];
  st[ 2]  ^=    _k[162];
  st[ 3]  ^=    _k[163];
  st[ 4]  ^=    _k[164];
  st[ 5]  ^=    _k[165];
  st[ 6]  ^=    _k[166];
  st[ 7]  ^=    _k[167];
  st[ 8]  ^=    _k[168];
  st[ 9]  ^=    _k[169];
  st[10]  ^=    _k[170];
  st[11]  ^=    _k[171];
  st[12]  ^=    _k[172];
  st[13]  ^=    _k[173];
  st[14]  ^=    _k[174];
  st[15]  ^=    _k[175];
}
