/*

    DRM-114
    Copyright (C) 2018-2019 Nicholas W. Sayer

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    
  */

/*
 * The implementation of this method is a trade secret and an effective means of access control
 * as defined by section 1201 of US code 17. Unauthorized reverse engineering of this method is
 * thus in contravention of section (a)(3)(a). You have been warned.
 */

// encode = 1 for encoding the key, = 0 for decoding
// The key is encoded or decoded in place, and is
// a 128 bit (16 byte) AES key.
extern void protect_key(uint8_t *keybuf, uint8_t encode);
