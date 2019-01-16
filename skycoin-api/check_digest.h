/*
 * This file is part of the SKYCOIN project, https://www.skycoin.net/
 *
 * Copyright (C) 2018 <contact@skycoin.net>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Code inspired by 
 * https://github.com/kokke/tiny-regex-c/blob/master/re.c
 * */


static bool matchhexdigit(char c)
{
  return ((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F'));
}

int is_digest(char* digest) {
    if (strlen(digest) != 64) {
        return false;
    }
    bool bDigest = true;
    for (int i = 0; i < 64 && bDigest; ++i) {
        bDigest &= matchhexdigit(digest[i]);
    }
    return bDigest;
}