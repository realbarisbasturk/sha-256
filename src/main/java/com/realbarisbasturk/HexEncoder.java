/*
 * Copyright 2022 Baris Basturk
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.realbarisbasturk;

public final class HexEncoder {

    public static String toHexString(final byte[] bytes) {
        final StringBuilder result = new StringBuilder();
        for (final byte i : bytes) {
            final int decimal = (int) i & 0XFF;
            String hex = Integer.toHexString(decimal);
            if (hex.length() % 2 == 1) {
                hex = "0" + hex;
            }

            result.append(hex);
        }

        return result.toString();
    }

}
