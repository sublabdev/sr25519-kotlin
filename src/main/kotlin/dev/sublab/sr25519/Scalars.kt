/**
 *
 * Copyright 2023 SUBSTRATE LABORATORY LLC <info@sublab.dev>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package dev.sublab.sr25519

internal fun divideScalarBytesByCofactor(input: ByteArray): ByteArray {
    val scalar = input.copyOf()

    var low: Byte = 0
    for ((i, byte) in scalar.reversed().withIndex()) {
        var b = byte.toUByte().toInt() // convert to UByte initially to keep proper bit shifting
        val r = b and 0b00000111 // save remainder

        b = b shr 3 // divide by 8
        b += low
        scalar[i] = b.toByte()

        low = (r shl 5).toByte()
    }

    return scalar.reversed().toByteArray()
}

internal fun multiplyScalarBytesByCofactor(input: ByteArray): ByteArray {
    val scalar = input.copyOf()

    var high: Byte = 0
    for ((i, byte) in scalar.withIndex()) {
        var b = byte.toUByte().toInt() // convert to UByte initially to keep proper bit shifting
        val r = b and 0b11100000 // carry bits

        b = b shl 3 // multiply by 8
        b += high
        scalar[i] = b.toByte()

        high = (r shr 5).toByte()
    }

    return scalar
}