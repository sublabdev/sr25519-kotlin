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

package dev.sublab.merlin

import dev.sublab.hashing.hashers.keccak1600
import dev.sublab.hashing.hashing

private const val STROBE_R = 166
private const val FLAG_I = 1
private const val FLAG_A = 1 shl 1
private const val FLAG_C = 1 shl 2
private const val FLAG_T = 1 shl 3
private const val FLAG_M = 1 shl 4
private const val FLAG_K = 1 shl 5

class Strobe128(protocol: ByteArray, clone: Boolean = false): Cloneable {
    private var state: ByteArray = ByteArray(200).let { state ->
        byteArrayOf(1, (STROBE_R + 2).toByte(), 1, 0, 1, 96).copyInto(state)
        "STROBEv1.0.2".toByteArray().copyInto(state, 6)
        state.hashing.keccak1600()
    }

    init {
        if (!clone) {
            metaAd(protocol, false)
        }
    }

    private var pos = 0
    private var posBegin = 0
    private var curFlags = 0

    @Throws(Exception::class)
    fun metaAd(data: ByteArray, more: Boolean) {
        beginOp(FLAG_M or FLAG_A, more)
        absorb(data)
    }

    @Throws(Exception::class)
    fun ad(data: ByteArray, more: Boolean) {
        beginOp(FLAG_A, more)
        absorb(data)
    }

    @Throws(Exception::class)
    fun prf(data: ByteArray, more: Boolean) {
        beginOp(FLAG_I or FLAG_A or FLAG_C, more)
        squeeze(data)
    }

    @Throws(Exception::class)
    fun key(data: ByteArray, more: Boolean) {
        beginOp(FLAG_A or FLAG_C, more)
        overwrite(data)
    }

    private fun runF() {
        state[pos] = (state[pos].toInt() xor posBegin).toByte()
        state[pos + 1] = (state[pos + 1].toInt() xor 0x04).toByte()
        state[STROBE_R + 1] = (state[STROBE_R + 1].toInt() xor 0x80).toByte()
        state = state.hashing.keccak1600()
        pos = 0
        posBegin = 0
    }

    private fun absorb(data: ByteArray) {
        for (byte in data) {
            state[pos] = (state[pos].toInt() xor byte.toUByte().toInt()).toByte()
            pos += 1

            if (pos == STROBE_R) {
                runF()
            }
        }
    }

    private fun overwrite(data: ByteArray) {
        for (byte in data) {
            state[pos] = byte
            pos += 1

            if (pos == STROBE_R) {
                runF()
            }
        }
    }

    private fun squeeze(data: ByteArray) {
        for (i in data.indices) {
            data[i] = state[pos]
            state[pos] = 0
            pos += 1

            if (pos == STROBE_R) {
                runF()
            }
        }
    }

    @Throws(Exception::class)
    private fun beginOp(flags: Int, more: Boolean) {
        // Check if we're continuing an operation
        if (more) {
            if (curFlags != flags) {
                throw Exception("You tried to continue op $curFlags but changed flags to $flags")
            }
            return
        }

        // Skip adjusting direction information (we just use AD, PRF)
        if (flags and FLAG_T != 0) {
            throw Exception("You used the T flag, which this implementation doesn't support")
        }

        val oldBegin = posBegin
        posBegin = pos + 1
        curFlags = flags
        absorb(byteArrayOf(oldBegin.toByte(), flags.toByte()))

        // Force running F if C or K is set
        val forceF = 0 != (flags and (FLAG_C or FLAG_K))
        if (forceF && pos != 0) {
            runF()
        }
    }

    public override fun clone() = Strobe128(byteArrayOf(), true).let { strobe ->
        strobe.curFlags = curFlags
        strobe.pos = pos
        strobe.posBegin = posBegin
        strobe.state = state.copyOf()
        strobe
    }
}
