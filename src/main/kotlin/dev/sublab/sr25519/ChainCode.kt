/**
 *
 * Copyright 2024 SUBSTRATE LABORATORY LLC <info@sublab.dev>
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

const val CHAIN_CODE_LENGTH = 32;

class ChainCode @Throws(Exception::class) constructor(cc: ByteArray) {
    val cc: ByteArray

    init {
        require(cc.size <= CHAIN_CODE_LENGTH) {
            "Invalid chain code length. Should be ${CHAIN_CODE_LENGTH}, got ${cc.size} instead"
        }

        if (cc.size < CHAIN_CODE_LENGTH) {
            val ccInflated = ByteArray(32)
            cc.forEachIndexed { index, byte ->
                ccInflated[index] = byte
            }

            this.cc = ccInflated
        } else {
            this.cc = cc
        }
    }
}