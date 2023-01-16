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

import dev.sublab.common.numerics.toByteArray
import kotlin.random.Random

class TranscriptRng(private val strobe: Strobe128) {
    fun <R: Random> nextUInt32(random: R) = random.nextInt()
    fun <R: Random> nextUInt64(random: R) = random.nextLong()

    @Throws(Exception::class)
    fun fillBytes(destination: ByteArray) {
        val destinationSize = destination.size.toByteArray()
        strobe.metaAd(destinationSize, false)
        strobe.prf(destination, false)
    }
}