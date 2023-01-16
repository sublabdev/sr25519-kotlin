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

import com.chrynan.krypt.csprng.SecureRandom
import dev.sublab.common.numerics.toByteArray
import kotlin.random.Random

class TranscriptRngBuilder(private val strobe: Strobe128) {
    @Throws(Exception::class)
    fun rekeyWithWitnessBytes(label: ByteArray, witness: ByteArray) = apply {
        strobe.metaAd(label, false)
        strobe.metaAd(witness.size.toByteArray(), true)
        strobe.key(witness, false)
    }

    @Throws(Exception::class)
    fun finalize() = finalizeWith(SecureRandom())

    @Throws(Exception::class)
    fun <R: Random> finalizeWith(random: R): TranscriptRng {
        val randomBytes = random.nextBytes(32)

        strobe.metaAd("rng".toByteArray(), false)
        strobe.key(randomBytes, false)

        return TranscriptRng(strobe.clone())
    }
}