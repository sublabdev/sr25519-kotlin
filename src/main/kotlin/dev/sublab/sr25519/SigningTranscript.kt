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

import com.chrynan.krypt.csprng.SecureRandom
import dev.sublab.curve25519.ristrettoElement.CompressedRistretto
import dev.sublab.curve25519.scalar.Scalar
import dev.sublab.curve25519.scalar.functions.toScalarBytesModOrderWide
import dev.sublab.merlin.Transcript
import dev.sublab.merlin.TranscriptImpl
import dev.sublab.merlin.TranscriptRngBuilder
import kotlin.random.Random

/**
 * We delegate `SigningTranscript` methods to the corresponding
 * inherent methods of `merlin.Transcript` and implement two
 * witness methods to avoid overwriting the `merlin.TranscriptRng`
 * machinery.
 */
class SigningTranscript(private val transcript: TranscriptImpl): Transcript {
    constructor(label: ByteArray) : this(TranscriptImpl(label))

    /**
     * Appends a proto-name to the transcript
     */
    @Throws(Exception::class)
    fun protoName(label: ByteArray) {
        transcript.appendMessage("proto-name".toByteArray(), label)
    }

    @Throws(Exception::class)
    fun commitPoint(label: ByteArray, compressed: CompressedRistretto) {
        transcript.appendMessage(label, compressed.toByteArray())
    }

    @Throws(Exception::class)
    fun witnessScalar(label: ByteArray, nonceSeeds: ByteArray): Scalar {
        val scalarBytes = ByteArray(64)
        witnessBytes(label, scalarBytes, nonceSeeds)
        return scalarBytes.toScalarBytesModOrderWide()
    }

    @Throws(Exception::class)
    fun witnessBytes(label: ByteArray, dest: ByteArray, nonceSeeds: ByteArray) {
        witnessBytesRng(label, dest, nonceSeeds, SecureRandom())
    }

    @Throws(Exception::class)
    fun <R: Random> witnessBytesRng(label: ByteArray, dest: ByteArray, nonceSeeds: ByteArray, random: R) {
        var br: TranscriptRngBuilder = transcript.buildRng()
        br = br.rekeyWithWitnessBytes(label, nonceSeeds)
        val r = br.finalizeWith(random)
        r.fillBytes(dest)
    }

    @Throws(Exception::class)
    fun challengeScalar(label: ByteArray): Scalar {
        val buffer = ByteArray(64)
        transcript.challengeBytes(label, buffer)
        return buffer.toScalarBytesModOrderWide()
    }

    /**
     * Appends a message to the transcript
     */
    override fun appendMessage(label: ByteArray, message: ByteArray)
        = transcript.appendMessage(label, message)
    
    /**
     * Appends a `Long` to the transcript
     */
    override fun appendUInt64(label: ByteArray, x: Long)
        = transcript.appendUInt64(label, x)

    override fun challengeBytes(label: ByteArray, destination: ByteArray)
        = transcript.challengeBytes(label, destination)

    /**
     * Builds `Rng`
     */
    override fun buildRng() = transcript.buildRng()

    /**
     * Clones the transcript
     */
    public override fun clone() = SigningTranscript(transcript.clone())
}