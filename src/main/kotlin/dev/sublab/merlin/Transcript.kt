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

private const val MERLIN_PROTOCOL_LABEL = "Merlin v1.0"

interface Transcript: Cloneable {
    fun appendMessage(label: ByteArray, message: ByteArray)
    fun appendUInt64(label: ByteArray, x: Long)
    fun challengeBytes(label: ByteArray, destination: ByteArray)
    fun buildRng(): TranscriptRngBuilder
}

class TranscriptImpl(private val strobe: Strobe128): Transcript {
    constructor(label: ByteArray): this(Strobe128(MERLIN_PROTOCOL_LABEL.toByteArray())) {
        appendMessage("dom-sep".toByteArray(), label)
    }

    @Throws(Exception::class)
    override fun appendMessage(label: ByteArray, message: ByteArray) {
        strobe.metaAd(label, false)
        strobe.metaAd(message.size.toByteArray(), true)
        strobe.ad(message, false)
    }

    @Throws(Exception::class)
    override fun appendUInt64(label: ByteArray, x: Long) = appendMessage(label, x.toByteArray())

    @Throws(Exception::class)
    override fun challengeBytes(label: ByteArray, destination: ByteArray) {
        strobe.metaAd(label, false)
        strobe.metaAd(destination.size.toByteArray(), true)
        strobe.prf(destination, false)
    }

    override fun buildRng() = TranscriptRngBuilder(strobe.clone())

    public override fun clone() = TranscriptImpl(strobe.clone())
}