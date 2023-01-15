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

/**
 * Schnorr signing context
 *
 * We expect users to have separate `SigningContext`s for each role
 * that signature play in their protocol.
 *
 * To sign a message, apply the appropriate inherent method to create
 * a signature transcript.
 *
 * You should use `merlin::Transcript`s directly if you must do
 * anything more complex, like use signatures in larger zero-knowledge
 * protocols or sign several components but only reveal one later.
 */
class SigningContext(private val transcript: SigningTranscript) {
    constructor(label: ByteArray): this(SigningTranscript(label))

    companion object {
        /**
         * Initialize a signing context from a static byte string
         * that identifies the signature's role in the larger protocol.
         */
        @Throws(Exception::class)
        fun fromContext(context: ByteArray): SigningContext {
            val t = SigningTranscript("SigningContext".toByteArray())
            t.appendMessage("".toByteArray(), context)
            return SigningContext(t)
        }
    }

    /**
     * Initialize an owned signing transcript on a message provided as a byte array.
     * @param bytes a [ByteArray] (message) used to create an owned signing transcript
     * @return signing transcript
     *
     * Avoid this method when processing large slices because it calls `Transcript.appendMessage` directly
     * and `merlin` is designed for domain separation, not performance.
     */
    @Throws(Exception::class)
    fun bytes(bytes: ByteArray): SigningTranscript {
        val t = transcript.clone()
        t.appendMessage("sign-bytes".toByteArray(), bytes)
        return t
    }
}