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

import dev.sublab.common.ByteArrayConvertible
import dev.sublab.curve25519.ristrettoElement.CompressedRistretto
import dev.sublab.curve25519.ristrettoElement.RistrettoElement
import dev.sublab.curve25519.ristrettoElement.RistrettoElement.Companion.RISTRETTO_GENERATOR_TABLE

const val PUBLIC_KEY_LENGTH = 32

class PublicKey(private val ristretto: RistrettoElement): Verifier, ByteArrayConvertible {
    companion object {
        /**
         * Decompress into the [PublicKey] format that also retains the compressed form.
         */
        fun fromCompressed(compressed: CompressedRistretto) = PublicKey(compressed.decompress())

        /**
         * Compress into the [PublicKey] format that also retains the uncompressed form.
         */
        fun fromByteArray(byteArray: ByteArray) = fromCompressed(CompressedRistretto(byteArray))
    }

    /**
     * Access the compressed Ristretto form
     */
    fun asCompressed(): CompressedRistretto = ristretto.compress()

    /**
     * Ristretto form byte array representation
     */
    override fun toByteArray(): ByteArray = asCompressed().toByteArray().copyOf()

    /**
     * Verify a signature by this public key on a transcript.
     * @param t a signing transcript to use
     * @param signature signature to verify
     * @return [Boolean] value indicating verification success
     *
     * Requires a `SigningTranscript`, normally created from a
     * `SigningContext` and a message, as well as the signature
     * to be verified.
     */
    @Throws(Exception::class)
    override fun verify(t: SigningTranscript, signature: Signature): Boolean {
        t.protoName("Schnorr-sig".toByteArray())
        t.commitPoint("sign:pk".toByteArray(), asCompressed())
        t.commitPoint("sign:R".toByteArray(), signature.R)

        val k = t.challengeScalar("sign:c".toByteArray())
        val R = RISTRETTO_GENERATOR_TABLE.multiply(signature.s).subtract(ristretto.multiply(k))

        return R.compress() == signature.R
    }

    /**
     * Verify a signature by this public key on a message.
     * @param context current context
     * @param message message from which public key is fetched
     * @param signature signature to verification success
     * @return [Boolean] value indicating
     */
    override fun verifySimple(context: ByteArray, message: ByteArray, signature: Signature): Boolean {
        val t = SigningContext.fromContext(context).bytes(message)
        return verify(t, signature)
    }
}