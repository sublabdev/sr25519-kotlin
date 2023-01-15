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
import dev.sublab.curve25519.scalar.Scalar
import dev.sublab.curve25519.scalar.functions.toScalarCanonicalBytes

/// The length of a curve25519 EdDSA `Signature`, in bytes.
const val SIGNATURE_LENGTH = 64

private const val DESCRIPTION = "A 64 byte Ristretto Schnorr signature"

/**
 * A Ristretto Schnorr signature "detached" from the signed message.
 *
 * These cannot be converted to any Ed25519 signature because they hash
 * curve points in the Ristretto encoding.
 */
class Signature(
    val R: CompressedRistretto,
    val s: Scalar
): ByteArrayConvertible {
    companion object {
        /**
         * Construct a `Signature` from a slice of bytes.
         *
         * We distinguish schnorrkel signatures from ed25519 signatures
         * by setting the high bit of byte 31. We return an error if
         * this marker remains unset because otherwise schnorrkel
         * signatures would be indistinguishable from ed25519 signatures.
         * We cannot always distinguish between schnorrkel and ed25519
         * public keys either, so without this marker bit we could not
         * do batch verification in systems that support precisely
         * ed25519 and schnorrkel.
         *
         * We cannot distinguish amongst different `SigningTranscript`
         * types using these marker bits, but protocol should not need
         * two different transcript types.
         */
        @Throws(SignatureError.BytesLengthError::class)
        fun fromByteArray(byteArray: ByteArray): Signature {
            if (byteArray.size != SIGNATURE_LENGTH) {
                throw SignatureError.BytesLengthError("Signature", DESCRIPTION, SECRET_KEY_LENGTH)
            }

            val lower = byteArray.copyOf(32)
            val upper = byteArray.copyOfRange(32, 64)

            if (upper[31].toInt() and 128 == 0) {
                throw Exception("Signature not marked as schnorrkel, maybe try ed25519 instead")
            }

            upper[31] = (upper[31].toInt() and 127).toByte()
            return Signature(CompressedRistretto(lower), upper.toScalarCanonicalBytes())
        }
    }
    /**
     * Convert this `Signature` to a byte array.
     */
    override fun toByteArray() = (R.toByteArray() + s.toByteArray()).apply {
        this[63] = (this[63].toInt() or 128).toByte()
    }
}