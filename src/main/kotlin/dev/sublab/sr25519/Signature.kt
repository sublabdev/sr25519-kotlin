package dev.sublab.sr25519

import cafe.cryptography.curve25519.CompressedRistretto
import cafe.cryptography.curve25519.Scalar
import dev.sublab.common.ByteArrayConvertible

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
            return Signature(CompressedRistretto(lower), Scalar.fromCanonicalBytes(upper))
        }
    }
    /**
     * Convert this `Signature` to a byte array.
     */
    override fun toByteArray() = (R.toByteArray() + s.toByteArray()).apply {
        this[63] = (this[63].toInt() or 128).toByte()
    }
}