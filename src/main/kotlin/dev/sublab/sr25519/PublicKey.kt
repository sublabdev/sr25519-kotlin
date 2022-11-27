package dev.sublab.sr25519

import cafe.cryptography.curve25519.CompressedRistretto
import cafe.cryptography.curve25519.Constants
import cafe.cryptography.curve25519.RistrettoElement
import cafe.cryptography.curve25519.Scalar
import dev.sublab.common.ByteArrayConvertible

const val PUBLIC_KEY_LENGTH = 32

class PublicKey(private val ristretto: RistrettoElement): Verifier, ByteArrayConvertible {
    companion object {
        /**
         * Decompress into the `PublicKey` format that also retains the compressed form.
         */
        fun fromCompressed(compressed: CompressedRistretto) = PublicKey(compressed.decompress())

        /**
         * Compress into the `PublicKey` format that also retains the uncompressed form.
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

        val k: Scalar = t.challengeScalar("sign:c".toByteArray())
        val R = Constants.RISTRETTO_GENERATOR_TABLE.multiply(signature.s).subtract(ristretto.multiply(k))

        return R.compress() == signature.R
    }

    /**
     * Verify a signature by this public key on a message.
     */
    override fun verifySimple(context: ByteArray, message: ByteArray, signature: Signature): Boolean {
        val t = SigningContext.fromContext(context).bytes(message)
        return verify(t, signature)
    }
}