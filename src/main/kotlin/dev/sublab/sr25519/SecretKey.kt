package dev.sublab.sr25519

import dev.sublab.common.ByteArrayConvertible
import dev.sublab.curve25519.ristrettoElement.RistrettoElement.Companion.RISTRETTO_GENERATOR_TABLE
import dev.sublab.curve25519.scalar.Scalar
import dev.sublab.curve25519.scalar.functions.multiplyAndAdd
import dev.sublab.curve25519.scalar.functions.toScalarBytesModOrderWide
import dev.sublab.curve25519.scalar.functions.toScalarFromBits
import kotlin.random.Random

/// The length of the "key" portion of a Ristretto Schnorr secret key, in bytes.
const val SECRET_KEY_KEY_LENGTH = 32

/// The length of the "nonce" portion of a Ristretto Schnorr secret key, in bytes.
const val SECRET_KEY_NONCE_LENGTH = 32

/// The length of a Ristretto Schnorr key, `SecretKey`, in bytes.
const val SECRET_KEY_LENGTH = SECRET_KEY_KEY_LENGTH + SECRET_KEY_NONCE_LENGTH

private const val DESCRIPTION = "An ed25519-like expanded secret key as 64 bytes, as specified in RFC8032."

class SecretKey(
    val key: ByteArray,
    val nonce: ByteArray
): Signer, ByteArrayConvertible {
    companion object {
        /**
         * Construct an `SecretKey` from a slice of bytes, corresponding to
         * an Ed25519 expanded secret key.
         */
        @Throws(SignatureError.BytesLengthError::class)
        fun fromByteArray(byteArray: ByteArray): SecretKey {
            if (byteArray.size != SECRET_KEY_LENGTH) {
                throw SignatureError.BytesLengthError("PrivateKey", DESCRIPTION, SECRET_KEY_LENGTH)
            }

            return SecretKey(byteArray.copyOf(32), byteArray.copyOfRange(32, 64))
        }

        /**
         * Construct an `SecretKey` from a slice of bytes, corresponding to
         * an Ed25519 expanded secret key.
         */
        @Throws(SignatureError.BytesLengthError::class)
        fun fromEd25519ByteArray(byteArray: ByteArray): SecretKey {
            if (byteArray.size != SECRET_KEY_LENGTH) {
                throw SignatureError.BytesLengthError("PrivateKey", DESCRIPTION, SECRET_KEY_LENGTH)
            }

            var key = byteArray.copyOf(32)
            // TODO:  We should consider making sure the scalar is valid,
            // maybe by zeroing the high bit, or preferably by checking < l.
            // key[31] &= 0b0111_1111;
            // We divide by the cofactor to internally keep a clean
            // representation mod l.
            key = divideScalarBytesByCofactor(key)

            val nonce = byteArray.copyOfRange(32, 64)

            return SecretKey(key, nonce)
        }

        /**
         * Generate an "unbiased" `SecretKey` directly, bypassing the `MiniSecretKey` layer.
         */
        fun generate() = generateWith(Random.Default)

        /**
         * Generate an "unbiased" `SecretKey` directly from a user
         * supplied `csprng` uniformly, bypassing the `MiniSecretKey`
         * layer.
         */
        fun <R: Random> generateWith(random: R): SecretKey {
            val key = random.nextBytes(64)
            val nonce = random.nextBytes(32)

            return SecretKey(
                key.toScalarBytesModOrderWide().toByteArray(),
                nonce
            )
        }
    }

    /**
     * Convert this `SecretKey` into an array of 64 bytes with.
     *
     * Returns an array of 64 bytes, with the first 32 bytes being
     * the secret scalar represented canonically, and the last
     * 32 bytes being the seed for nonces.
     */
    override fun toByteArray() = key.copyOf() + nonce.copyOf()

    /**
     * Convert this `SecretKey` into an array of 64 bytes, corresponding to
     * an Ed25519 expanded secret key.
     *
     * Returns an array of 64 bytes, with the first 32 bytes being
     * the secret scalar shifted ed25519 style, and the last 32 bytes
     * being the seed for nonces.
     */
    fun toEd25519ByteArray() = multiplyScalarBytesByCofactor(key.copyOf()) + nonce.copyOf()

    /**
     * Derive the `PublicKey` corresponding to this `SecretKey`.
     */
    fun toPublicKey()
        = PublicKey(RISTRETTO_GENERATOR_TABLE.multiply(key.toScalarFromBits()))

    /**
     * Derive the `PublicKey` corresponding to this `SecretKey`.
     */
    fun toKeyPair() = KeyPair(this, toPublicKey())

    /**
     * Sign a transcript with this `SecretKey`.
     *
     * Requires a `SigningTranscript`, normally created from a
     * `SigningContext` and a message, as well as the public key
     * corresponding to `self`.  Returns a Schnorr signature.
     *
     * We employ a randomized nonce here, but also incorporate the
     * transcript like in a derandomized scheme, but only after first
     * extending the transcript by the public key. As a result, there
     * should be no attacks even if both the random number generator
     * fails and the function gets called with the wrong public key.
     */
    @Throws(Exception::class)
    override fun sign(t: SigningTranscript): Signature {
        t.protoName("Schnorr-sig".toByteArray())
        t.commitPoint("sign:pk".toByteArray(), toPublicKey().asCompressed())

        // context, message, A/public_key
        var r = t.witnessScalar("signing".toByteArray(), nonce)
        val R = RISTRETTO_GENERATOR_TABLE.multiply(r).compress()
        t.commitPoint("sign:R".toByteArray(), R)

        // context, message, A/public_key, R=rG
        val k = t.challengeScalar("sign:c".toByteArray())
        val s = k.multiplyAndAdd(key.toScalarFromBits(), r)

        Scalar.ZERO.also { r = it }

        return Signature(R, s)
    }

    /**
     * Sign a message with this `SecretKey`, but double-check the result.
     */
    @Throws(Exception::class)
    override fun signDoubleCheck(t: SigningTranscript): Signature {
        val signature = Signature.fromByteArray(sign(t.clone()).toByteArray())
        if (!toPublicKey().verify(t, signature)) {
            throw SignatureError.EquationFalse()
        }

        return signature
    }

    /**
     * Sign a message with this `SecretKey`.
     */
    @Throws(Exception::class)
    override fun signSimple(context: ByteArray, message: ByteArray): Signature {
        val t = SigningContext.fromContext(context).bytes(message)
        return sign(t)
    }

    /**
     * Sign a message with this `SecretKey`, but double-check the result.
     */
    @Throws(Exception::class)
    override fun signSimpleDoubleCheck(context: ByteArray, message: ByteArray): Signature {
        val t = SigningContext.fromContext(context).bytes(message)
        return signDoubleCheck(t)
    }
}