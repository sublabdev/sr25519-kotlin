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
import dev.sublab.common.ByteArrayConvertible
import kotlin.random.Random

const val KEYPAIR_LENGTH = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH

private const val DESCRIPTION = "A 96 bytes Ristretto Schnorr keypair"

/**
 * A key pair object containing a secret key and a public key
 * @property secretKey A secret key
 * @property publicKey A public key
 */
class KeyPair(
    val secretKey: SecretKey,
    val publicKey: PublicKey,
): Signer, Verifier, ByteArrayConvertible {
    companion object {
        @Throws(SignatureError.BytesLengthError::class)
        private fun checkByteArray(byteArray: ByteArray) {
            if (byteArray.size != KEYPAIR_LENGTH) {
                throw SignatureError.BytesLengthError(
                    "KeyPair",
                    DESCRIPTION,
                    KEYPAIR_LENGTH
                )
            }
        }

        /**
         * Deserialize a [KeyPair] from bytes.
         *
         * @param byteArray a [ByteArray] consisting of byte representations of first a [SecretKey],
         * and then the corresponding Ristretto `PublicKey`.
         *
         * @throws SignatureError if [byteArray] size is not equal to [KEYPAIR_LENGTH]
         * @return EdDSA [KeyPair]
         */
        @Throws(Exception::class)
        fun fromByteArray(byteArray: ByteArray): KeyPair {
            checkByteArray(byteArray)

            val secretKey = SecretKey.fromByteArray(byteArray.copyOf(SECRET_KEY_LENGTH))
            val publicKey = PublicKey.fromByteArray(byteArray.copyOfRange(SECRET_KEY_LENGTH, KEYPAIR_LENGTH))

            return KeyPair(secretKey, publicKey)
        }

        /**
         * Deserialize a [KeyPair] from bytes with ed25519 style [SecretKey] format.
         *
         * @param byteArray a [ByteArray] representing the scalar for the secret key,
         * and then the corresponding Ristretto [PublicKey].
         *
         * @throws SignatureError if [byteArray] size is not equal to [KEYPAIR_LENGTH]
         * @return EdDSA `Keypair`
         */
        fun fromEd25519ByteArray(byteArray: ByteArray): KeyPair {
            checkByteArray(byteArray)

            val secretKey = SecretKey.fromEd25519ByteArray(byteArray.copyOf(SECRET_KEY_LENGTH))
            val publicKey = PublicKey.fromByteArray(byteArray.copyOfRange(SECRET_KEY_LENGTH, KEYPAIR_LENGTH))

            return KeyPair(secretKey, publicKey)
        }

        /**
         * Generate a Ristretto Schnorr [KeyPair] directly, bypassing the [MiniSecretKey] layer.
         */
        fun generate() = generateWith(SecureRandom())

        /**
         * Generate a Ristretto Schnorr [KeyPair] directly, from a user supplied [Random],
         * bypassing the `MiniSecretKey` layer.
         */
        fun <R: Random> generateWith(random: R) = SecretKey.generateWith(random).let {
            KeyPair(it, it.toPublicKey())
        }
    }

    /**
     * Serialize [KeyPair] to bytes with ed25519 secret key format.
     *
     * @returnA [ByteArray] consisting of first a [SecretKey] serialized like Ed25519,
     * and next the Ristretto [PublicKey]
     */
    fun toEd25519ByteArray() = ByteArray(KEYPAIR_LENGTH).apply {
        secretKey.toEd25519ByteArray().copyInto(this)
        publicKey.toByteArray().copyInto(this, SECRET_KEY_LENGTH)
    }

    /**
     * Serialize `[KeyPair]` to bytes.
     *
     * @return A [ByteArray] consisting of first a [SecretKey] serialized canonically,
     * and next the Ristretto [PublicKey]
     */
    override fun toByteArray() = secretKey.toByteArray() + publicKey.toByteArray()

    /**
     * Sign a message with a signing transcript
     * @param t signing transcript
     * @return A signature
     */
    override fun sign(t: SigningTranscript)
        = secretKey.sign(t)

    /**
     * Sign a message with a [SigningTranscript] but double check
     * @param t signing transcript
     * @return A signature
     */
    override fun signDoubleCheck(t: SigningTranscript)
        = secretKey.signDoubleCheck(t)

    /**
     * Sign a message with a context
     * @param context provided signing context
     * @param message message to sign
     * @return A signature
     */
    override fun signSimple(context: ByteArray, message: ByteArray)
        = secretKey.signSimple(context, message)

    /**
     * Sign a message with a context but double check
     * @param context provided signing context
     * @param message message to sign
     * @return A signature
     */
    override fun signSimpleDoubleCheck(context: ByteArray, message: ByteArray)
        = secretKey.signSimpleDoubleCheck(context, message)

    /**
     * Verify public key and signature
     * @param t signing transcript
     * @param signature signature to verify
     * @return A [Boolean] value indicating whether the verification was successful
     */
    override fun verify(t: SigningTranscript, signature: Signature)
        = publicKey.verify(t, signature)

    /**
     *  Verify a signature by this public key on a message.
     *  @return A [Boolean] value indicating whether the verification was successful
     */
    override fun verifySimple(context: ByteArray, message: ByteArray, signature: Signature)
        = publicKey.verifySimple(context, message, signature)
}