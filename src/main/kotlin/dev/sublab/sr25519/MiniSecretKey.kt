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
import dev.sublab.curve25519.scalar.functions.toScalarBytesModOrderWide
import dev.sublab.hashing.hashers.sha512
import dev.sublab.hashing.hashing
import dev.sublab.merlin.TranscriptImpl
import kotlin.random.Random

/// The length of a Ristretto Schnorr `MiniSecretKey`, in bytes.
const val MINI_SECRET_KEY_LENGTH = 32

private const val DESCRIPTION = "Analogous to ed25519 secret key as 32 bytes, see RFC8032."

enum class ExpansionMode {
    UNIFORM,
    ED25519
}

class MiniSecretKey private constructor(private val seed: ByteArray): ByteArrayConvertible {
    companion object {
        /**
         * Construct a [MiniSecretKey] from a slice of bytes.
         * @param seed a seed used to construct a mini secret key
         * @return A mini secret key from the provided seed
         */
        @Throws(SignatureError.BytesLengthError::class)
        fun fromByteArray(seed: ByteArray): MiniSecretKey {
            if (seed.size != MINI_SECRET_KEY_LENGTH) {
                throw SignatureError.BytesLengthError(
                    "MiniSecretKey",
                    DESCRIPTION,
                    MINI_SECRET_KEY_LENGTH
                )
            }

            return MiniSecretKey(seed.copyOf())
        }

        /**
         * Generate a [MiniSecretKey]` from default `csprng`.
         * @return A mini secret key
         */
        fun generate() = generateWith(SecureRandom())

        /**
         * Generate a [MiniSecretKey] from a `csprng`.
         */
        fun <R: Random> generateWith(random: R) = MiniSecretKey(random.nextBytes(32))
    }

    /**
     * Expand this [MiniSecretKey] into a [SecretKey]
     * @return A [SecretKey] from expanding [MiniSecretKey]
     *
     * We produce a secret keys using merlin and more uniformly
     * with this method, which reduces binary size and benefits
     * some future protocols.
     */
    @Throws(Exception::class)
    private fun expandUniform(): SecretKey {
        val t = TranscriptImpl("ExpandSecretKeys".toByteArray())
        t.appendMessage("mini".toByteArray(), seed)

        val scalarBytes = ByteArray(64)
        t.challengeBytes("sk".toByteArray(), scalarBytes)

        val key = scalarBytes.toScalarBytesModOrderWide().toByteArray()

        val nonce = ByteArray(32)
        t.challengeBytes("no".toByteArray(), nonce)

        return SecretKey(key, nonce)
    }

    /**
     * Expand this `MiniSecretKey` into a [SecretKey] using
     * ed25519-style bit clamping.
     *
     * At present, there is no exposed mapping from Ristretto
     * to the underlying Edwards curve because Ristretto involves
     * an inverse square root, and thus two such mappings exist.
     * Ristretto could be made usable with Ed25519 keys by choosing
     * one mapping as standard, but doing so makes the standard more
     * complex, and possibly harder to implement.  If anyone does
     * standardize the mapping to the curve then this method permits
     * compatible schnorrkel and ed25519 keys.
     */
    private fun expandEd25519(): SecretKey {
        val r = seed.hashing.sha512()

        // We need not clamp in a Schnorr group like Ristretto, but here
        // we do so to improve Ed25519 comparability.
        r[0] = (r[0].toInt() and 248).toByte()
        r[31] = (r[31].toInt() and 63).toByte()
        r[31] = (r[31].toInt() or 64).toByte()

        // We then divide by the cofactor to internally keep a clean
        // representation mod l.
        val key = divideScalarBytesByCofactor(r.copyOf(32))
        val nonce = r.copyOfRange(32, 64)

        return SecretKey(key, nonce)
    }

    /**
     * Derive the [SecretKey] corresponding to this `[MiniSecretKey]`.
     * @param mode an expansion mode to use
     *
     * We caution that `mode` must always be chosen consistently.
     * We slightly prefer `ExpansionMode::Uniform` here, but both
     * remain secure under almost all situations.  There exists
     * deployed code using `ExpansionMode::Ed25519`, so you might
     * require that for compatibility.
     */
    @Throws(Exception::class)
    fun expand(mode: ExpansionMode) = when (mode) {
        ExpansionMode.UNIFORM -> expandUniform()
        ExpansionMode.ED25519 -> expandEd25519()
    }

    /**
     * Derive the [KeyPair] corresponding to this [MiniSecretKey].
     * @param mode an expansion mode to use
     */
    @Throws(Exception::class)
    fun expandToKeyPair(mode: ExpansionMode) = expand(mode).toKeyPair()

    /**
     * Derive the [PublicKey] corresponding to this [MiniSecretKey].
     * @param mode an expansion mode to use
     */
    @Throws(Exception::class)
    fun expandToPublic(mode: ExpansionMode) = expand(mode).toPublicKey()

    /**
     * Convert this secret key to a [ByteArray].
     */
    override fun toByteArray() = seed
}