/**
 *
 * Copyright 2024 SUBSTRATE LABORATORY LLC <info@sublab.dev>
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

import dev.sublab.curve25519.scalar.functions.toScalarFromBits

private const val transcript = "SchnorrRistrettoHDKD"

// region Hard derivation

data class HardDerivationResult(
    val miniSecretKey: MiniSecretKey,
    val chainCode: ChainCode,
)

fun SecretKey.deriveHard(cc: ByteArray?): HardDerivationResult {
    val t = SigningTranscript(transcript.toByteArray())
    t.appendMessage("sign-bytes".toByteArray(), byteArrayOf())

    if (cc != null) {
        t.appendMessage("chain-code".toByteArray(), cc)
    }

    t.appendMessage("secret-key".toByteArray(), this.key)

    val msk = ByteArray(MINI_SECRET_KEY_LENGTH)
    t.challengeBytes("HDKD-hard".toByteArray(), msk)

    val chaincode = ByteArray(32)
    t.challengeBytes("HDKD-chaincode".toByteArray(), chaincode)

    return HardDerivationResult(
        MiniSecretKey.fromByteArray(msk),
        ChainCode(chaincode),
    )
}

fun MiniSecretKey.deriveHard(cc: ByteArray?, mode: ExpansionMode)
    = expand(mode).deriveHard(cc)

fun KeyPair.deriveHard(cc: ByteArray?, mode: ExpansionMode) = secretKey.deriveHard(cc)
    .miniSecretKey
    .expand(mode)
    .let { secretKey ->
        KeyPair(
            secretKey = secretKey,
            publicKey = secretKey.toPublicKey(),
        )
    }

// endregion

// region Simple derivation

data class SimpleDerivationResult(
    val secretKey: SecretKey,
    val chainCode: ChainCode,
)

fun SecretKey.deriveSimple(cc: ByteArray?): SimpleDerivationResult {
    val t = SigningTranscript(transcript.toByteArray())
    t.appendMessage("sign-bytes".toByteArray(), byteArrayOf())

    if (cc != null) {
        t.appendMessage("chain-code".toByteArray(), cc)
    }

    t.commitPoint("public-key".toByteArray(), toPublicKey().asCompressed())

    val scalar = t.challengeScalar("HDKD-scalar".toByteArray())

    val chaincode = ByteArray(32)
    t.challengeBytes("HDKD-chaincode".toByteArray(), chaincode)

    val nonce = ByteArray(32)
    t.witnessBytes(
        "HDKD-nonce".toByteArray(),
        nonce,
        arrayOf(
            this.nonce.copyOf(),
            toByteArray()
        ),
    )

    return SimpleDerivationResult(
        secretKey = SecretKey(
            key = key.toScalarFromBits().add(scalar).toByteArray(),
            nonce = nonce,
        ),
        chainCode = ChainCode(chaincode),
    )
}

fun MiniSecretKey.deriveSimple(cc: ByteArray?, mode: ExpansionMode)
        = expand(mode).deriveSimple(cc)

fun KeyPair.deriveSimple(cc: ByteArray?) = secretKey.deriveSimple(cc)
    .secretKey
    .let { secretKey ->
        KeyPair(
            secretKey = secretKey,
            publicKey = secretKey.toPublicKey(),
        )
    }

// endregion