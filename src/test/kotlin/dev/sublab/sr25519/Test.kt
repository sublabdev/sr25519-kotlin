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

import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class Test {
    private val goodContext = "good".toByteArray()

    @Test
    internal fun test() {
        for (i in 0 until Constants.TESTS_COUNT) {
            val keyPair = KeyPair.generate()

            // Check restoring public key from byte array
            run {
                val restored = PublicKey.fromByteArray(keyPair.publicKey.toByteArray())
                assertContentEquals(keyPair.publicKey.toByteArray(), restored.toByteArray())
            }

            // Check restoring public key from Ristretto compressed
            run {
                val restored = PublicKey.fromCompressed(keyPair.publicKey.asCompressed())
                assertContentEquals(keyPair.publicKey.toByteArray(), restored.toByteArray())
            }

            // Check restoring secret key from byte array
            run {
                val restored = SecretKey.fromByteArray(keyPair.secretKey.toByteArray())
                assertContentEquals(keyPair.secretKey.toByteArray(), restored.toByteArray())
                assertContentEquals(keyPair.publicKey.toByteArray(), restored.toPublicKey().toByteArray())
            }

            // Check restoring secret key from ed25519 bytes
            run {
                val restored = SecretKey.fromEd25519ByteArray(keyPair.secretKey.toEd25519ByteArray())
                assertContentEquals(keyPair.secretKey.toByteArray(), restored.toByteArray())
                assertContentEquals(keyPair.publicKey.toByteArray(), restored.toPublicKey().toByteArray())
            }

            // Check restoring key pair from byte array
            run {
                val restored = KeyPair.fromByteArray(keyPair.toByteArray())
                assertContentEquals(keyPair.toByteArray(), restored.toByteArray())
                assertContentEquals(keyPair.secretKey.toByteArray(), restored.secretKey.toByteArray())
                assertContentEquals(keyPair.publicKey.toByteArray(), restored.publicKey.toByteArray())
            }

            // Check restoring key pair from ed25519 bytes
            run {
                val restored = KeyPair.fromEd25519ByteArray(keyPair.toEd25519ByteArray())
                assertContentEquals(keyPair.toByteArray(), restored.toByteArray())
                assertContentEquals(keyPair.secretKey.toByteArray(), restored.secretKey.toByteArray())
                assertContentEquals(keyPair.publicKey.toByteArray(), restored.publicKey.toByteArray())
            }

            for (j in 0 until Constants.TESTS_COUNT/10) {
                val message = UUID.randomUUID().toString().toByteArray()

                // Check simple signature
                val simpleSignature = keyPair.signSimple(goodContext, message)
                val simpleVerified = keyPair.verifySimple(goodContext, message, simpleSignature)
                assertEquals(true, simpleVerified)

                // Check simple double signature
                val simpleDoubleSignature = keyPair.signSimpleDoubleCheck(goodContext, message)
                val simpleDoubleVerified = keyPair.verifySimple(goodContext, message, simpleDoubleSignature)
                assertEquals(true, simpleDoubleVerified)

                fun transcript() = SigningContext(goodContext).bytes(message)

                // check regular signature
                val signature = keyPair.sign(transcript())
                val verified = keyPair.verify(transcript(), signature)
                assertEquals(true, verified)

                // check double signature
                val doubleSignature = keyPair.signDoubleCheck(transcript())
                val doubleVerified = keyPair.verify(transcript(), doubleSignature)
                assertEquals(true, doubleVerified)
            }
        }
    }
}