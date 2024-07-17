package dev.sublab.sr25519

import dev.sublab.hex.hex
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Tests taken from https://github.com/Warchant/sr25519-crust/blob/1c190bdf6fb523f3eb85c3dcff130bfc3b383e5b/test/derive.cpp
 */
class TestDerivation {

    private val knownKeyPair = "0x4c1250e05afcd79e74f6c035aee10248841090e009b6fd7ba6a98d5dc743250cafa4b32c608e3ee2ba624850b3f14c75841af84b16798bf1ee4a3875aa37a2cee661e416406384fe1ca091980958576d2bff7c461636e9f22c895f444905ea1f"
        .hex
        .decode()

    @Test
    internal fun testHard() {
        val cc = "0x14416c6963650000000000000000000000000000000000000000000000000000"
            .hex
            .decode()

        val expectedPublicKey = "0xd8db757f04521a940f0237c8a1e44dfbe0b3e39af929eb2e9e257ba61b9a0a1a"
            .hex
            .decode()

        val keyPair = KeyPair.fromByteArray(knownKeyPair)

        // Test direct derivation
        run {
            val derivationResult = keyPair.secretKey.deriveHard(cc)
            val derivedPublicKey = derivationResult.miniSecretKey.expandToPublic(ExpansionMode.ED25519)
            assertContentEquals(expectedPublicKey, derivedPublicKey.toByteArray())
        }

        // Test keypair derivation
        run {
            val derivedKeyPair = keyPair.deriveHard(cc, ExpansionMode.ED25519)
            assertContentEquals(expectedPublicKey, derivedKeyPair.publicKey.toByteArray())
        }
    }

    @Test
    internal fun testSimple() {
        val cc = "0c666f6f00000000000000000000000000000000000000000000000000000000"
            .hex
            .decode()

        val expectedPublicKey = "0xb21e5aabeeb35d6a1bf76226a6c65cd897016df09ef208243e59eed2401f5357"
            .hex
            .decode()

        val keyPair = KeyPair.fromByteArray(knownKeyPair)

        println("keypair nonce: ${keyPair.secretKey.nonce.copyOf().hex.encode()}")

        // Test direct derivation
        run {
            val derivationResult = keyPair.secretKey.deriveSimple(cc)
            println("Secret key size: ${derivationResult.secretKey.toByteArray().size}")
            val derivedPublicKey = derivationResult.secretKey.toPublicKey()
            assertContentEquals(expectedPublicKey, derivedPublicKey.toByteArray())
        }

        // Test keypair derivation
        run {
            val derivedKeyPair = keyPair.deriveSimple(cc)
            assertContentEquals(expectedPublicKey, derivedKeyPair.publicKey.toByteArray())
        }
    }
}