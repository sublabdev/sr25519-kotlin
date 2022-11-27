package dev.sublab.sr25519

interface Verifier {
    fun verify(t: SigningTranscript, signature: Signature): Boolean
    fun verifySimple(context: ByteArray, message: ByteArray, signature: Signature): Boolean
}