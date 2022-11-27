package dev.sublab.sr25519

interface Signer {
    fun sign(t: SigningTranscript): Signature
    fun signDoubleCheck(t: SigningTranscript): Signature
    fun signSimple(context: ByteArray, message: ByteArray): Signature
    fun signSimpleDoubleCheck(context: ByteArray, message: ByteArray): Signature
}