package dev.sublab.sr25519

/**
 * An interface for verifying the signature and public key
 */
interface Verifier {
    /**
     * Verify public key and signature
     * @param t signing transcript
     * @param signature signature to verify
     */
    fun verify(t: SigningTranscript, signature: Signature): Boolean
    /**
     *  Verify a signature by this public key on a message.
     *  @return A [Boolean] value indicating whether the verification was successful
     */
    fun verifySimple(context: ByteArray, message: ByteArray, signature: Signature): Boolean
}