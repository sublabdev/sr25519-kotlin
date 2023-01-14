package dev.sublab.sr25519

/**
 * An interface for signing
 */
interface Signer {
    /**
     * Sign a message with a signing transcript
     * @param t signing transcript
     * @return A signature
     */
    fun sign(t: SigningTranscript): Signature

    /**
     * Sign a message with a signing transcript but double check
     * @param t signing transcript
     * @return A signature
     */
    fun signDoubleCheck(t: SigningTranscript): Signature

    /**
     * Sign a message with a context
     * @param context provided signing context
     * @param message message to sign
     * @return A signature
     */
    fun signSimple(context: ByteArray, message: ByteArray): Signature

    /**
     * Sign a message with a context but double check
     * @param context provided signing context
     * @param message message to sign
     * @return A signature
     */
    fun signSimpleDoubleCheck(context: ByteArray, message: ByteArray): Signature
}