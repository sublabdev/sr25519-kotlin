package dev.sublab.sr25519

/**
 * Schnorr signing context
 *
 * We expect users to have separate `SigningContext`s for each role
 * that signature play in their protocol.
 *
 * To sign a message, apply the appropriate inherent method to create
 * a signature transcript.
 *
 * You should use `merlin::Transcript`s directly if you must do
 * anything more complex, like use signatures in larger zero-knowledge
 * protocols or sign several components but only reveal one later.
 */
class SigningContext(private val transcript: SigningTranscript) {
    constructor(label: ByteArray): this(SigningTranscript(label))

    companion object {
        /**
         * Initialize a signing context from a static byte string
         * that identifies the signature's role in the larger protocol.
         */
        @Throws(Exception::class)
        fun fromContext(context: ByteArray): SigningContext {
            val t = SigningTranscript("SigningContext".toByteArray())
            t.appendMessage("".toByteArray(), context)
            return SigningContext(t)
        }
    }

    /**
     * Initialize an owned signing transcript on a message provided as a byte array.
     * @param bytes a [ByteArray] (message) used to create an owned signing transcript
     * @return signing transcript
     *
     * Avoid this method when processing large slices because it calls `Transcript.appendMessage` directly
     * and `merlin` is designed for domain separation, not performance.
     */
    @Throws(Exception::class)
    fun bytes(bytes: ByteArray): SigningTranscript {
        val t = transcript.clone()
        t.appendMessage("sign-bytes".toByteArray(), bytes)
        return t
    }
}