package dev.sublab.sr25519

sealed class SignatureError: Exception() {
    class BytesLengthError(
        val name: String,
        val description: String,
        val size: Int
    ): SignatureError()

    class EquationFalse: SignatureError()
}