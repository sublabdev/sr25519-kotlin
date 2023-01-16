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