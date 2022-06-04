/*
 * Copyright 2022 Baris Basturk
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.realbarisbasturk.sha256;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

/**
 * Pure Java implementation of SHA-256 hashing algorithm.
 */
public final class Sha256 {

    //region Constants

    private static final int BLOCK_SIZE_IN_BITS = 512;
    private static final int BLOCK_SIZE_IN_BYTES = 512 / Byte.SIZE;
    private static final int WORD_SIZE = 64;

    // ROUND CONSTANTS
    private static final int[] K = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
            0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
            0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
            0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
            0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
            0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb,
            0xbef9a3f7, 0xc67178f2};

    private static final int H0 = 0x6a09e667;
    private static final int H1 = 0xbb67ae85;
    private static final int H2 = 0x3c6ef372;
    private static final int H3 = 0xa54ff53a;
    private static final int H4 = 0x510e527f;
    private static final int H5 = 0x9b05688c;
    private static final int H6 = 0x1f83d9ab;
    private static final int H7 = 0x5be0cd19;

    private static final byte SINGLE_BIT_ONE_IN_BYTE = (byte) 0b10000000;

    //endregion

    /**
     * Hashes the input using SHA-256.
     *
     * @param input input
     * @return hash
     */
    public byte[] hash(final byte[] input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }

        final int[] hash = new int[]{H0, H1, H2, H3, H4, H5, H6, H7};
        final int[] temp = new int[8];
        final int[] words = new int[WORD_SIZE];
        final int[] blockWords = pad(input);

        final long numberOfBlocks = ((long) blockWords.length * Integer.BYTES) / BLOCK_SIZE_IN_BYTES;
        for (int blockIndex = 0; blockIndex < numberOfBlocks; ++blockIndex) {
            initializeWords(words, blockWords, blockIndex);
            System.arraycopy(hash, 0, temp, 0, hash.length);
            compressionLoop(words, temp);
            updateIntermediateHash(hash, temp);
        }

        return toByteArray(hash);
    }

    /**
     * Initialize words from the given block words and block index.
     *
     * @param words      words to initialize
     * @param blockWords all block words
     * @param blockIndex block index
     */
    private void initializeWords(final int[] words, final int[] blockWords, final int blockIndex) {
        System.arraycopy(blockWords, blockIndex * 16, words, 0, 16);
        for (int i = 16; i < words.length; ++i) {
            words[i] = smallSigma1(words[i - 2]) + words[i - 7] + smallSigma0(words[i - 15]) + words[i - 16];
        }
    }

    /**
     * Compression loop that operates on words using temporary int array.
     *
     * @param words words
     * @param temp  temporary int array
     */
    private void compressionLoop(final int[] words, final int[] temp) {
        for (int i = 0; i < words.length; ++i) {
            final int temp1 = temp[7] + bigSigma1(temp[4]) + choice(temp[4], temp[5], temp[6]) + K[i] + words[i];
            final int temp2 = bigSigma0(temp[0]) + majority(temp[0], temp[1], temp[2]);
            //noinspection SuspiciousSystemArraycopy
            System.arraycopy(temp, 0, temp, 1, temp.length - 1);
            temp[4] += temp1;
            temp[0] = temp1 + temp2;
        }
    }

    /**
     * Copies the value stored in temporary int array to hash array.
     *
     * @param hash hash array
     * @param temp temporary int array
     */
    private void updateIntermediateHash(final int[] hash, final int[] temp) {
        for (int i = 0; i < hash.length; ++i) {
            hash[i] += temp[i];
        }
    }

    //region Padding

    /**
     * Pad the input to multiple of {@link #BLOCK_SIZE_IN_BITS}.
     *
     * @param input input
     * @return padded input
     */
    private int[] pad(final byte[] input) {
        final long inputSizeInBits = calculateInputSizeInBits(input);
        final long numberOfBlocks = calculateNumberOfRequiredBlocks(inputSizeInBits);
        final int paddedInputBufferSize = (int) ((numberOfBlocks * BLOCK_SIZE_IN_BYTES) / Integer.BYTES);
        final IntBuffer paddedInputBuffer = IntBuffer.allocate(paddedInputBufferSize);

        // Copy input to the padded input buffer as much as possible
        // Since default byte value is 0, padding the rest explicitly is not necessary
        final ByteBuffer inputBuffer = ByteBuffer.wrap(input).asReadOnlyBuffer();
        final int inputSizeInIntSize = input.length / Integer.BYTES;
        copyInputToPaddedInputBuffer(inputBuffer, inputSizeInIntSize, paddedInputBuffer);
        addRemainingWithSingleBit(inputBuffer, paddedInputBuffer);

        addInputLength(paddedInputBuffer, inputSizeInBits);

        return paddedInputBuffer.array();
    }

    /**
     * Copies the input to the padded input buffer as much as possible. Remaining bytes (less than 4) will be handled
     * with {@link  #addRemainingWithSingleBit(ByteBuffer, IntBuffer)}.
     *
     * @param inputBuffer       input buffer
     * @param paddedInputBuffer added input buffer
     */
    private void copyInputToPaddedInputBuffer(final ByteBuffer inputBuffer,
                                              final int inputSizeInIntSize,
                                              final IntBuffer paddedInputBuffer) {
        for (int i = 0; i < inputSizeInIntSize; ++i) {
            paddedInputBuffer.put(inputBuffer.getInt());
        }
    }

    /**
     * Adds the remaining bytes not copied to the padded input buffer and appends {@link #SINGLE_BIT_ONE_IN_BYTE}.
     *
     * @param inputBuffer       input buffer
     * @param paddedInputBuffer padded input buffer
     */
    private void addRemainingWithSingleBit(final ByteBuffer inputBuffer, final IntBuffer paddedInputBuffer) {
        final ByteBuffer remainingBytes = ByteBuffer.allocate(Integer.BYTES);
        remainingBytes.put(inputBuffer); // less than Integer.Bytes
        remainingBytes.put(SINGLE_BIT_ONE_IN_BYTE);
        remainingBytes.rewind();
        paddedInputBuffer.put(remainingBytes.getInt());
    }

    /**
     * Adds message length in bits as 64-bit integer.
     *
     * @param paddedInputBuffer padded input buffer
     * @param inputSizeInBits   input size in bits
     */
    private void addInputLength(final IntBuffer paddedInputBuffer, final long inputSizeInBits) {
        paddedInputBuffer.position(paddedInputBuffer.capacity() - 2); // 2 int (32-bit) required
        paddedInputBuffer.put((int) (inputSizeInBits >>> 32)); // first part
        paddedInputBuffer.put((int) inputSizeInBits); // second part
    }

    /**
     * Calculates number of blocks required.
     *
     * @return number of blocks required
     */
    private static long calculateNumberOfRequiredBlocks(final long inputSizeInBits) {
        final long inputSizeWithoutPaddingInBits = inputSizeInBits + 1L + 64L;
        final long numberOfZeroPaddingBits;
        if (inputSizeWithoutPaddingInBits < BLOCK_SIZE_IN_BITS) {
            numberOfZeroPaddingBits = BLOCK_SIZE_IN_BITS - inputSizeInBits;
        } else {
            final long remainderBits = inputSizeWithoutPaddingInBits % BLOCK_SIZE_IN_BITS;
            numberOfZeroPaddingBits = remainderBits == 0L ? 0L : BLOCK_SIZE_IN_BITS - remainderBits;
        }

        return (inputSizeWithoutPaddingInBits + numberOfZeroPaddingBits) / BLOCK_SIZE_IN_BITS;
    }

    /**
     * @param input input
     * @return input size in bits
     */
    private static long calculateInputSizeInBits(final byte[] input) {
        return ((long) input.length * Byte.SIZE);
    }

    //endregion

    //region Logical Methods

    private static int bigSigma0(final int x) {
        return Integer.rotateRight(x, 2) ^ Integer.rotateRight(x, 13) ^ Integer.rotateRight(x, 22);
    }

    private static int bigSigma1(final int x) {
        return Integer.rotateRight(x, 6) ^ Integer.rotateRight(x, 11) ^ Integer.rotateRight(x, 25);
    }

    private static int smallSigma0(final int x) {
        return Integer.rotateRight(x, 7) ^ Integer.rotateRight(x, 18) ^ (x >>> 3);
    }

    private static int smallSigma1(final int x) {
        return Integer.rotateRight(x, 17) ^ Integer.rotateRight(x, 19) ^ (x >>> 10);
    }

    private static int choice(final int x, final int y, final int z) {
        return (x & y) | ((~x) & z);
    }

    private static int majority(final int x, final int y, final int z) {
        return (x & y) | (x & z) | (y & z);
    }

    //endregion

    //region Utility Methods

    /**
     * Converts the given int[] into byte[].
     *
     * @param input input
     * @return input as byte array
     */
    private static byte[] toByteArray(final int[] input) {
        final ByteBuffer byteBuffer = ByteBuffer.allocate(input.length * Integer.BYTES);
        for (final int i : input) {
            byteBuffer.putInt(i);
        }

        return byteBuffer.array();
    }

    //endregion

}
