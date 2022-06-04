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


import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public final class Sha256Test {

    private static final String RESOURCE_DIRECTORY_RANDOM_FILES = "random.org-pregenerated-2022-05-bin";
    private static final String EXTENSION_RANDOM_FILE = ".bin";
    private static final String ALGORITHM_SHA256 = "SHA-256";
    private static final String ALGORITHM_SHA512 = "SHA-512";
    private static final int SEED_TEST_RANDOM = 123456789;


    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    final class RandomInputs {

        Stream<Arguments> provideArguments() {
            final IntStream stream = IntStream.range(0, 32);
            return stream.map(i -> {
                if (i < 31) {
                    return 1 << i;
                } else {
                    return (1 << i) - 8; // https://stackoverflow.com/a/31382608/14771468
                }
            }).mapToObj(Arguments::of);
        }

        @ParameterizedTest(name = "Given a random input with size {0}, " +
                "when hashed with sha-256, " +
                "then output hash should match the expected")
        @MethodSource("provideArguments")
        @Execution(ExecutionMode.CONCURRENT)
        void testRandomInput(final int inputSize) {
            final Sha256 sha256 = new Sha256();
            final Random random = new Random(SEED_TEST_RANDOM);
            final byte[] input = new byte[inputSize];
            random.nextBytes(input);
            assertArrayEquals(sha256.hash(input), hash(ALGORITHM_SHA256, input));
        }

    }

    @DisplayName("Given random input files, " +
            "when hashed with sha-512, " +
            "then output hash should not match the expected")
    @Test
    void testSha256WithRandomInputFilesIncorrectAlgorithm() {
        final List<File> files = getInputFiles();
        final Sha256 sha256 = new Sha256();
        for (final File file : files) {
            try {
                final byte[] input = Files.readAllBytes(file.toPath());
                final byte[] hash = hash(ALGORITHM_SHA512, input);
                assertFalse(Arrays.equals(hash, sha256.hash(input)));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @DisplayName("Given a random input file, " +
            "when hashed with sha-256, " +
            "then output hash should match the expected")
    @Test
    void testSha256WithRandomInputFiles() {
        final List<File> files = getInputFiles();
        final Sha256 sha256 = new Sha256();
        for (final File file : files) {
            try {
                final MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_SHA256);
                final byte[] input = Files.readAllBytes(file.toPath());
                final byte[] hash = messageDigest.digest(input);
                assertArrayEquals(hash, sha256.hash(input));
            } catch (NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @DisplayName("Given random input files, " +
            "when hashed with sha-512 in a multithreaded environment, " +
            "then output hash should not match the expected")
    @Test
    void testSha256WithRandomInputFilesIncorrectAlgorithmMultithreading() {
        final List<File> files = getInputFiles();
        final Sha256 sha256 = new Sha256();
        final List<Callable<Boolean>> hashComputations = new ArrayList<>(files.size());
        for (final File file : files) {
            hashComputations.add(new HashFileCallable(sha256, file, ALGORITHM_SHA512));
        }
        final ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

        try {
            final List<Future<Boolean>> results = executor.invokeAll(hashComputations);
            assertNotNull(results);
            for (Future<Boolean> result : results) {
                assertFalse(result.get());
            }
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    @DisplayName("Given random input files, " +
            "when hashed with sha-256 in a multithreaded environment, " +
            "then output hash should match the expected")
    @Test
    void testSha256WithRandomInputFilesMultithreading() {
        final List<File> files = getInputFiles();
        final Sha256 sha256 = new Sha256();
        final List<Callable<Boolean>> hashComputations = new ArrayList<>(files.size());
        for (final File file : files) {
            hashComputations.add(new HashFileCallable(sha256, file, ALGORITHM_SHA256));
        }
        final ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

        try {
            final List<Future<Boolean>> results = executor.invokeAll(hashComputations);
            assertNotNull(results);
            for (Future<Boolean> result : results) {
                assertTrue(result.get());
            }
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        }
    }


    private static class HashFileCallable implements Callable<Boolean> {

        private final Sha256 sha256;
        private final File file;
        private final String algorithm;

        HashFileCallable(final Sha256 sha256, final File file, final String algorithm) {
            this.sha256 = sha256;
            this.file = file;
            this.algorithm = algorithm;
        }

        @Override
        public Boolean call() {
            try {
                final MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
                final byte[] input = Files.readAllBytes(file.toPath());
                final byte[] hash = messageDigest.digest(input);
                return Arrays.equals(hash, sha256.hash(input));
            } catch (NoSuchAlgorithmException | IOException e) {
                return false;
            }
        }

    }

    private List<File> getInputFiles() {
        final File[] files = getResourceDirectory().listFiles();
        Objects.requireNonNull(files);
        final List<File> inputFiles = new ArrayList<>(files.length);
        for (final File file : files) {
            if (file.isFile() && file.getName().endsWith(EXTENSION_RANDOM_FILE)) {
                inputFiles.add(file);
            }
        }

        return inputFiles;
    }

    private File getResourceDirectory() {
        final URL resourceDirectoryUrl = getClass().getClassLoader().getResource(RESOURCE_DIRECTORY_RANDOM_FILES);
        Objects.requireNonNull(resourceDirectoryUrl);
        return new File(resourceDirectoryUrl.getFile());
    }

    private static byte[] hash(final String algorithm, final byte[] input) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            return messageDigest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
