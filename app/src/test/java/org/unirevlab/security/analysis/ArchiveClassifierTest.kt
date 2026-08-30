package org.unirevlab.security.analysis

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ArchiveClassifierTest {
    @Test fun detectsTraversalAndAbsolutePaths() {
        assertTrue(ArchiveClassifier.isSuspiciousPath("../escape"))
        assertTrue(ArchiveClassifier.isSuspiciousPath("a/../../escape"))
        assertTrue(ArchiveClassifier.isSuspiciousPath("/absolute"))
        assertTrue(ArchiveClassifier.isSuspiciousPath("\\absolute"))
        assertFalse(ArchiveClassifier.isSuspiciousPath("lib/arm64-v8a/libsafe.so"))
    }

    @Test fun classifiesDexAndNativeLibraries() {
        assertTrue(ArchiveClassifier.isDex("classes2.dex"))
        assertTrue(ArchiveClassifier.isNativeLibrary("lib/arm64-v8a/libexample.so"))
        assertTrue(ArchiveClassifier.isNativeLibrary("assets/libexample.so"))
        assertFalse(ArchiveClassifier.isStandardNativeLibraryPath("assets/libexample.so"))
        assertTrue(ArchiveClassifier.isStandardNativeLibraryPath("lib/arm64-v8a/libexample.so"))
    }
}
