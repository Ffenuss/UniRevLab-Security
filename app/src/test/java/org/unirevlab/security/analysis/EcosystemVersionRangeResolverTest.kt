package org.unirevlab.security.analysis

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EcosystemVersionRangeResolverTest {
    @Test fun npmSemverSafeSubset() {
        assertTrue(EcosystemVersionRangeResolver.evaluate("NPM", "1.5.0", ">= 1.2.0, < 2.0.0")!!.matches)
        assertFalse(EcosystemVersionRangeResolver.evaluate("NPM", "2.0.0", ">= 1.2.0, < 2.0.0")!!.matches)
        assertNull(EcosystemVersionRangeResolver.evaluate("NPM", "1.5.0", "^1.2.0"))
    }

    @Test fun nugetPrereleaseOrderIsSemverCompatible() {
        assertTrue(EcosystemVersionRangeResolver.evaluate("NUGET", "3.1.0-beta.2", ">= 3.1.0-beta.1, < 3.1.0")!!.matches)
    }

    @Test fun mavenRejectsUnknownQualifierInsteadOfGuessing() {
        assertTrue(EcosystemVersionRangeResolver.evaluate("MAVEN", "4.12.0", ">= 4.0.0, < 4.12.1")!!.matches)
        assertNull(EcosystemVersionRangeResolver.evaluate("MAVEN", "1.0.Final", ">= 1.0, < 2.0"))
    }
}
