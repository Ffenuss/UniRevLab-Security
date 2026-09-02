package org.unirevlab.security.ui

import org.unirevlab.security.model.CrossRuntimeCorrelationSummary

internal val CrossRuntimeCorrelationSummary.links: List<Any>
    get() = buildList {
        addAll(jniNative)
        addAll(il2cppRegistrations)
        addAll(il2cppMethods)
    }
