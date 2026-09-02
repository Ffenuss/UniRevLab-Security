package org.unirevlab.testtarget;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public final class LabReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent == null ? "<none>" : intent.getAction();
        boolean integrity = SecuritySurfaces.localIntegrityGate(context);
        Log.d("UniRevLabTestTarget", "receiver action=" + action + " integrity=" + integrity);
    }
}
