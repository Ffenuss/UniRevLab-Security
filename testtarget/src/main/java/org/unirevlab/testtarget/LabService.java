package org.unirevlab.testtarget;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public final class LabService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        boolean premium = SecuritySurfaces.isPremiumUnlocked(this);
        Log.d("UniRevLabTestTarget", "exported service premium=" + premium);
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
