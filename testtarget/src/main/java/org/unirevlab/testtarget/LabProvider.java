package org.unirevlab.testtarget;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;

public final class LabProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"name", "value"});
        boolean premium = getContext() != null && SecuritySurfaces.isPremiumUnlocked(getContext());
        cursor.addRow(new Object[]{"fixture_premium", premium ? "1" : "0"});
        cursor.addRow(new Object[]{"fixture_endpoint", SecuritySurfaces.FIXTURE_HTTP_ENDPOINT});
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        return "vnd.android.cursor.item/vnd.unirevlab.fixture";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
