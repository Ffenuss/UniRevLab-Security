from pathlib import Path


def test_evidence_service_checks_cancel_during_rodroid_workspace_cleanup():
    source = Path("android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java").read_text(encoding="utf-8")

    assert 'check();deleteTree(app.file("rodroid"));' in source
    assert 'private void deleteTree(File file)throws IOException{' in source
    assert 'if(file==null||!file.exists())return;check();' in source
    assert '}check();if(!file.delete()&&file.exists())' in source
    assert 'private static void deleteTree(File file)' not in source
