# Runtime profile signals

Runtime profiles are routing metadata, not security findings by themselves.

| Profile | Example passive indicators | Follow-up analyzer |
|---|---|---|
| UNITY_IL2CPP | `global-metadata.dat`, `libil2cpp.so`, validated metadata | IL2CPP + ELF/Ghidra worker |
| UNITY_MONO | Managed `.dll` files, `libmono*`, `libunity.so` | Managed assembly inventory |
| UNREAL_ENGINE | `libUE4.so`/`libUnreal.so`, packaged `.pak` assets | ELF + package inventory |
| FLUTTER | `libflutter.so`, `libapp.so`, `flutter_assets` | Flutter snapshot/assets inventory |
| REACT_NATIVE_HERMES | Hermes/native RN libraries or JS/HBC bundle | JS/Hermes inventory |
| XAMARIN_DOTNET | Mono/Xamarin native bridge or `assemblies/*.dll` | .NET assembly inventory |
| CORDOVA_WEBVIEW | `cordova.js` or Cordova Java classes | Web assets/WebView bridge review |

A profile must never be reported as a vulnerability merely because the technology is present.
