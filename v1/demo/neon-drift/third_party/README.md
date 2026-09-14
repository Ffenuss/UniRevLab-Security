Vendor here:

* `imgui/`  — https://github.com/ocornut/imgui (docking branch is fine)
* `dobby/`   — https://github.com/jmp03/Dobby, enables MODKIT_HAVE_DOBBY

Both are optional: without imgui the loader console drives the module, without
dobby the built-in arm64 inline hooker is used and refuses PC-relative prologues.
