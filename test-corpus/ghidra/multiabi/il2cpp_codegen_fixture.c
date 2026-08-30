/* UniRevLab-owned benign structural IL2CPP fixture. No Android/runtime APIs are used. */
typedef unsigned int uint32_t;
typedef unsigned long uintptr_t;

typedef void (*MethodPointer)(void);

typedef struct {
    const char *moduleName;
    uint32_t methodPointerCount;
    MethodPointer *methodPointers;
} Il2CppCodeGenModuleFixture;

typedef struct {
    uint32_t codeGenModulesCount;
    Il2CppCodeGenModuleFixture **codeGenModules;
} Il2CppCodeRegistrationFixture;

__attribute__((visibility("default"), noinline)) void Managed_Method_One(void) { __asm__ volatile(""); }
__attribute__((visibility("default"), noinline)) void Managed_Method_Two(void) { __asm__ volatile(""); }

static MethodPointer method_pointers[] = { Managed_Method_One, Managed_Method_Two };
static Il2CppCodeGenModuleFixture assembly_csharp_module = {
    "Assembly-CSharp.dll", 2, method_pointers
};
static Il2CppCodeGenModuleFixture *codegen_modules[] = { &assembly_csharp_module };

__attribute__((used, visibility("default")))
Il2CppCodeRegistrationFixture g_CodeRegistration = { 1, codegen_modules };

__attribute__((used, visibility("default")))
uintptr_t g_MetadataRegistration[4] = { 1, 2, 3, 4 };

__attribute__((visibility("default"), noinline))
void il2cpp_codegen_register(void *code, void *metadata, void *options) {
    volatile uintptr_t sink = (uintptr_t)code ^ (uintptr_t)metadata ^ (uintptr_t)options;
    (void)sink;
}

__attribute__((visibility("default"), noinline))
void fixture_registration_call(void) {
    il2cpp_codegen_register(&g_CodeRegistration, &g_MetadataRegistration, 0);
}
