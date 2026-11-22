# CPU and accelerator detection

Run `hashmap cpu` to print the processor identity, CPU features, selected
batched MD5 and SHA-256 kernels, and a best-effort Linux accelerator report.
The logical processor count is the system online count, which can exceed a
process affinity limit.
`src/cpu.c` owns detection and runtime selection; `src/accelerator.c` inspects
visible accelerator devices. The standard build does not use `-march=native`,
so optional x86 SIMD kernels are selected at runtime rather than assumed for
the build machine.

## CPU kernels

On supported x86 builds, CPUID detects the features; AVX, AVX2 and AVX-512
selection also checks that the operating system enables the necessary register
state. The implementation uses 16-way AVX-512, 8-way AVX2, or the four-way
baseline. Other architectures use the baseline. Detected **SHA-NI** is shown
separately: there is currently no SHA-NI kernel, so it is not used for hashing.
Other listed features are informational, not a promise that a corresponding
optimized implementation exists.

When both AVX2 and AVX-512 are available in automatic mode, a short startup
microbenchmark compares both kernels independently for MD5 and SHA-256. The
16-way kernel is selected only if it measures at least 25% higher throughput;
otherwise the 8-way kernel is used. This conservative threshold is a heuristic,
not a guarantee of the best choice for every workload, and the results can vary
with load or frequency scaling. The decision is cached once per process and is
used by the batched compression functions.

| Environment variable | Effect |
| --- | --- |
| unset `HM_CPU` | Automatically detect and, where applicable, benchmark kernels. |
| `HM_CPU=off` or `HM_CPU=baseline` | Disable optional AVX2 and AVX-512 kernels. |
| `HM_CPU=avx2` | Cap selection at AVX2; fall back if unavailable. |
| `HM_CPU=avx512` | Prefer AVX-512, falling back to AVX2 or baseline if unavailable. Skip autotuning. |
| `HM_CPU_VERBOSE=1` | Print selection and timing details to stderr. |

The controls select among implemented vector kernels; they cannot turn on an
unsupported CPU/OS instruction or enable an unimplemented SHA-NI backend.
Unrecognized `HM_CPU` values use automatic selection. `hashmap cpu` shows the
actual choices, which can differ for MD5 and SHA-256.

## Non-CPU devices

On Linux the report counts DRM cards in `/sys/class/drm`, DRM render nodes in
`/dev/dri`, NVIDIA device nodes in `/dev`, and checks for `/dev/kfd`. An
unreadable directory is shown as `unknown`. Device visibility depends on
permissions, drivers, containers and device passthrough; these checks do not
prove a GPU is usable or detect every accelerator. Non-Linux systems report
that this detection is unsupported. **There is no GPU or other accelerator
hashing backend in this version**: all work runs on the CPU, even if a device
is visible. No CUDA/OpenCL driver or SDK is required.
