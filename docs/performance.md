# Performance notes

The multi-target paths build a deletion-free digest index and confirm hits with
full digest comparisons. Batched compression processes independent candidates
in parallel; map records are buffered. These changes do not alter the digest
or map formats. Hash tables can still have long probe chains in the worst case.

The following are illustrative local measurements, not performance promises.
They compare the parent commit `faf1a02` with this branch, on a two-logical-CPU
Intel Xeon 2.60 GHz Linux sandbox with AVX2 and AVX-512, using GCC optimized
builds. Numbers are median wall time of three runs, including process startup,
with outputs discarded. Automatic CPU selection was used. Both brute and
wordlist miss tests exhaust their inputs; the 1,024 targets are MD5 digests of
`unmatched-0` through `unmatched-1023` and are absent from the test spaces.
The wordlist contained one million numeric lines. Map writes included file I/O;
search read an existing 254 MiB map. Cache and host load affect results.

| Workload | Parent | This branch |
| --- | ---: | ---: |
| Brute MD5, digits through length 7, 1 thread | 0.803 s | 0.402 s |
| Brute SHA-256, digits through length 7, 1 thread | 4.005 s | 0.602 s |
| Brute MD5, 1,024 misses, digits through length 6, 2 threads | 1.603 s | 0.203 s |
| Wordlist MD5, 1 million lines, 1 miss, 2 threads | 0.051 s | 0.052 s |
| Wordlist MD5, 1 million lines, 1,024 misses, 2 threads | 1.594 s | 0.066 s |
| Map MD5, digits through length 6, 1 thread | 0.202 s | 0.203 s |
| Search, one MD5 in a 254 MiB map | 0.512 s | 0.509 s |

Short engine runs include the existing progress-monitor timing granularity, so
small timings are particularly sensitive to that overhead. SHA-NI and GPU
execution were not used; see [CPU and accelerator detection](cpu.md).
