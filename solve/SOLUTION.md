# The Locked Ledger — solution

**Flag: `tandav{th3_st4mp_s41d_1t_4ll}`**

## What is in the handout

`The_Locked_Ledger_Challenge.zip` contains:

| file | note |
|---|---|
| `ledger.pdf` | the locked ledger extract (1 page) |
| `pdfcrack.py` | the author's "helper" cracker |
| `crack_multi.py` | multiprocessing wrapper around it |
| `__pycache__/pdfcrack.cpython-313.pyc` | compiled copy of the same helper |

The PDF encryption dictionary:

```
/Filter /Standard /V 4 /R 4 /Length 128
/CF << /StdCF << /CFM /AESV2 /AuthEvent /DocOpen /Length 16 >> >>
/StmF /StdCF /StrF /StdCF
/O <278401...2a0b> /U <b39ad4...84c1> /P -1028
```

i.e. **AES-128-CBC (AESV2), R=4**, no empty user password.

## Step 1 — the handout cracker is broken

`pdfcrack.py` verifies the `/U` entry like this:

```python
enc = AES.new(key, AES.MODE_ECB).encrypt(md5(pad(b'') + ID))
return enc == U[:16]
```

That is wrong. For R = 2…4 the `/U` value is computed with **RC4**
(ISO 32000-1, Algorithm 5) even when the *streams* use AES (V=4). So the
script rejects every password, no matter the wordlist. Worse, for R ≥ 3 the
`/U` value is a 20-round RC4 chain, not a single RC4/AES pass:

```
1. x = MD5(PAD || ID)                                   # 16 bytes
2. x = RC4(filekey, x)
3. for i in 1..19:  x = RC4(filekey XOR i, x)
4. U = x || 16 arbitrary bytes
```

Correct implementation → [`pdf_crypt.py`](pdf_crypt.py) (Python) and
[`pdfcrack.c`](pdfcrack.c) (fast C version, ~37 k candidates/s/core; it also
supports the owner-password path, Algorithm 7).

Validation: encrypt a throwaway page with `pikepdf.Encryption(user='hunter2',
owner='ownerpw', R=4)` and confirm both user and owner checks fire. (qpdf's
`/U` padding even matches the challenge's trailing `00214469...84c1`, which
confirms the PDF was produced with qpdf/pikepdf after ReportLab rendering.)

## Step 2 — recover the password

Hints: *"the password is the same ordinary word I use for all my paperwork"*,
*"Sharma ji is not a complicated man"* → a plain dictionary word.

```
$ head -1000000 rockyou.txt > sample
$ ./pdfcrack sample                       # no hit in the first 1M
$ ./pdfcrack ry_part_00                   # halves of rockyou.txt, in parallel
$ ./pdfcrack ry_part_01
FOUND user password: paperwork (candidate 1410300)
```

**Password: `paperwork`**

## Step 3 — open the ledger and read the stamp

```
$ python3 decrypt_and_extract.py
password accepted: paperwork
docinfo: Author 'R. Sharma, Accounts', Title 'Ledger Extract FY 2025-26'
```

The decrypted page text is the ledger plus a note:

> Last year's code `tandav{0ld_c0d3_d0_n0t_us3}` stands cancelled and must not be used.

That one is a **decoy** — explicitly retired in the text. The real
verification is the rotated image XObject (`/FormXob.b4615ef4...`, 1572×798
DeviceRGB + DeviceGray SMask, object 7 + 11) placed at the bottom of the page:

> **TANDAV TRADERS — ACCOUNTS - VERIFIED**
> `tandav{th3_st4mp_s41d_1t_4ll}`
> ORIGINAL - DO NOT COPY

Extracted straight from the *decrypted* PDF stream:
[`stamp_from_pdf.png`](stamp_from_pdf.png).

## Reproduce

```bash
pip install pycryptodome pikepdf pillow
gcc -O3 -march=native -o pdfcrack pdfcrack.c
split -n l/2 -d rockyou.txt ry_part_ && (./pdfcrack ry_part_00 & ./pdfcrack ry_part_01 &)
python3 decrypt_and_extract.py            # reads ledger.pdf straight from the handout zip
```

## Flag

```
tandav{th3_st4mp_s41d_1t_4ll}
```
