#!/usr/bin/env python3
"""Decrypt ledger.pdf with the recovered password and extract the stamp.

Password: "paperwork" (rockyou.txt line 1,410,300)
PDF:       /V 4, /R 4, /CFM /AESV2 (AES-128-CBC), /P -1028

Usage: python3 decrypt_and_extract.py [path/to/ledger.pdf]
Without an argument the PDF is read straight out of the handout zip.
"""
import io
import sys
import zipfile

import pikepdf
from PIL import Image

ZIP = "../The_Locked_Ledger_Challenge.zip"
PDF = sys.argv[1] if len(sys.argv) > 1 else None
PASSWORD = "paperwork"
OUT = "stamp_from_pdf.png"


def main() -> None:
    if PDF is None:
        with zipfile.ZipFile(ZIP) as z:
            data = z.read("ledger.pdf")
        src = io.BytesIO(data)
    else:
        src = PDF

    with pikepdf.open(src, password=PASSWORD) as pdf:
        print("password accepted:", PASSWORD)
        print("pages:", len(pdf.pages))
        print("docinfo:", dict(pdf.docinfo))

        page = pdf.pages[0]
        print("\n--- decrypted page content stream ---")
        print(page.Contents.read_bytes().decode("latin-1"))

        # The verification stamp is the only image XObject on the page.
        xo = page.Resources.XObject
        key = next(k for k in xo.keys() if str(k).startswith("/FormXob"))
        img = xo[key]
        w, h = int(img.Width), int(img.Height)
        rgb = img.read_bytes()                 # DeviceRGB, 8 bpc
        mask = img.SMask.read_bytes()          # DeviceGray alpha

        colour = Image.frombytes("RGB", (w, h), rgb).convert("RGBA")
        colour.putalpha(Image.frombytes("L", (int(img.SMask.Width), int(img.SMask.Height)), mask))
        flat = Image.alpha_composite(Image.new("RGBA", (w, h), (255, 255, 255, 255)), colour)
        flat.convert("RGB").save(OUT)
        print(f"\nstamp image extracted -> {OUT} ({w}x{h})")


if __name__ == "__main__":
    main()
