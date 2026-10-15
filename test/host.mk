# PC build of the signing code (Linux, gcc). From the test/ folder:
#   ./smoke.sh            — quick check with random keys (what CI runs)
#   make -f host.mk       — cwtool, cwsim, test_hotcold; needs secrets.h in the
#                           project root (keys of your test wallet)
#   ./test_hotcold        — signs monero-wallet-gui files and compares with the
#                           GUI's own: ../../gui/{o,tx1,tx2,tx1_signed,tx2_signed}
#   ./cwsim pty.txt &     — device simulator on a pseudo-terminal, then
#   python3 ../tools/mwlink/mwlink.py --serial $(cat pty.txt) info
FW  := ..
SRC := $(FW)/cw_crypto.c $(FW)/cw_sal.c $(FW)/cw_carrot.c $(FW)/cw_hotcold.c $(FW)/x25519.c \
       $(FW)/crypto-ops.c $(FW)/crypto-ops-data.c $(FW)/keccak.c $(FW)/blake2b.c $(FW)/chacha20.c \
       $(FW)/slow-hash.c $(FW)/aesb.c $(FW)/oaes_lib.c $(FW)/blake256.c $(FW)/groestl.c $(FW)/jh.c \
       $(FW)/skein.c $(FW)/hash-extra-blake.c $(FW)/hash-extra-groestl.c $(FW)/hash-extra-jh.c \
       $(FW)/hash-extra-skein.c $(FW)/hash.c
CFLAGS := -O2 -w -Ihost -I$(FW)

all: cwtool cwsim test_hotcold

cwtool: cwtool.c host_store.c platform_host.c $(SRC)
	gcc $(CFLAGS) -o $@ $^
test_hotcold: test_hotcold.c host_store.c platform_host.c $(SRC)
	gcc $(CFLAGS) -o $@ $^
cwsim: cwsim.c $(FW)/cw_link.c platform_host.c $(SRC)
	gcc $(CFLAGS) -o $@ $^ -lutil -lpthread

clean:
	rm -f cwtool cwsim test_hotcold
.PHONY: all clean
