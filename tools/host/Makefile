# Хостовая сборка прошивочного кода подписи (Linux, gcc).
FW  := ../..
SRC := main.c \
       $(FW)/sign_tx.c $(FW)/sign_tx_construct.c $(FW)/rct_sig_construct.c \
       $(FW)/clsag.c $(FW)/bp_plus.c $(FW)/unsigned_tx_set.c $(FW)/monero_crypto.c \
       $(FW)/chacha20.c $(FW)/epee_reader.c $(FW)/tx_parser.c \
       $(FW)/crypto-ops.c $(FW)/crypto-ops-data.c $(FW)/keccak.c $(FW)/hash.c \
       $(FW)/slow-hash.c $(FW)/aesb.c $(FW)/oaes_lib.c \
       $(FW)/blake256.c $(FW)/groestl.c $(FW)/jh.c $(FW)/skein.c \
       $(FW)/hash-extra-blake.c $(FW)/hash-extra-groestl.c \
       $(FW)/hash-extra-jh.c $(FW)/hash-extra-skein.c

signer: $(SRC)
	gcc -O2 -w -I. -I$(FW) -o $@ $(SRC)

clean:
	rm -f signer
.PHONY: clean
