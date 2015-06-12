#!/usr/bin/sh
time ../g10/gpg2 --homedir=.gnupg1 --gen-key --batch batchparams &
time ../g10/gpg2 --homedir=.gnupg2 --gen-key --batch batchparams &
time ../g10/gpg2 --homedir=.gnupg3 --gen-key --batch batchparams &
time ../g10/gpg2 --homedir=.gnupg4 --gen-key --batch batchparams &
