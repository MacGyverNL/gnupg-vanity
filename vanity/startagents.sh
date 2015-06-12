#!/bin/sh
../agent/gpg-agent --homedir=.gnupg1 --daemon --no-detach
../agent/gpg-agent --homedir=.gnupg2 --daemon --no-detach
../agent/gpg-agent --homedir=.gnupg3 --daemon --no-detach
../agent/gpg-agent --homedir=.gnupg4 --daemon --no-detach
