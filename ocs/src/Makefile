#
# Copyright 2025 Morse Micro
# SPDX-License-Identifier: GPL-3.0-or-later
#
APP=ocs

LDFLAGS?=-lnl-3 -lnl-genl-3

ODIR=build

_OBJ = ocs.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c
	mkdir $(ODIR) -p
	$(CC) -c -o $@ $< $(CFLAGS)

$(APP): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	rm -rf $(ODIR) $(APP)
