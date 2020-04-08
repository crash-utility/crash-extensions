#
# Copyright (C) 2013 Alexandr Terekhov
# Copyright (C) 2013 EPAM Systems. All rights reserved.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 

all: fp.so

ifeq ($(shell arch), x86_64)
  TARGET=X86_64
  TARGET_CFLAGS=
endif

fp.so: fp.c
	gcc -Wall -I.. -shared -rdynamic -g -o fp.so fp.c -fPIC -D$(TARGET) -DGDB_7_6 $(TARGET_CFLAGS)

clean:
	rm -f x86_64_params.o fp.o fp.so

