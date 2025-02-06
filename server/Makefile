.PHONY : default_target
default_target : all

LIBS :=
OPTIONS:= -g -Wall
C_SRCS:= main.c

OBJS := $(subst .cpp,.o,$(C_SRCS))
OBJS := $(subst .c,.o,$(OBJS))



CXX:=$(CROSS_COMPILE)g++
AS:=$(CROSS_COMPILE)gcc
CC:=$(CROSS_COMPILE)gcc
LD:=$(CC)

all : aesdsocket

./aesdsocket : $(OBJS)
	@echo   $(TYPE)LD        $@
	$(CC) -o aesdsocket $(OPTIONS)     $(OBJS) $(LIBS) 



./%.o : %.c
	@echo   $(TYPE)CC        $<	
	$(CC) -c  $(OPTIONS)  -o $@ $<

clean : 
	-@echo   CLEAN     
	-$(RM) *.o *.d *.elf *.map aesdsocket


