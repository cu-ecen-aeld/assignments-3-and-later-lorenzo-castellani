.PHONY : default_target
default_target : all

LIBS :=
OPTIONS:= -g -Wall
C_SRCS:= writer.c

OBJS := $(subst .c,.o,$(C_SRCS))


CXX:=$(CROSS_COMPILE)g++
AS:=$(CROSS_COMPILE)gcc
CC:=$(CROSS_COMPILE)gcc
LD:=$(CC)

all : writer

./writer : $(OBJS)
	@echo   $(TYPE)LD        $@
	$(CC) -o writer $(OPTIONS)     $(OBJS) $(LIBS) 



./%.o : %.c
	@echo   $(TYPE)CC        $<	
	$(CC) -c  $(OPTIONS)  -o $@ $<

clean : 
	-@echo   CLEAN     
	-$(RM) *.o *.d *.elf *.map writer


