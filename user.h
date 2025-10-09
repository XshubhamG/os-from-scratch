#pragma once
#include "common.h"

void putchar(char ch);
int getchar(void);
__attribute__((noreturn)) void exit(void);
__attribute__((section(".text.start"))) __attribute__((naked)) void start(void);
