alias b := build
alias c := clean

default:
    @just --list

build:
    python3 extract_syscall_numbers.py
    gcc -o sys_trace sys_tracer.c -Wall -Werror

clean:
    rm sys_trace
