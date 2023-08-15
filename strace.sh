strace -e trace=process,write,read,open,close -o strace_output.txt python buggy.py
