import ctypes
from ctypes.util import find_library
import sys

libc = ctypes.CDLL(find_library('c'), use_errno=True)
ptrace = ctypes.CDLL(find_library('ptrace'), use_errno=True)

# Constant definitions for syscalls
PTRACE_ATTACH = 0x4e5
PTRACE_DETACH = 0x4b7
PTRACE_PEEKTEXT = 0x10
PTRACE_POKETEXT = 0x11 #0x04 ??

def search_in_heap(proc_handle, search_str, replacement_str):
    """Search for the given search string within the process' heap memory."""
    found = False

    # Iterate over each page in the virtual memory space of the process
    cur_page = proc_handle[1]
    while True:
        start_addr = cur_page.contents.mr_start
        end_addr = start_addr + cur_page.contents.mr_size

        # Check if current page contains the search string
        ptr = ctypes.cast((start_addr), ctypes.POINTER(ctypes.c_char))
        data = str(ctypes.string_at(ptr, min(len(search_str), end_addr-start_addr)))
        if search_str in data:
            offset = data.index(search_str)

            new_addr = start_addr + offset

            replacement_bytes = replacement_str.encode('utf-8')

            # PTRACE_POKETEXT is a system call in Linux that's used to modify a word (4 bytes) 
            # of data in the memory of a traced process
            ptrace.syscall(PTRACE_POKETEXT, proc_handle[0], new_addr, ctypes.c_longlong(int.from_bytes(replacement_bytes, byteorder='little')))

            print(f"Replaced '{search_str}' with '{replacement_str}' at address: 0x{new_addr:08X}")

            found = True

        if end_addr >= proc_handle[0] + 0x1000:
            break  # Assuming the heap won't span over 4KB, adjust as needed

        cur_page = ctypes.cast(ctypes.c_ulonglong(cur_page.contents.mr_next), ctypes.POINTER(ctypes.c_ulonglong))

    if not found:
        print("Search string not found in the process heap.")


 
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: read_write_heap.py pid search_string replace_string")
        sys.exit(1)
    
pid = int(sys.argv[1])
search_string = sys.argv[2]
replace_string = sys.argv[3]
    
proc_handle = open_process(pid)
search_in_heap(proc_handle, search_string, replace_string)

# Detach from the process
ptrace.syscall(PTRACE_DETACH, pid, None, None)
