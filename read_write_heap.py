#!/usr/bin/python3
"""
script that finds a string in the heap of a running process
and replaces it.
usage ./read_write_heap pid earch_string replace_string
"""

import sys
import ptrace.debugger

def get_process_maps(pid):
    maps = []
    with open(f"/proc/{pid}/maps", "r") as maps_file:
        for line in maps_file:
            maps.append(line.strip())
    return maps

def find_heap_bounds(maps):
    heap_start = None
    heap_end = None

    for entry in maps:
        if "[heap]" in entry: #better than endswith('')
            parts = entry.split()
            addr_range = parts[0]
            addr_start, addr_end = map(lambda x: int(x, 16), addr_range.split("-"))
            heap_start = addr_start
            heap_end = addr_end
            break

    return heap_start, heap_end

def read_process_memory(pid, address, size):
    process = ptrace.debugger.PtraceProcess(pid)
    data = process.read_bytes(address, size)
    process.detach()
    return data

def write_process_memory(pid, address, data):
    process = ptrace.debugger.PtraceProcess(pid)
    process.write_bytes(address, data)
    process.detach()

def find_and_replace_string(pid, search_string, replace_string):
    process = ptrace.debugger.PtraceProcess(pid)
    
    maps = get_process_maps(pid)
    heap_start, heap_end = find_heap_bounds(maps)
    
    if heap_start is None or heap_end is None:
        print("Could not determine heap boundaries.")
        sys.exit(1)
    
    current_address = heap_start
    while current_address < heap_end:
        data = process.read_bytes(current_address, len(search_string))
        if data == search_string.encode('utf-8'):
            print(f"Found match at address: 0x{current_address:08X}")
            write_process_memory(pid, current_address, replace_string.encode('utf-8'))
            break
        current_address += 1
    
    process.detach()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: read_write_heap.py pid search_string replace_string")
        sys.exit(1)
    
    pid = int(sys.argv[1])
    search_string = sys.argv[2]
    replace_string = sys.argv[3]
    
    find_and_replace_string(pid, search_string, replace_string)
