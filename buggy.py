import os

def divide(a, b):
    return a / b

def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()

numerator = 10
denominator = 2

result = divide(numerator, denominator)
print("Division result:", result)

filename = 'data.txt'
file_content = read_file(filename)
print("File content:", file_content)

print("Process ID:", os.getpid())
