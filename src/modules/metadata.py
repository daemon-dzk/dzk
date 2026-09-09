import os
import time

def get_metadata(filepath):
    stats = os.stat(filepath)
    print(f"Metadata for: {filepath}")
    print(f"Size: {stats.st_size} bytes")
    print(f"Created: {time.ctime(stats.st_ctime)}")
    print(f"Modified: {time.ctime(stats.st_mtime)}")
    print(f"Permissions: {oct(stats.st_mode)}")