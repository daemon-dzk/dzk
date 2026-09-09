import hashlib

def hash_file(filepath, algo='sha256'):
    hash_func = getattr(hashlib, algo)()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    print(f"{algo.upper()}: {hash_func.hexdigest()}")