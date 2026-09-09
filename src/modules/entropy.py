def calculate_entropy(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    from .analyze import calculate_entropy_bytes
    entropy = calculate_entropy_bytes(data)
    print(f"Entropy: {entropy}")