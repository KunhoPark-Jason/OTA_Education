import os
import hashlib

def create_hash_file(file_path, output_dir):
    # Ensure the file exists
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return

    # Compute the SHA-256 hash of the file
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Write the hash to a new file
    base_name = os.path.basename(file_path)
    hash_file_path = os.path.join(output_dir, f"{base_name}.hash")
    with open(hash_file_path, 'w') as hash_file:
        hash_file.write(file_hash)

    print(f"Hash file created: {hash_file_path}")

# Example usage
if __name__ == "__main__":
    input_file = input("Enter the file path: ").strip()
    output_directory = input("Enter the output directory: ").strip()
    create_hash_file(input_file, output_directory)
