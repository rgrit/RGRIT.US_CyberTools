#!/usr/bin/env python3
import os

PROJECT_ROOT = "/home/administrator/PycharmProjects/RGRIT.US"  # Update this to your actual project path
EXCLUDED_DIRS = {".venv", "venv", ".git", "__pycache__"}  # add more if needed

def main():
    """
    1. Lists immediate subdirectories of PROJECT_ROOT -> considered 'level 2' dirs.
    2. For each level 2 directory, do a full recursive search for .py files (levels 3,4,5,...).
    3. Combine all .py contents into a single .txt in that level 2 directory.
    """

    # Step 1: Identify level-2 directories (the immediate children of PROJECT_ROOT)
    level2_dirs = []
    for item in os.listdir(PROJECT_ROOT):
        full_path = os.path.join(PROJECT_ROOT, item)
        if os.path.isdir(full_path):
            level2_dirs.append(full_path)

    # Step 2: For each level-2 directory, recursively find all .py
    for level2_dir in level2_dirs:
        # We'll create a single .txt file in the level2_dir
        dir_name = os.path.basename(level2_dir)
        output_filename = f"{dir_name}_python_files.txt"
        output_path = os.path.join(level2_dir, output_filename)

        print(f"\n[INFO] Processing level-2 directory: {level2_dir}")
        print(f"       Gathering all .py files (including deeper levels).")
        print(f"       Writing combined text to: {output_path}")

        # We'll open the output file once, write content from each .py
        with open(output_path, "w", encoding="utf-8") as out_file:
            # Step 2a: Recursively walk from this level-2 directory
            for root, dirs, files in os.walk(level2_dir):
                # Optionally skip excluded dirs
                dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

                for filename in files:
                    if filename.endswith(".py"):
                        py_path = os.path.join(root, filename)
                        # Read the content
                        try:
                            with open(py_path, "r", encoding="utf-8", errors="ignore") as f_in:
                                content = f_in.read()
                        except Exception as e:
                            content = f"[ERROR reading {py_path}: {e}]"

                        # Write a header, then the file content
                        out_file.write(f"===== Start of {os.path.relpath(py_path, level2_dir)} =====\n")
                        out_file.write(content)
                        out_file.write(f"\n===== End of {os.path.relpath(py_path, level2_dir)} =====\n\n")

        print(f"[INFO] Completed writing {output_path}")

if __name__ == "__main__":
    main()
