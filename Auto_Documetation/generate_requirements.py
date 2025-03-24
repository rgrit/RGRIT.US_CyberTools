import os
import ast
import sys
import importlib.util

try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    from importlib_metadata import version, PackageNotFoundError  # for Python <3.8

STANDARD_LIBS = set(sys.builtin_module_names)

def is_standard_module(module_name):
    if module_name in STANDARD_LIBS:
        return True
    try:
        spec = importlib.util.find_spec(module_name)
        if spec is None or spec.origin is None:
            return False
        return "site-packages" not in spec.origin and "dist-packages" not in spec.origin
    except Exception:
        return False

def find_imports_in_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        try:
            tree = ast.parse(f.read(), filename=file_path)
        except SyntaxError:
            return set()
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split('.')[0])
    return imports

def scan_repository(repo_path):
    all_imports = set()
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("venv", "env", "__pycache__")]
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                imports = find_imports_in_file(full_path)
                all_imports.update(imports)
    return all_imports

def filter_third_party(imports, repo_path):
    local_dirs = {name for name in os.listdir(repo_path)
                  if os.path.isdir(os.path.join(repo_path, name)) and not name.startswith('__')}
    return {pkg for pkg in imports if not is_standard_module(pkg) and pkg not in local_dirs}

def get_installed_version(pkg_name):
    try:
        return f"{pkg_name}=={version(pkg_name)}"
    except PackageNotFoundError:
        return pkg_name

def write_requirements_txt(packages, output_path="requirements.txt"):
    with open(output_path, "w") as f:
        for pkg in sorted(packages):
            f.write(get_installed_version(pkg) + "\n")
    print(f"[✓] requirements.txt created with {len(packages)} packages.")

if __name__ == "__main__":
    # 👇 CHANGE THIS TO YOUR PROJECT PATH IF NEEDED
    repo_dir = os.path.abspath(r"C:\Users\RGRIT\PycharmProjects\RGRIT.US_CyberTools")  # e.g., os.path.abspath("C:/Users/you/Projects/my-repo")

    all_imports = scan_repository(repo_dir)
    third_party = filter_third_party(all_imports, repo_dir)
    write_requirements_txt(third_party)
