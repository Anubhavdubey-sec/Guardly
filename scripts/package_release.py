#!/usr/bin/env python3
"""
PhishGuard Enterprise Release Packaging Utility
Produces a clean, production-ready release ZIP containing only tracked git files.
Excludes .env, .venv/, .git/, __pycache__/, and tmp/ artifacts.
"""

import os
import sys
import subprocess
import zipfile


def check_git_safety():
    """Verify that sensitive configuration files are not tracked by git."""
    try:
        res = subprocess.run(
            ["git", "ls-files", "--error-unmatch", ".env"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if res.returncode == 0:
            print("CRITICAL SECURITY ERROR: '.env' is currently tracked by git!")
            print("Run 'git rm --cached .env' before packaging for distribution.")
            sys.exit(1)
    except FileNotFoundError:
        print("ERROR: git executable not found in PATH.")
        sys.exit(1)


def build_release_archive():
    check_git_safety()

    dist_dir = os.path.abspath("dist")
    os.makedirs(dist_dir, exist_ok=True)
    zip_path = os.path.join(dist_dir, "Phishing-Email-Detector.zip")

    print("[*] Creating release archive using git archive...")
    cmd = ["git", "archive", "--format=zip", "--output", zip_path, "HEAD"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if res.returncode != 0:
        print(f"ERROR: Failed to create git archive: {res.stderr}")
        sys.exit(1)

    print(f"[+] Release archive created successfully at: {zip_path}\n")

    # Verify and inspect ZIP contents
    print("[*] Verifying release package contents:")
    violations = []

    with zipfile.ZipFile(zip_path, "r") as z:
        file_list = z.namelist()
        total_files = len(file_list)
        total_size = sum(info.file_size for info in z.infolist())

        for name in file_list:
            print(f"  - {name}")
            is_forbidden = False
            if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
                is_forbidden = True
            elif any(name.startswith(p) for p in (".venv/", ".git/", "__pycache__/", "tmp/")):
                is_forbidden = True

            if is_forbidden:
                violations.append(name)

    print(f"\n[+] Total Files Included: {total_files}")
    print(f"[+] Total Uncompressed Size: {total_size / (1024 * 1024):.2f} MB")

    if violations:
        print("\nCRITICAL ERROR: Found forbidden files in release package:")
        for v in violations:
            print(f"  [!] {v}")
        os.remove(zip_path)
        sys.exit(1)

    print("\n[SUCCESS] Release archive passes all security and distribution hygiene checks!")


if __name__ == "__main__":
    build_release_archive()
