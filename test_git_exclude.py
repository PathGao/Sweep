# init must keep .sweep/ out of git inside a worktree. sweep.py needs tree-sitter, so run with graphify's python:
#   "$(head -1 "$(which graphify)" | cut -c3-)" test_git_exclude.py
import os, subprocess, tempfile
import sweep

def git(*a, cwd):
    return subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True, text=True).stdout

with tempfile.TemporaryDirectory() as d:
    main, wt = os.path.join(d, "main"), os.path.join(d, "wt")
    os.mkdir(main)
    git("init", "-q", cwd=main)
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x", cwd=main)
    git("worktree", "add", "-q", wt, cwd=main)
    os.makedirs(os.path.join(wt, ".sweep"))
    open(os.path.join(wt, ".sweep", "db"), "w").close()
    sweep.git_exclude(wt)
    out = git("status", "--porcelain", "--untracked-files=all", cwd=wt)
    assert ".sweep/" not in out, out
    sweep.git_exclude(d)  # not a repo: no-op, no crash
print("ok")
