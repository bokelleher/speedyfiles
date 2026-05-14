# GitHub Actions workflows

These workflow files are staged here for users to copy into their own
`.github/workflows/` directory after cloning, **once your GitHub Personal
Access Token has the `workflow` scope**. (GitHub refuses to let a PAT
without that scope create or modify workflow files via the API or
`git push`.)

To enable CI in your fork:

```bash
mkdir -p .github/workflows
cp deploy/github-workflows/*.yml .github/workflows/
git add .github/workflows/
git commit -m "ci: enable GitHub Actions workflows"
git push
```

| File | Purpose |
|------|---------|
| `test.yml`   | Runs `pytest` across Python 3.12 + 3.13 |
| `lint.yml`   | `ruff check` + `ruff format --check` + `mypy` |
| `docker.yml` | Builds + pushes multi-arch image to GHCR on tag |
