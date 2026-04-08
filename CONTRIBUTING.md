# Contributing to Dvorah 🐝

First off, thank you for considering contributing to Dvorah! It’s people like you who make Dvorah a better tool for the Kubernetes community.

Dvorah follows the **"Precision Scalpel"** philosophy: we aim to be a lightweight, high-performance, and focused security tool. We value simplicity, speed, and security over feature bloat.

## 🏗️ Getting Started
Prerequisites
To build and test Dvorah, you will need:
- **Go** (1.24+ recommended)
- **Task** (see [Taskfile.dev](https://taskfile.dev/) for installation)
- **Docker** (for container builds)
- **Kind** for local testing [link](https://kind.sigs.k8s.io/)
- **Golangci-lint** linting [link](https://github.com/golangci/golangci-lint)
- **GoSec** security scan [link](https://github.com/securego/gosec) 
- **ctlptl** creating kind and local registry [link](https://github.com/tilt-dev/ctlptl).

### Fork and Clone
  1. **Fork** the repository on GitHub.
  2. Clone your fork locally:

```Bash
git clone https://github.com/YOUR_USERNAME/dvorah.git
cd dvorah
```

  3. Add the original repository as a remote:

```Bash
git remote add upstream https://github.com/betorvs/dvorah.git
```

### Local Development
We use task to automate our workflow. Here are the most common commands:

Go tidy to download all required packages:

```Bash
task tidy
```

Run end-to-end tests:

```Bash
task dvorah-e2e-test
```

Run golangci-lint and security scan (gosec):

```Bash
task lint
task sec
```

Build and test it locally with Kind

```Bash
task dev-create
task dvorah-deploy
```

Run `task dvorah-deploy` everytime you need to apply a new image to your local Kind cluster. Use `task dev-delete` to delete your local development environment.

Other options:
- `task dvorah-logs`: to get local logs from Kind cluster.
- `task dvorah-test-cosign`: to test using local Bee command from dvorah container in Kind cluster.


### 🛠️ Development Workflow
1. Create a Branch
Always create a new branch for your work:

```Bash
git checkout -b feat/my-awesome-feature
# or
git checkout -b fix/issue-description
```

2. Coding Standards

- Security First: Dvorah is a security tool. Always run task lint before committing to ensure no security regressions are introduced.
- Be Concise: Follow the "Scalpel" philosophy. If a feature adds significant complexity or weight, let's discuss it in an issue first.
- Tests: Ensure that your changes are covered by unit tests.

3. Commit Messages
Keep them descriptive and use the imperative mood (e.g., `feat: add support for OCI auth` instead of `Added some auth things`).

## 🚀 Submitting a Pull Request

1. **Sync with Upstream**: Before submitting, make sure your branch is up to date:

```Bash
git fetch upstream
git rebase upstream/main
```
2. **Push to your Fork**:

```Bash
git push origin your-branch-name
```

3. **Open a PR**: Go to the Dvorah GitHub page and you should see a prompt to open a Pull Request.

4. **Use the Template**: Fill out the PR template completely so we can review your changes efficiently.

## ❓ Need Help?

If you have questions, feel free to open an Issue with the question label. We are happy to help!