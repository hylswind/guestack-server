# Build inputs

> Everything the image build takes from outside this repository, and how each input is fixed.

The build runs in [`.github/workflows/build-image.yml`](../.github/workflows/build-image.yml). Its provenance names the commit, so every input fixed by that commit is covered by the attestation.

| Input | Fixed by |
|-------|----------|
| Go toolchain | `toolchain` line in [`go.mod`](../go.mod) |
| Go modules | [`go.sum`](../go.sum) |
| GitHub Actions | Full commit SHA in the workflow |
| Image description | The files in this directory, adapted from the example named in [`NOTICE`](NOTICE) |
| **Packages in the image** | **Not fixed.** The latest Amazon Linux 2023 release at build time, with RPM signature checks. The build log lists the exact versions |
| **Builder container, KIWI NG, and the NitroTPM tools used to build** | **Not fixed.** `amazonlinux:2023`, upgraded to the latest release at build time |
| **GitHub-hosted runner** | **Not fixed.** `ubuntu-24.04` names only the major version. GitHub updates the runner image weekly, so the host kernel and Docker can change between builds |

> [!NOTE]
> The build is not reproducible, and nothing here claims it is. Trust in an image comes from its [build provenance](../VERIFY.md).
