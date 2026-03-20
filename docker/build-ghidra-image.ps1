# Build Ghidra server image. Uses host network so build can reach api.github.com
# and dl-cdn.alpinelinux.org from environments where container DNS fails.
Set-Location $PSScriptRoot\..
podman build --network host -f Dockerfile.ghidra -t ghidra-server .
