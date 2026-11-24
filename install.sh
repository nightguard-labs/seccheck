#!/bin/sh
# seccheck installer: checks Docker + Ollama, builds the sandbox image, pulls the default checker model.
set -e
EDITION="${SECCHECK_EDITION:-lite}"; FAMILY="${SECCHECK_FAMILY:-qwen}"
command -v docker >/dev/null || { echo "Docker is required (Docker Desktop, OrbStack or Colima)."; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is installed but not running. Start it and re-run."; exit 1; }
command -v ollama >/dev/null || { echo "Ollama is required: https://ollama.com"; exit 1; }
cd "$(dirname "$0")"
echo "Building the sandbox image (no network, no privileges at run time)..."
docker build -q -t seccheck-sandbox:1 . >/dev/null
MODEL=$(SECCHECK_EDITION="$EDITION" SECCHECK_FAMILY="$FAMILY" ./seccheck --print-model)
echo "Pulling the checker model: $MODEL ($EDITION edition, $FAMILY family)"
ollama pull "$MODEL"
echo "Done. Try:  ./seccheck demo/task.txt demo        (finds 2 holes)"
echo "            ./seccheck demo-fixed/task.txt demo-fixed   (clean)"
echo "            ./seccheck demo/task.txt demo --fix  (writes a fix, keeps it only if it passes re-attack + still-works tests)"
