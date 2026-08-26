#!/bin/sh

set -eu

runtime_file="${HOME}/.vscode/silmaril-firewall-node-path"
if [ ! -f "${runtime_file}" ]; then
  printf '%s\n' '{}'
  exit 0
fi

node_path=$(/usr/bin/head -n 1 "${runtime_file}")
if [ -z "${node_path}" ] || [ ! -x "${node_path}" ]; then
  printf '%s\n' '{}'
  exit 0
fi

exec "${node_path}" "${PLUGIN_ROOT}/dist/vscode-hook.js" "${1:-}"

