#!/bin/sh

set -eu

runtime_file="${HOME}/.vscode/silmaril-firewall-node-path"
if [ ! -f "${runtime_file}" ] || [ -L "${runtime_file}" ]; then
  printf '%s\n' '{}'
  exit 0
fi

runtime_metadata=$(/usr/bin/stat -f '%u %Lp' "${runtime_file}" 2>/dev/null || true)
if [ "${runtime_metadata}" != "$(/usr/bin/id -u) 600" ]; then
  printf '%s\n' '{}'
  exit 0
fi

node_path=$(/usr/bin/head -n 1 "${runtime_file}")
if [ -z "${node_path}" ] || [ "${node_path#/}" = "${node_path}" ] \
  || [ ! -f "${node_path}" ] || [ -L "${node_path}" ] || [ ! -x "${node_path}" ]; then
  printf '%s\n' '{}'
  exit 0
fi

node_owner=$(/usr/bin/stat -f '%u' "${node_path}" 2>/dev/null || true)
node_mode=$(/usr/bin/stat -f '%Lp' "${node_path}" 2>/dev/null || true)
case "${node_owner}" in
  0|"$(/usr/bin/id -u)") ;;
  *)
    printf '%s\n' '{}'
    exit 0
    ;;
esac
case "${node_mode}" in
  500|555|700|711|744|755) ;;
  *)
    printf '%s\n' '{}'
    exit 0
    ;;
esac

exec "${node_path}" "${PLUGIN_ROOT}/dist/vscode-hook.js" "${1:-}"
