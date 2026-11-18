#!/usr/bin/env bash
# Instalación de DockerHard sin crear un venv manualmente (Linux/macOS).
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v python3 >/dev/null 2>&1; then
  echo 'ERROR: se requiere Python 3 y pip.' >&2; exit 1
fi
python3 -m pip --version >/dev/null 2>&1 || { echo 'ERROR: instale python3-pip.' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo 'ERROR: se requiere curl para instalar Trivy.' >&2; exit 1; }
mkdir -p "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"

# Trivy es un binario externo: pip/requirements.txt no puede instalarlo.
if ! command -v trivy >/dev/null 2>&1; then
  echo 'Instalando Trivy con el instalador oficial de Aqua Security...'
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT
  curl --fail --location --silent --show-error \
    'https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh' \
    --output "$tmpdir/trivy-install.sh"
  # El instalador se descarga antes de ejecutarse; revisar su procedencia antes de usarlo.
  bash "$tmpdir/trivy-install.sh" -b "$HOME/.local/bin"
else
  echo "Trivy ya instalado: $(command -v trivy)"
fi

# PEP 668 en Debian/Kali bloquea pip global. Se instala en el directorio del usuario.
pip_args=(--user)
if python3 - <<'PY'
import pathlib, sysconfig
p = pathlib.Path(sysconfig.get_path('stdlib')) / 'EXTERNALLY-MANAGED'
raise SystemExit(0 if p.exists() else 1)
PY
then
  echo 'Python gestionado por el sistema (PEP 668): habilitando instalación de usuario.'
  pip_args+=(--break-system-packages)
fi

echo 'Instalando dependencias Python...'
python3 -m pip install "${pip_args[@]}" -r requirements.txt

echo 'Instalando comando dockerhard...'
python3 -m pip install "${pip_args[@]}" --no-deps .

if ! command -v dockerhard >/dev/null 2>&1; then
  echo 'ATENCIÓN: añada ~/.local/bin al PATH y abra otra terminal:'
  echo '  export PATH="$HOME/.local/bin:$PATH"'
  exit 1
fi

echo 'Verificando instalación...'
trivy --version
dockerhard --help
printf '\nInstalación completada. Comando disponible: dockerhard scan --help\n'
