# DockerHard

Herramienta CLI de análisis de seguridad y hardening de Dockerfiles e imágenes Docker para proyectos de videojuegos Linux. Incluye análisis de configuraciones, escaneo con Trivy, cálculo de Hardening Score, enriquecimiento EPSS y exportación de hallazgos.

## Requisitos

- Linux (probado a nivel de empaquetado en entorno Debian; pensado para Kali/Ubuntu/Debian). macOS puede requerir ajustes.
- Python 3, `python3-pip`, `curl` y conexión a Internet durante la instalación.
- Docker instalado y operativo cuando se analicen imágenes locales o se construyan imágenes.
- Trivy: el instalador `install.sh` lo descarga si no está disponible.

## Instalación sencilla (sin crear un entorno virtual)

Después de clonar o descomprimir el proyecto:

```bash
cd DockerHard
bash install.sh
```

El instalador instala las dependencias de `requirements.txt`, instala el comando `dockerhard` e instala Trivy en `~/.local/bin` si falta. En Debian/Kali con PEP 668, utiliza una instalación Python de usuario con `--break-system-packages`: esto evita crear un venv, **pero puede interferir con paquetes Python gestionados por el sistema**. Si se desea evitarlo, usar un entorno virtual o pipx.

Si el comando no aparece al abrir una nueva terminal:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Para conservar el cambio, agregue esa línea a `~/.bashrc` o `~/.zshrc` según su shell.

**Seguridad:** el instalador descarga y ejecuta el instalador oficial de Trivy desde GitHub. Revise `install.sh` antes de ejecutarlo en equipos de producción. La descarga requiere acceso a GitHub. No se ha fijado una versión de Trivy.

## Comandos reales de esta versión

```bash
dockerhard --help
dockerhard scan --help
dockerhard compare --help
```

### Análisis estático de Dockerfile

```bash
dockerhard scan --file Dockerfile
dockerhard scan --file Dockerfile --output reports/dockerfile.xlsx
dockerhard scan --file Dockerfile --limit 20
```

### Análisis de imagen Docker

```bash
dockerhard scan --image mi-juego:latest
dockerhard scan --image mi-juego:latest --output reports/imagen.xlsx
dockerhard scan --image mi-juego:latest --limit 20
```

### Comparar resultados antes/después (IMH)

```bash
dockerhard compare --before reports/antes.xlsx --after reports/despues.xlsx
```

`scan` acepta `--file/-f`, `--image/-i`, `--output/-o` y `--limit/-l` (30 por defecto). El comando `compare` requiere `--before` y `--after`.

## Dependencias y limitaciones

- `requirements.txt` solo instala paquetes Python. **Trivy es un ejecutable externo** y se instala por separado mediante `install.sh`.
- El análisis de imágenes requiere que Trivy pueda acceder a la imagen, por ejemplo a través de Docker o un registro compatible.
- FIRST EPSS requiere acceso a la red para consultar datos de vulnerabilidades.
- El análisis de Dockerfiles combina reglas internas con el análisis de configuración de Trivy.
- El Hardening Score y el IMH son métricas diferentes: el primero pondera hallazgos y el segundo mide su reducción cuantitativa.
- La ejecución en otras plataformas no se ha verificado en esta entrega.

## Instalación manual alternativa

```bash
python3 -m pip install -r requirements.txt
python3 -m pip install --no-deps .
```

Esta opción presupone que Trivy está instalado y que Python permite la instalación. En Debian/Kali puede requerirse un venv o las opciones de instalación de usuario descritas en `install.sh`.

## Origen académico

DockerHard fue desarrollado como parte de una investigación sobre hardening de imágenes Docker para videojuegos en Linux. Consulte la documentación científica del proyecto para interpretar el alcance experimental de las métricas.
