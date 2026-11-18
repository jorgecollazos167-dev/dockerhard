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

## Generación de gráficas desde reportes XLSX

DockerHard incluye un generador de gráficas en `hardener/charts.py`. **En esta versión no es un subcomando de `dockerhard`**; se ejecuta mediante `python3 -m hardener.charts` desde la carpeta raíz del proyecto, sin modificar el código. Los reportes de entrada deben ser archivos **`.xlsx`** compatibles con los exportados por DockerHard (no `.xls` antiguo).

### Gráficas del análisis estático (Dockerfile)

```bash
python3 -m hardener.charts static \
  --input reports/dockerfile.xlsx \
  --output-dir graficos/estatico
```

Genera `01_static_severity_distribution.png`, `02_static_sources.png` y `03_static_top_rules.png`.

### Gráficas del análisis dinámico (imagen Docker)

```bash
python3 -m hardener.charts dynamic \
  --input reports/imagen.xlsx \
  --output-dir graficos/dinamico
```

Genera `01_dynamic_severity_distribution.png`, `02_dynamic_top_packages.png` y `03_dynamic_top_risk_packages.png`.

### Gráficas comparativas antes y después del hardening

```bash
python3 -m hardener.charts compare \
  --before reports/antes.xlsx \
  --after reports/despues.xlsx \
  --case Aeroblasters \
  --output-dir graficos/comparacion
```

Genera `01_compare_severity_before_after.png`, `02_compare_reduction_by_severity.png` y `03_compare_imh.png`.

### Comparación numérica de dos reportes XLSX

```bash
dockerhard compare --before reports/antes.xlsx --after reports/despues.xlsx
```

Presenta en terminal hallazgos iniciales, finales, reducidos, IMH y nivel IMH. Esta opción **no genera gráficas**; utilice el modo `hardener.charts compare` para obtenerlas.

### Ayuda de los comandos

```bash
dockerhard --help
dockerhard scan --help
dockerhard compare --help
python3 -m hardener.charts --help
python3 -m hardener.charts static --help
python3 -m hardener.charts dynamic --help
python3 -m hardener.charts compare --help
```

**Nota de ejecución:** `python3 -m hardener.charts` requiere ejecutar el comando desde la raíz del repositorio, o tener el paquete instalado en el intérprete Python utilizado. Las dependencias gráficas `matplotlib` y `openpyxl` ya están declaradas en `requirements.txt`.

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

## Gráficos desde la CLI

La ayuda general `dockerhard --help` incluye `charts`. Para consultar las opciones disponibles:

```bash
dockerhard charts --help
dockerhard charts static --help
dockerhard charts dynamic --help
dockerhard charts compare --help
```

Generar gráficos estáticos a partir de un reporte XLSX:

```bash
dockerhard charts static --input reports/dockerfile.xlsx --output-dir graficos/estatico
```

Generar gráficos dinámicos de una imagen Docker:

```bash
dockerhard charts dynamic --input reports/imagen.xlsx --output-dir graficos/dinamico
```

Generar gráficos comparativos e IMH:

```bash
dockerhard charts compare --before reports/antes.xlsx --after reports/despues.xlsx --case Aeroblasters --output-dir graficos/comparacion
```

Los gráficos se guardan como archivos PNG. Los subcomandos reutilizan las funciones originales de `hardener/charts.py`.

**Después de actualizar el código**, si el proyecto se instaló sin modo editable, reinstalar desde la raíz mediante `python3 -m pip install .` o ejecutar de nuevo `bash install.sh`.
