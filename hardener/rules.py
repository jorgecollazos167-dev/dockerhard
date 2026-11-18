RULES = [
    {
        "id": "D01_USER_ROOT",
        "owasp": "D01 - Secure User Mapping",
        "severity": "CRITICAL",
        "description": "El Dockerfile define explícitamente USER root.",
        "recommendation": "Crear un usuario no privilegiado y ejecutar el contenedor con USER <usuario>.",
        "check": lambda lines: any(
            line.strip().lower() in ["user root", "user 0"]
            for line in lines
        )
    },
    {
        "id": "D01_MISSING_NON_ROOT_USER",
        "owasp": "D01 - Secure User Mapping",
        "severity": "HIGH",
        "description": "No se define un usuario no privilegiado en el Dockerfile.",
        "recommendation": "Agregar RUN useradd/adduser y posteriormente USER <usuario>.",
        "check": lambda lines: not any(
            line.strip().lower().startswith("user ")
            for line in lines
        )
    },
    {
        "id": "D02_BASE_IMAGE_LATEST",
        "owasp": "D02 - Patch Management Strategy",
        "severity": "HIGH",
        "description": "La imagen base usa la etiqueta latest.",
        "recommendation": "Usar una versión explícita de imagen base, por ejemplo ubuntu:22.04 o python:3.11-slim.",
        "check": lambda lines: any(
            line.strip().lower().startswith("from ")
            and ":latest" in line.strip().lower()
            for line in lines
        )
    },
    {
        "id": "D03_EXPOSE_SENSITIVE_PORT",
        "owasp": "D03 - Network Segmentation and Firewalling",
        "severity": "HIGH",
        "description": "El Dockerfile expone puertos sensibles o administrativos.",
        "recommendation": "Evitar exponer puertos como 22, 2375, 2376 o interfaces de administración.",
        "check": lambda lines: any(
            line.strip().lower().startswith("expose ")
            and any(port in line for port in ["22", "2375", "2376"])
            for line in lines
        )
    },
    {
        "id": "D04_ADD_USED_INSTEAD_COPY",
        "owasp": "D04 - Secure Defaults and Hardening",
        "severity": "MEDIUM",
        "description": "Se usa ADD en lugar de COPY.",
        "recommendation": "Usar COPY salvo que se requiera específicamente la funcionalidad adicional de ADD.",
        "check": lambda lines: any(
            line.strip().lower().startswith("add ")
            for line in lines
        )
    },
    {
        "id": "D04_SUDO_INSTALLED_OR_USED",
        "owasp": "D04 - Secure Defaults and Hardening",
        "severity": "MEDIUM",
        "description": "Se detectó uso o instalación de sudo.",
        "recommendation": "Evitar sudo dentro del contenedor y ejecutar solo los comandos necesarios durante build.",
        "check": lambda lines: any(
            "sudo" in line.strip().lower()
            for line in lines
        )
    },
    {
        "id": "D04_APT_CACHE_NOT_CLEANED",
        "owasp": "D04 - Secure Defaults and Hardening",
        "severity": "MEDIUM",
        "description": "Se instalan paquetes sin limpiar la caché de apt.",
        "recommendation": "Agregar rm -rf /var/lib/apt/lists/* en la misma instrucción RUN.",
        "check": lambda lines: any(
            "apt install" in line.lower() or "apt-get install" in line.lower()
            for line in lines
        ) and not any(
            "rm -rf /var/lib/apt/lists" in line.lower()
            for line in lines
        )
    },
    {
        "id": "D04_NO_INSTALL_RECOMMENDS_MISSING",
        "owasp": "D04 - Secure Defaults and Hardening",
        "severity": "LOW",
        "description": "Se instalan paquetes sin --no-install-recommends.",
        "recommendation": "Usar --no-install-recommends para reducir paquetes innecesarios y superficie de ataque.",
        "check": lambda lines: any(
            "apt install" in line.lower() or "apt-get install" in line.lower()
            for line in lines
        ) and not any(
            "--no-install-recommends" in line.lower()
            for line in lines
        )
    },
    {
        "id": "D06_HARDCODED_SECRET",
        "owasp": "D06 - Protect Secrets",
        "severity": "CRITICAL",
        "description": "Se detectan posibles secretos embebidos en el Dockerfile.",
        "recommendation": "No incluir passwords, tokens, claves privadas o credenciales en el Dockerfile. Usar gestores de secretos.",
        "check": lambda lines: any(
            keyword in line.lower()
            for line in lines
            for keyword in ["password=", "passwd=", "token=", "secret=", "apikey=", "api_key=", "private_key"]
        )
    },

    {
    "id": "NON_MINIMAL_BASE_IMAGE",
    "source": "OWASP Docker Security Cheat Sheet",
    "severity": "LOW",
    "description": "La imagen base no parece minimalista.",
    "recommendation": "Considerar imágenes minimalistas como alpine, slim o distroless para reducir superficie de ataque.",
    "check": lambda lines: any(
        line.lower().startswith("from ubuntu")
        or line.lower().startswith("from debian")
        for line in lines
    )
    },
    {
        "id": "UNNECESSARY_PACKAGES",
        "source": "OWASP Docker Security Cheat Sheet",
        "severity": "MEDIUM",
        "description": "Se detectan herramientas potencialmente innecesarias dentro del contenedor.",
        "recommendation": "Evitar instalar herramientas administrativas o de debugging como vim, nano, telnet o netcat.",
        "check": lambda lines: any(
            any(pkg in line.lower() for pkg in [
                "vim", "nano", "telnet", "netcat", "nmap", "ftp"
            ])
            for line in lines
        )
    },

    {
        "id": "INTERACTIVE_SHELL_EXECUTION",
        "source": "OWASP Docker Security Cheat Sheet",
        "severity": "MEDIUM",
        "description": "El contenedor inicia una shell interactiva.",
        "recommendation": "Evitar CMD bash/sh salvo que sea estrictamente necesario.",
        "check": lambda lines: any(
            'cmd ["bash"]' in line.lower()
            or 'cmd ["sh"]' in line.lower()
            for line in lines
        )
    },

    {
        "id": "MULTIPLE_EXPOSED_PORTS",
        "source": "OWASP Docker Security Cheat Sheet",
        "severity": "LOW",
        "description": "El Dockerfile expone múltiples puertos.",
        "recommendation": "Exponer únicamente los puertos estrictamente necesarios.",
        "check": lambda lines: sum(
            1 for line in lines
            if line.lower().startswith("expose ")
        ) > 1
    },

    {
        "id": "REMOTE_BINARY_DOWNLOAD",
        "source": "OWASP Docker Security Cheat Sheet",
        "severity": "HIGH",
        "description": "Se detecta descarga remota de contenido durante el build.",
        "recommendation": "Validar integridad/hash de binarios descargados o usar repositorios confiables.",
        "check": lambda lines: any(
            "curl " in line.lower()
            or "wget " in line.lower()
            for line in lines
        )
    },
    {
        "id": "MISSING_HEALTHCHECK",
        "source": "OWASP Docker Security Cheat Sheet",
        "severity": "LOW",
        "description": "No se define HEALTHCHECK en el Dockerfile.",
        "recommendation": "Definir HEALTHCHECK para facilitar monitoreo y recuperación.",
        "check": lambda lines: not any(
            line.lower().startswith("healthcheck")
            for line in lines
        )
    },
    {
    "id": "NIST_IMAGE_SSH_DAEMON",
    "source": "NIST SP 800-190 - Image configuration defects",
    "severity": "HIGH",
    "description": "La imagen instala o ejecuta un servicio SSH dentro del contenedor.",
    "recommendation": "Evitar incluir SSH daemon en imágenes de aplicación. El contenedor debe ejecutar solo el proceso necesario.",
    "check": lambda lines: any(
        "openssh-server" in line.lower()
        or "sshd" in line.lower()
        for line in lines
    )
    },
    {
        "id": "NIST_EMBEDDED_CLEAR_TEXT_SECRET",
        "source": "NIST SP 800-190 - Embedded clear text secrets",
        "severity": "CRITICAL",
        "description": "Se detectan posibles secretos embebidos en el Dockerfile.",
        "recommendation": "No incluir credenciales, connection strings, llaves SSH o certificados privados en la imagen. Usar secretos externos inyectados en runtime.",
        "check": lambda lines: any(
            keyword in line.lower()
            for line in lines
            for keyword in [
                "password=", "passwd=", "token=", "secret=",
                "api_key=", "apikey=", "private_key",
                "connection_string", "ssh_private_key",
                "-----begin rsa private key-----",
                "-----begin private key-----"
            ]
        )
    },
    {
        "id": "NIST_REMOTE_DOWNLOAD_WITHOUT_VALIDATION",
        "source": "NIST SP 800-190 - Embedded malware / untrusted images",
        "severity": "HIGH",
        "description": "Se descargan archivos remotos durante el build sin validación evidente de integridad.",
        "recommendation": "Validar descargas con hash, firma o repositorios confiables antes de incorporarlas a la imagen.",
        "check": lambda lines: any(
            ("curl " in line.lower() or "wget " in line.lower())
            for line in lines
        ) and not any(
            "sha256sum" in line.lower()
            or "gpg" in line.lower()
            or "cosign" in line.lower()
            for line in lines
        )
    },
    {
        "id": "NIST_MUTABLE_IMAGE_TAG",
        "source": "NIST SP 800-190 - Stale images / immutable names",
        "severity": "HIGH",
        "description": "La imagen base usa una etiqueta mutable o poco específica.",
        "recommendation": "Usar etiquetas explícitas y, preferiblemente, digest SHA256 para garantizar trazabilidad e integridad.",
        "check": lambda lines: any(
            line.lower().strip().startswith("from ")
            and (
                ":latest" in line.lower()
                or ":" not in line.split()[1]
            )
            for line in lines
        )
    },

    {
    "id": "NIST_UNTRUSTED_BASE_IMAGE",
    "source": "NIST SP 800-190 - Use of untrusted images",
    "severity": "MEDIUM",
    "description": "La imagen base no parece provenir de un registro interno, oficial o controlado.",
    "recommendation": "Mantener un conjunto de imágenes base confiables y aprobadas; preferir imágenes oficiales, firmadas o de registro interno.",
    "check": lambda lines: any(
        line.lower().strip().startswith("from ")
        and not any(
            trusted in line.lower()
            for trusted in [
                "ubuntu",
                "debian",
                "alpine",
                "python",
                "node",
                "nginx",
                "gcr.io/distroless"
            ]
        )
        for line in lines
    )
}





]