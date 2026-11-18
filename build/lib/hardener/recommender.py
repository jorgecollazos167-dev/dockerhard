def generate_vulnerability_recommendation(vuln: dict) -> str:
    package = vuln.get("PkgName", "N/A")
    severity = vuln.get("Severity", "UNKNOWN")
    fixed_version = vuln.get("FixedVersion", "")

    base = []

    if fixed_version:
        base.append(
            f"Actualizar el paquete '{package}' a la versión corregida {fixed_version}."
        )
    else:
        base.append(
            f"No se reporta versión corregida para '{package}'. Evaluar actualización de imagen base o cambio a una imagen más reciente/minimalista."
        )

    package_recommendations = {
        "bash": "Evitar shells innecesarias en imágenes de producción y preferir imágenes minimalistas. Esto reduce superficie de ataque.",
        "apt": "Reconstruir la imagen con repositorios actualizados y limpiar caché de paquetes durante el build.",
        "openssl": "Actualizar librerías criptográficas con prioridad alta, ya que pueden afectar comunicaciones seguras.",
        "glibc": "Actualizar la imagen base, debido a que glibc suele depender directamente del sistema operativo base.",
        "libc6": "Actualizar la imagen base o migrar a una variante slim/alpine cuando sea compatible.",
        "curl": "Evitar herramientas de descarga en imágenes finales; usar multi-stage build si se requieren durante construcción.",
        "wget": "Evitar herramientas de descarga en imágenes finales; validar integridad de archivos descargados.",
        "pip": "Actualizar dependencias Python y usar versiones fijadas en requirements.txt.",
        "setuptools": "Actualizar dependencias Python y fijar versiones seguras.",
    }

    if package in package_recommendations:
        base.append(package_recommendations[package])

    if severity in ["CRITICAL", "HIGH"]:
        base.append(
            "Priorizar esta corrección en el ciclo inmediato de hardening."
        )
    elif severity == "MEDIUM":
        base.append(
            "Programar corrección en el siguiente ciclo de mejora de la imagen."
        )
    else:
        base.append(
            "Monitorear y corregir durante mantenimiento regular."
        )

    base.append(
        "Base: NIST SP 800-190 recomienda gestionar vulnerabilidades en imágenes; OWASP/CIS recomiendan imágenes mínimas, reducción de superficie de ataque y actualización continua."
    )

    return " ".join(base)