# ARGOS Defense (resumen en español)

**Framework local de investigación defensiva para analizar de forma explicable actividad sospechosa, automatizada y asistida por LLM.**

> **Detección experimental; precisión en entornos reales no medida.** Toda la validación usa datos sintéticos.

ARGOS importa ficheros de telemetría que tú aportas (proxy, identidad, endpoint, red y auditoría de agentes de IA), los correlaciona por caso, aplica reglas declarativas y explica **qué apoya la evidencia y qué no**. Mantiene separadas seis dimensiones:

1. amenaza
2. automatización
3. implicación de un LLM
4. framework
5. propósito
6. entidades

Responde *desconocido* cuando los datos no permiten decidir. No identifica personas, grupos, nacionalidades ni modelos concretos. No bloquea, aísla ni escanea nada, y no envía datos fuera del equipo.

## Descarga (v0.2.0)
Página de la versión: https://github.com/CSTHUESP/argos-defense/releases/tag/v0.2.0 (repositorio privado: requiere una cuenta con acceso).

| Sistema | Fichero | Probado en |
|---|---|---|
| Windows 64 bits (Intel/AMD) | `ARGOS-Defense-0.2.0-windows-x86_64.zip` | runner `windows-2022` |
| Linux 64 bits (glibc ≥ 2.35) | `ARGOS-Defense-0.2.0-linux-x86_64.tar.gz` | runner `ubuntu-22.04` |
| Mac Apple Silicon | `ARGOS-Defense-0.2.0-macos-arm64.zip` | runner `macos-15` |
| Mac Intel | `ARGOS-Defense-0.2.0-macos-x86_64.zip` | runner `macos-15-intel` |

Los paquetes no necesitan Python instalado y funcionan sin conexión. Comprueba el hash con `SHA256SUMS`. Solo se han probado en esas imágenes de GitHub, no en Windows 10/11 de escritorio ni en otras versiones de macOS.

## Arranque
- **Windows:** descomprime y haz doble clic en `Start ARGOS Defense.cmd`. SmartScreen puede avisar porque no está firmado; comprueba antes el hash.
- **macOS:** descomprime y haz doble clic en `Start ARGOS Defense.command`. No está notarizado: si Gatekeeper lo bloquea, ve a *Ajustes del Sistema → Privacidad y seguridad → Abrir igualmente*.
- **Linux:** `tar xzf ARGOS-Defense-0.2.0-linux-x86_64.tar.gz && ./ARGOS-Defense-0.2.0-linux-x86_64/start-argos-defense.sh`

Se abre el navegador en `http://127.0.0.1:8789` (solo local) con la sesión iniciada. El token está en `<carpeta de datos>/.session_token` y no se imprime por defecto. Para parar, pulsa Ctrl+C o cierra la ventana.

## Demo sin datos privados
`argos-defense/argos-defense demo` crea el caso **demo-synthetic**, marcado como DEMO/SYNTHETIC.

## Flujo de trabajo
1. **Importar:** página *Import* o `ingest`.
2. **Analizar:** botón *Analyze* o `analyze`.
3. **Investigar:** cola de alertas, detalle, evidencias, entidades y notas.
4. **Exportar:** JSON, HTML o CSV.

## Datos y privacidad
Los datos se guardan en `%LOCALAPPDATA%\ARGOS Defense` (Windows), `~/Library/Application Support/ARGOS Defense` (macOS) o `~/.local/share/argos-defense` (Linux), o en la carpeta que indiques con `--data-dir`.

- **Copia de seguridad:** copia esa carpeta.
- **Desinstalar:** borra la carpeta del programa y, si quieres, la de datos.

## Relación con ARTEX
- Se inspira en su arquitectura (orquestación, grafo de evidencias, registro de llamadas al LLM, aprobación humana), pero **no reutiliza su código**. ARTEX es AGPL-3.0 y no se distribuye.
- Las cuatro huellas de ARTEX son experimentales y solo visibles en la máquina que lo ejecuta o en un gateway de modelos.
- **En la versión revisada no se encontró ninguna huella validada visible desde el lado de la víctima.**

## Firma
- Windows: sin firma Authenticode.
- macOS: solo firma ad-hoc; sin Developer ID y sin notarización.
- Sin atestaciones de GitHub (no disponibles para repositorios privados fuera de GitHub Enterprise Cloud).

Los checksums garantizan integridad, no la identidad de quien publica.

Más detalles en [README.md](README.md) (inglés), [CHANGELOG.md](CHANGELOG.md) y `docs/`.
