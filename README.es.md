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

## Descarga (v0.3.1)
Página de la versión: https://github.com/CSTHUESP/argos-defense/releases/tag/v0.3.1 (los enlaces funcionan cuando v0.3.1 esté publicada; hasta entonces la última versión publicada es v0.3.0). Los ficheros solo se publican cuando todos los paquetes superan el contrato de publicación y los bytes subidos se han vuelto a descargar y verificar.

| Sistema | Fichero | Probado en |
|---|---|---|
| Windows 64 bits (Intel/AMD) | [ARGOS-Defense-0.3.1-windows-x86_64.zip](https://github.com/CSTHUESP/argos-defense/releases/download/v0.3.1/ARGOS-Defense-0.3.1-windows-x86_64.zip) | runner `windows-2022` |
| Linux 64 bits (glibc ≥ 2.35) | [ARGOS-Defense-0.3.1-linux-x86_64.tar.gz](https://github.com/CSTHUESP/argos-defense/releases/download/v0.3.1/ARGOS-Defense-0.3.1-linux-x86_64.tar.gz) | runner `ubuntu-22.04` |
| Mac Apple Silicon | [ARGOS-Defense-0.3.1-macos-arm64.zip](https://github.com/CSTHUESP/argos-defense/releases/download/v0.3.1/ARGOS-Defense-0.3.1-macos-arm64.zip) | runner `macos-15` |
| Mac Intel | [ARGOS-Defense-0.3.1-macos-x86_64.zip](https://github.com/CSTHUESP/argos-defense/releases/download/v0.3.1/ARGOS-Defense-0.3.1-macos-x86_64.zip) | runner `macos-15-intel` |

Los paquetes no necesitan Python instalado y funcionan sin conexión. Comprueba el hash con `SHA256SUMS`. Solo se han probado en esas imágenes de GitHub (incluido el arranque mediante los lanzadores), no en Windows 10/11 de escritorio, otras distribuciones o versiones de macOS, ni tras una descarga normal con atributos de cuarentena.

## Arranque
- **Windows:** descomprime y haz doble clic en `Start ARGOS Defense.cmd`. SmartScreen puede avisar porque no está firmado; comprueba antes el hash. Decidir si ejecutas software sin firmar es cosa tuya o de tu organización; no desactives SmartScreen ni el antivirus.
- **macOS:** descomprime y haz doble clic en `Start ARGOS Defense.command`. No está notarizado: si Gatekeeper lo bloquea, ve a *Ajustes del Sistema → Privacidad y seguridad → Abrir igualmente* (procedimiento documentado por Apple).
- **Linux:** `tar xzf ARGOS-Defense-0.3.1-linux-x86_64.tar.gz && ./ARGOS-Defense-0.3.1-linux-x86_64/start-argos-defense.sh`

Se abre el navegador en `http://127.0.0.1:8789` (solo local) con la sesión iniciada. El token está en `<carpeta de datos>/.session_token` y no se imprime por defecto. Para parar, pulsa Ctrl+C o cierra la ventana.

## Demo sin datos privados
`argos-defense/argos-defense demo` crea el caso **demo-synthetic**, marcado como DEMO/SYNTHETIC.

## Flujo de trabajo
1. **Importar:** página *Import* o `ingest`. Puedes **declarar la cobertura de recogida** (inicio, fin, ámbito `all` / `tenant:<id>` / `host:<nombre>` / `app_id:<id>`). ARGOS no la verifica y la marca como *declarada por el analista*; sin ella, la ausencia de actividad posterior solo se informa como *no observada en los registros aportados*.
2. **Corregir una importación:** *Reprocess* (o `ingest … --reprocess`) crea una nueva **revisión** con otras opciones (zona horaria, mapeo) a partir del original conservado. Solo una revisión está activa; las anteriores se conservan y un reproceso fallido mantiene la revisión utilizable.
3. **Analizar:** botón *Analyze* (trabajo en segundo plano con progreso y cancelación) o `analyze`. Cada ejecución guarda una instantánea inmutable de alertas, valoración, reglas y configuración; una ejecución fallida o cancelada no sustituye a la última correcta.
4. **Diagnóstico:** el caso muestra qué reglas pudieron evaluarse y por qué no otras (telemetría ausente, historial insuficiente, etc.), campos que faltan, rechazos, cobertura declarada y huecos.
5. **Investigar:** cola de alertas, detalle con las seis dimensiones y el resultado final de la acción, evidencias (con el registro original exacto, verificado por hash), entidades, notas y estado con justificación.
6. **Comparar ejecuciones:** `runs`, `compare-runs` o *Compare runs* en el caso.
7. **Exportar:** JSON, HTML o CSV de la última ejecución o de una anterior (`report --run`).

Los secretos se ocultan en la interfaz, la API, las exportaciones, las notas y los extractos de registros rechazados (detección por claves y patrones: no reconoce todos los formatos). Los originales se conservan intactos; un analista autenticado puede ver un registro sin ocultar de forma explícita (*Show raw*).

**Ingesta continua de ficheros (opcional):** `argos-defense watch --case CASO --dir CARPETA --format native_jsonl` lee en solo lectura una carpeta indicada explícitamente, con puntos de control, líneas parciales, rotación y duplicados. No es un sensor EDR ni prueba de cobertura continua.

## Datos, privacidad, copias y actualización
Los datos se guardan en `%LOCALAPPDATA%\ARGOS Defense` (Windows), `~/Library/Application Support/ARGOS Defense` (macOS) o `~/.local/share/argos-defense` (Linux), o en la carpeta que indiques con `--data-dir`. Las carpetas que crea ARGOS solo son accesibles para tu usuario; `doctor` avisa si una ubicación existente es accesible para otras cuentas. Nada sale del equipo.

- **Copia de seguridad:** `argos-defense backup` (zip con instantánea consistente de la base de datos, todos los originales referenciados verificados por hash y la configuración; falla si falta un original, salvo `--allow-incomplete`, que lo marca `.INCOMPLETE`); `verify-backup` informa por separado de la consistencia de la base de datos y de la completitud de las evidencias; `--data-dir CARPETA_VACÍA restore FICHERO.zip`.
- **Actualización:** descomprime la nueva versión y arráncala; la base de datos se migra tras una copia verificada. Las ejecuciones anteriores a 0.3.0 se conservan como *legacy (sin instantánea)*. Al actualizar desde 0.3.0, los puntos de control del vigilante pasan a *legacy* y se reidentifican de forma conservadora, y la cobertura declarada sin tipos de evento solo cubre los tipos presentes en esa entrada.
- **Desinstalar:** borra la carpeta del programa y, si quieres, la de datos.

## Limitaciones
Validación solo con datos sintéticos generados por el mismo autor de las reglas. En el conjunto reservado eval-v2.1, 90 de 300 unidades benignas generaron alguna alerta de severidad baja o superior (eval-v2.0: 68 de 200); la atribución LLM, evaluada por alerta de forma independiente, no tuvo ninguna atribución excesiva en 646 alertas, y no se detectó ninguno de los 20 ataques que rotan direcciones intercalándose con los accesos del usuario legítimo. El análisis es en memoria: se midieron 300.000 eventos de un perfil de estrés con poca densidad de alertas (69 s, 2,8 GiB de pico); los casos mayores se rechazan. Por defecto se ejecuta un análisis a la vez (cola FIFO de 8) y un solo servidor por carpeta de datos. Sin importación EVTX binaria (dependencia externa no disponible). Detalles en [docs/EVALUATION_PROTOCOL.md](docs/EVALUATION_PROTOCOL.md).

## Relación con ARTEX
- Se inspira en su arquitectura (orquestación, grafo de evidencias, registro de llamadas al LLM, aprobación humana), pero **no reutiliza su código**. ARTEX es AGPL-3.0 y no se distribuye.
- Las cuatro huellas de ARTEX son experimentales y solo visibles en la máquina que lo ejecuta o en un gateway de modelos.
- **En la versión revisada no se encontró ninguna huella validada visible desde el lado de la víctima.**

## Firma
- Windows: sin firma Authenticode.
- macOS: solo firma ad-hoc; sin Developer ID y sin notarización.
- Atestaciones de procedencia de GitHub: se generan cuando el repositorio es público; `release-manifest.json` indica el estado real de cada versión.

Los checksums garantizan integridad, no la identidad de quien publica.

Más detalles en [README.md](README.md) (inglés), [CHANGELOG.md](CHANGELOG.md) y `docs/`.
