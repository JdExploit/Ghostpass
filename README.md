# GhostPass vX

**Autor:** JDEXPLOIT - Joan David Torres Garcia  
**Clasificación:** Herramienta de Investigación Ofensiva  
**Plataforma:** Windows x86_64  
**Versión:** Final (vX)

---

## 1. Descripción General

GhostPass vX es una herramienta de investigación ofensiva diseñada para la ejecución de carga útil (payload) en entornos Windows x86_64 mediante múltiples técnicas de inyección avanzada. El proyecto incorpora mecanismos de evasión de defensas, ofuscación temporal de datos en memoria y capacidades de autodestrucción post-ejecución.

La herramienta opera como un cargador (loader) que recibe un archivo binario como argumento, lo carga en memoria y lo ejecuta utilizando una de las cuatro técnicas de inyección disponibles, seleccionables por el operador.

---

## 2. Capacidades Principales

### 2.1 Técnicas de Ejecución de Carga Útil

| Índice | Técnica | Descripción |
|--------|---------|-------------|
| 0 | Inyección APC | Creación de proceso suspendido (svchost.exe), asignación de memoria, escritura de carga útil y ejecución mediante APC Queue |
| 1 | Module Stomping | Sobrescritura de la sección `.text` de una DLL legítima cargada (comctl32.dll) con la carga útil |
| 2 | Thread Pool | Ejecución de la carga útil mediante la API de Windows Thread Pool (CreateThreadpoolWork) |
| 3 | Ejecución Directa | Asignación de memoria ejecutable y llamada directa a la carga útil |

### 2.2 Mecanismos de Evasión

- **Parcheo de ETW (Event Tracing for Windows):** Neutraliza las funciones `EtwEventWrite`, `EtwEventWriteFull`, `EtwEventWriteTransfer` y `NtTraceEvent` en ntdll.dll, escribiendo instrucciones de retorno inmediato (xor rax, rax; ret) mediante llamadas indirectas al sistema.

- **Parcheo de AMSI (Antimalware Scan Interface):** Deshabilita `AmsiScanBuffer`, `AmsiInitialize` y `AmsiNotifyOperation` en amsi.dll, forzando códigos de retorno que indican resultado limpio (0x80070057 - E_INVALIDARG).

- **Desenganche de ntdll.dll (Unhooking):** Recupera una copia limpia de ntdll.dll desde `\KnownDlls\ntdll.dll` mediante `NtOpenSection` y `NtMapViewOfSection`, sobrescribiendo la sección `.text` del módulo cargado en el proceso actual para eliminar hooks de EDR/AV en modo usuario.

- **Desactivación de Windows Defender:** Modifica las claves de registro `DisableRealtimeMonitoring` y `DisableAntiSpyware` bajo `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`.

### 2.3 Anti-Análisis

- **Detección de depuración:** Verifica el flag `BeingDebugged` en el PEB (Process Environment Block).

- **Detección de hipervisor:** Comprueba el bit 31 de ECX tras ejecutar `CPUID` con EAX=1 (indicador de presencia de hipervisor).

- **Detección de entornos virtualizados por MAC address:** Compara la dirección MAC del adaptador de red contra patrones conocidos de VMware, VirtualBox y Microsoft Virtual PC.

- **Verificación de recursos del sistema:** Requiere un mínimo de 4 GB de RAM física para proceder, dificultando la ejecución en entornos sandbox limitados.

### 2.4 Cifrado de Memoria Durante Pausa (Sleep Encryption)

La función `SleepEncrypt` aplica cifrado XOR mediante una clave derivada de:
- Registro de timestamp del procesador (RDTSC)
- Tiempo de actividad del sistema (GetTickCount64)
- Dirección base de ntdll.dll
- Hash del string "ghostpass"

La carga útil se cifra antes de un período de espera configurable y se descifra al finalizar, protegiendo los datos contra análisis de memoria durante pausas en la ejecución.

### 2.5 Autodestrucción

El ejecutable se elimina del disco tras la ejecución mediante la creación de un proceso `cmd.exe` que ejecuta un comando `del /f /q` con un retardo de 2 segundos.

---

## 3. Arquitectura Técnica

### 3.1 Resolución Dinámica de APIs

Toda función de la API de Windows y NT se resuelve dinámicamente mediante:
- **Recorrido del PEB:** Obtención de módulos cargados mediante `InMemoryOrderModuleList`.
- **Hashing de cadenas:** Algoritmo de hash personalizado que procesa nombres de función y módulo.
- **Recorrido de tabla de exportación:** Búsqueda de funciones por hash en la tabla de exportación de cada módulo.

Esto elimina dependencias en la tabla de importación (IAT) y dificulta el análisis estático.

### 3.2 Llamadas Indirectas al Sistema (Indirect Syscalls)

Las funciones críticas (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtQueueApcThread`, `NtResumeThread`) se invocan mediante stubs en ensamblador que:
1. Resuelven dinámicamente el SSN (System Service Number) desde ntdll.dll.
2. Localizan la instrucción `syscall` correspondiente en ntdll.dll.
3. Ejecutan el syscall desde la ubicación original en ntdll.dll, no desde el stub propio.

Esto evade hooks en modo usuario que interceptan llamadas desde direcciones fuera de los módulos del sistema, así como detecciones basadas en la instrucción `syscall` fuera de ntdll.dll.

### 3.3 Estructura de Soportes de Syscall

```c
typedef struct _SYSCALL_ENTRY {
    DWORD ssn;      // System Service Number
    PVOID gadget;   // Puntero a la instrucción syscall en ntdll.dll
} SYSCALL_ENTRY;
```

La función `ResolveSyscall` localiza el SSN y el gadget mediante escaneo de bytes en la función exportada correspondiente en ntdll.dll, buscando la secuencia `0F 05` (syscall) y extrayendo el SSN del byte inmediatamente anterior.

### 3.4 Carga Dinámica de DLLs

La función `LoadDLLByHash` utiliza `LdrLoadDll` para cargar módulos adicionales (amsi.dll, comctl32.dll, etc.) en el espacio de direcciones del proceso, permitiendo su manipulación posterior sin dependencias estáticas.

---

## 4. Requisitos de Compilación

### 4.1 Herramientas Necesarias

- Compilador MinGW-w64 (x86_64) con soporte para ensamblador Intel
- Windows SDK (para cabeceras y bibliotecas)
- Sistema operativo Windows 10/11 x64 o superior

### 4.2 Comando de Compilación

```bash
x86_64-w64-mingw32-gcc -O2 -s -march=native -masm=intel -fomit-frame-pointer \
  -o ghostpass.exe ghostpass_vX.c \
  -lntdll -liphlpapi -ladvapi32 \
  -static-libgcc -fno-stack-protector -fvisibility=hidden -Wno-unused-result
```

### 4.3 Flags de Compilación

| Flag | Propósito |
|------|-----------|
| `-O2` | Optimización de nivel 2 |
| `-s` | Eliminación de símbolos del binario final |
| `-march=native` | Optimización para la arquitectura de la máquina de compilación |
| `-masm=intel` | Sintaxis Intel para ensamblador inline |
| `-fomit-frame-pointer` | Omisión del frame pointer para reducir tamaño |
| `-fno-stack-protector` | Desactivación de protecciones de stack |
| `-fvisibility=hidden` | Ocultación de símbolos exportados |
| `-static-libgcc` | Enlace estático de libgcc |
| `-Wno-unused-result` | Supresión de advertencias por resultados no utilizados |

---

## 5. Modo de Uso

### 5.1 Sintaxis

```
ghostpass.exe <archivo_payload> [tecnica]
```

### 5.2 Parámetros

| Parámetro | Descripción | Requerido |
|-----------|-------------|-----------|
| `archivo_payload` | Ruta al archivo binario que contiene la carga útil a ejecutar | Sí |
| `tecnica` | Índice de técnica de inyección (0-3, por defecto 0) | No |

### 5.3 Ejemplos

```
ghostpass.exe payload.bin
ghostpass.exe payload.bin 1
ghostpass.exe payload.bin 2
```

### 5.4 Técnicas Disponibles

- `0` - APC Injection (svchost.exe suspendido)
- `1` - Module Stomping (comctl32.dll)
- `2` - Thread Pool Execution
- `3` - Ejecución Directa

---

## 6. Flujo de Ejecución

```
main()
  |
  +---> Validar argumentos
  |
  +---> Leer archivo de carga útil
  |
  +---> Execute()
          |
          +---> InitHashes()         // Inicializar hashes de funciones
          |
          +---> PatchAMSI()          // Deshabilitar AMSI
          |
          +---> PatchETW()           // Deshabilitar ETW
          |
          +---> DisableDefender()    // Deshabilitar Windows Defender
          |
          +---> UnhookNTDLL()        // Desenganchar ntdll.dll
          |
          +---> AntiAnalysis()       // Verificar entorno
          |
          +---> SleepEncrypt()       // Cifrar y pausar
          |
          +---> [Técnica seleccionada]
          |
  +---> VirtualFree()                // Liberar payload
  |
  +---> SelfDelete()                 // Autodestrucción
```

---

## 7. Consideraciones de Seguridad y Detección

### 7.1 Indicadores de Compromiso (IOC)

- Creación de procesos svchost.exe en estado suspendido con parámetros `-k netsvcs`.
- Manipulación de secciones de memoria en ntdll.dll mediante `NtOpenSection` y `NtMapViewOfSection` a `\KnownDlls`.
- Modificación de claves de registro de Windows Defender.
- Escritura en la sección `.text` de comctl32.dll.
- Llamadas al sistema con dirección de retorno en ntdll.dll pero origen en memoria privada.

### 7.2 Medidas Defensivas

Los mecanismos de defensa implementados están diseñados para evadir:
- Soluciones EDR (Endpoint Detection and Response) con hooks en modo usuario.
- Análisis de memoria mediante volcados.
- Sandboxes automatizadas con recursos limitados.
- Entornos de análisis virtualizados.
- Instrumentación de ETW.
- Escaneo de AMSI.

### 7.3 Limitaciones

- No evade hooks en modo kernel (callbacks de PsSetCreateProcessNotifyRoutine, etc.).
- La manipulación de registro de Windows Defender requiere privilegios elevados.
- La detección de entornos virtuales por MAC address es limitada a configuraciones de red específicas.
- El stub en ensamblador para syscalls indirectos depende de convenciones de llamada y disposición de pila específicas de x64.

---

## 8. Estructura del Código Fuente

### 8.1 Secciones Principales

| Sección | Líneas | Contenido |
|---------|--------|-----------|
| Definiciones de tipos | 1-35 | Estructuras del NT API y prototipos de función |
| Utilidades de hashing | 36-37 | Funciones de hash para cadenas ANSI y Unicode |
| Resolución de módulos | 38-46 | Obtención de módulos por hash mediante recorrido del PEB |
| Resolución de funciones | 47-55 | Obtención de direcciones de función por hash desde tabla de exportación |
| Resolución de syscalls | 56-63 | Localización de SSN y gadget syscall en ntdll.dll |
| Carga dinámica de DLLs | 64-79 | Carga de DLLs mediante LdrLoadDll |
| Stubs indirectos | 80-98 | Funciones en ensamblador para syscalls indirectos |
| Inicialización de hashes | 99-125 | Cálculo de todos los hashes de función y módulo |
| Anti-análisis | 126-135 | Verificación de depuración, hipervisor, MAC y RAM |
| Parcheo de ETW/AMSI | 136-155 | Deshabilitación de capacidades de telemetría y escaneo |
| Unhooking de ntdll | 156-179 | Restauración de sección .text desde KnownDlls |
| Técnicas de inyección | 180-245 | Implementación de los cuatro métodos de ejecución |
| Cifrado de pausa | 246-261 | Protección de memoria durante esperas |
| Flujo principal | 262-280 | Orquestación de la ejecución y autodestrucción |

---

## 9. Advertencia Legal

Esta herramienta ha sido desarrollada exclusivamente para fines de investigación ofensiva, pruebas de penetración autorizadas y evaluación de mecanismos de defensa. El uso de esta herramienta contra sistemas sin autorización explícita del propietario constituye una violación de las leyes aplicables en la mayoría de jurisdicciones.

El autor no asume responsabilidad alguna por el uso indebido de este software. Es responsabilidad del usuario asegurarse de que su utilización cumple con todas las leyes y regulaciones aplicables en su jurisdicción.

---

## 10. Referencias Técnicas

- Windows NT Kernel Internals - System Service Dispatch
- Process Environment Block (PEB) y estructuras asociadas
- NTAPI - Funciones del espacio de usuario del kernel de Windows
- ETW (Event Tracing for Windows) - Arquitectura y mecanismos de intercepción
- AMSI (Antimalware Scan Interface) - Integración con proveedores de seguridad
- Técnicas de Module Stomping y Process Hollowing
- Indirect Syscall - Evasión de hooks en modo usuario mediante ejecución desde ntdll.dll

---

**Versión del Documento:** 1.0  
**Fecha:** Junio 2026  
**Clasificación:** Documentación Técnica de Proyecto de Investigación
