# ZeroTier Network Monitor

Un servicio ligero de monitorización de red basado en Docker que rastrea la disponibilidad de hosts a través de redes Locales, ZeroTier y Remotas (usando un Jump Host).

## Características

- **Monitorización Multi-Red**: Verifica la conectividad de los hosts en redes locales, ZeroTier, o en ubicaciones remotas.
- **Notificaciones por Telegram**: Recibe alertas instantáneas en tu dispositivo.
- **Horarios Flexibles**: Configura qué hosts son "opcionales" o define un horario específico (`8-18`) para evitar alertas de fuera de horario.Dentro de este campo, puedes usar:
  - **Rango de horas (`8-18`)**: El host se monitoriza en ese intervalo. Si se apaga fuera de él, no recibes alerta (se marca como *Scheduled*).
  - **`libre` / `opcional` / `ondemand` / `none` / `-`**: El host es opcional. No envía alertas de "OFFLINE", ideal para equipos de uso ocasional.
  - **Vacio / Otros**: Se asume monitorización **24/7**. Alertará en cualquier momento si el equipo cae.
- **Dashboard Web**: Interfaz clara con Flask para visualizar y ordenar todos tus nodos.
- **Editor Visual SSH**: Gestiona tus configuraciones desde un editor estructurado con tabla CRUD en la web (adiós a editar texto plano).
- **Escáner/Descubrimiento**: Escanea las diferentes subredes para añadir nuevos dispositivos fácilmente a la monitorización.

## Despliegue

1. Clona el repositorio.
2. Copia el archivo `.env.example` como `.env` y rellena tus datos.
3. Levanta el servicio con Docker Compose:

   ```bash
   docker-compose up -d
   ```

4. Visita el puerto `8080` (o el que hayas definido) para acceder al panel.

## Variables de Entorno (`.env`)

A continuación se detalla el propósito de cada parámetro dentro del archivo `.env`:

### ZeroTier
- `ZT_TOKEN`: Tu token de acceso de la API de ZeroTier (necesario para leer el estado de la red ZeroTier).
- `ZT_NETWORK`: El ID de tu red de ZeroTier que quieres escanear/monitorizar.

### Notificaciones de Telegram
- `TELEGRAM_BOT_TOKEN`: Token de tu bot de Telegram.
- `TELEGRAM_CHAT_ID`: ID del chat/grupo donde el bot enviará las notificaciones (No olvides el guión - en caso de ser un chat/grupo, por ejemplo: `-123456789`).  

### Red Remota (Jump Host)
- `JUMP_HOST_IP`: Dirección IP de la máquina (Jump Host) usada para monitorizar nodos de la red remota mediante SSH.
- `JUMP_HOST_USER`: Usuario empleado para la conexión SSH hacia el Jump Host.

### Seguridad Web
- `WEB_USER`: Nombre de usuario para el inicio de sesión básico del panel web (por defecto: `admin`).
- `WEB_PASSWORD`: Contraseña para el panel web. **Importante:** Si dejas este valor vacío, se desactivará la protección con contraseña.

### Configuración de Alertas (true/false)
- `NOTIFY_OFFLINE`: Notificar cuando un dispositivo programado se apaga o pierde conexión.
- `NOTIFY_ONLINE`: Notificar cuando un dispositivo vuelve a conectarse en su horario.
- `NOTIFY_OFF_SCHEDULE`: Notificar si un dispositivo se conecta **fuera** de su horario (útil para detectar accesos inesperados).
- `NOTIFY_STARTUP`: Recibir un mensaje cuando el contenedor y el servicio de monitorización se inician.
- `NOTIFY_API_ERROR`: Recibir alertas si hay problemas de conexión con la API de ZeroTier.

### Rendimiento / Escaneo
- `CHECK_INTERVAL_SECONDS`: Frecuencia de actualización en segundos (tiempo que espera el script entre comprobaciones). Por defecto es `300` (5 minutos).
