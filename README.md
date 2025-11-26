# BitBots EcoWatt Cloud

**BitBots EcoWatt Cloud** serves as the cloud interface for EcoWatt embedded device, enabling seamless interaction between the hardware and the user.

This system is designed to monitor, configure, and manage EcoWatt smart energy devices. It provides a secure and efficient platform for real-time data collection, remote device management, and Firmware Over-The-Air (FOTA) updates.

## Features

*   **Real-time Monitoring**: Visual dashboard to monitor device parameters like Voltage, Current, Frequency, Power, and Temperature.
*   **Secure Communication**: Implements HMAC-SHA256 authentication and nonce-based replay attack prevention to ensure secure data transmission between EcoWatt devices and the cloud.
*   **Device Configuration**: Remotely configure device settings such as sampling intervals and active registers.
*   **Remote Commands**: Send commands to devices, such as controlling output power percentage.
*   **Firmware Over-The-Air (FOTA)**:
    *   Upload firmware binaries (`.bin`).
    *   Queue updates for specific devices.
    *   Chunked firmware delivery with integrity verification.
    *   Real-time download progress tracking.
*   **Error Emulation**: Simulate various error conditions (CRC errors, packet drops, delays) to test device resilience.
*   **Data Compression**: Supports delta decompression for efficient bandwidth usage.
*   **In-Memory Storage**: Uses in-memory data structures for high-speed data processing (Note: Data is not persistent across restarts).

## Tech Stack

*   **Backend**: Python, Flask
*   **Frontend**: HTML, CSS, JavaScript
*   **Security**: HMAC-SHA256, Base64 encoding

## Prerequisites

*   Python 3.x
*   pip (Python package manager)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd EcoWatt_Cloud
    ```

2.  **Install dependencies:**
    You need to install Flask. You can install it using pip:
    ```bash
    pip install flask
    ```

## Usage

1.  **Start the server:**
    ```bash
    python app.py
    ```
    The server will start on port **5001** by default.

2.  **Access the Dashboard:**
    Open your web browser and navigate to:
    ```
    http://localhost:5001
    ```

3.  **Dashboard Functionality:**
    *   **Device Configurations**: Set sampling intervals and choose which registers to monitor.
    *   **Firmware Update**: Upload `.bin` firmware files and deploy them to connected devices.
    *   **Error Emulation**: Inject faults to test how devices handle errors.

## API Endpoints

### Device Communication
*   `POST /upload`: Endpoint for devices to upload sensor data. Requires secure payload.
*   `POST /config`: Endpoint for devices to poll for configuration updates, commands, and FOTA chunks.

### Management & Frontend
*   `GET /`: Main dashboard interface.
*   `POST /set-config`: Queue a new configuration for a device.
*   `POST /queue-command`: Queue a command for a device.
*   `POST /upload-firmware`: Upload a new firmware binary to the server.
*   `POST /queue-firmware-update`: Initiate a FOTA update for a specific device.
*   `GET /api/latest_data`: Retrieve the latest device data for the dashboard.
*   `GET /api/fota-status/<device_id>`: Check the status of an active FOTA session.

## Security Mechanism

The system uses a pre-shared key (PSK) mechanism.
1.  **Payload Encryption**: The device encrypts the payload.
2.  **HMAC Signature**: A signature is generated using the PSK and the message (nonce + payload).
3.  **Replay Protection**: A strictly increasing nonce is used to prevent replay attacks.
4.  **Validation**: The server validates the device ID, checks the nonce, and verifies the HMAC signature before processing any data.

## Project Structure

*   `app.py`: Main Flask application containing all backend logic, routes, and in-memory storage.
*   `firmware_files/`: Directory where uploaded firmware binaries are stored.
*   `templates/`: (Implicit) HTML content is currently embedded in `app.py` for simplicity.

