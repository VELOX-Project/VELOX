# VELOX 🚀

**VELOX** is a terminal-based C++ tool designed to safely and legally load `.sys` kernel-mode drivers on Windows. Built with a focus on developer transparency and system stability, VELOX allows users to input or drag-and-drop `.sys` driver files, verify them, and configure them to load at boot via the Windows Service Control Manager (SCM). This project is created for educational, development, and legitimate use only.

## Features

- 🔍 Drag-and-drop `.sys` file detection
- 🛠 Driver validation & service creation
- ⚙️ Configures driver for boot-time load
- 🔐 Admin privilege & error checking
- 📜 Clean, informative terminal logs
- 🧼 No memory tampering or kernel patching

## Usage

1. Run the VELOX executable as administrator.
2. Drag a valid `.sys` driver into the terminal window, or manually type its path.
3. VELOX will validate the file and create the necessary service.
4. If successful, the driver will be set to auto-load during system startup.

> **NOTE:** This tool does **NOT** support or include any cheat-related features. It is intended for use by security researchers, driver developers, and educational purposes only.

## Requirements

- Windows 10/11
- Administrator privileges
- A valid `.sys` driver

## Disclaimer

VELOX is provided as-is, without warranty. The author is **not responsible** for any misuse, damage, or system instability caused by this software. Use it at your own risk.

## License

This project is licensed under the MIT License.
