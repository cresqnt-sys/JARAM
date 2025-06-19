<div align="center">
  <img src="JARAM.ico" alt="JARAM Logo" width="64" height="64">
  <h1>JARAM</h1>
  <p><strong>Just Another Roblox Account Manager</strong></p>
  <p>A modern, feature-rich app for managing multiple Roblox accounts with automatic reconnection and low resource usage.</p>
</div>

## Features

### Multi-Account
- Manage unlimited Roblox accounts
- Bypasses Roblox's Multi Account/Instance limit by reconnecting per process on crash or disconenect.
- Automatic session launching and monitoring
- Consolidated and easy to use interface

### Private Server Support
- **Direct Private Server Links**: Support for standard Roblox private server URLs
- **Share Link Resolution**: Automatic conversion of Roblox share links using official API
- **Seamless Launching**: Direct client launching without browser
- **Multiple Link Formats**:
  - `https://www.roblox.com/games/[ID]/[NAME]?privateServerLinkCode=[CODE]`
  - `https://www.roblox.com/share?code=[CODE]&type=Server`

### Modern GUI Interface
- Clean, dark theme design with modern styling
- Real-time status updates
- Tabbed interface with dedicated sections for users, processes, logs, and settings
- Consolidated account manager

### Advanced Process Management
- Monitor all Roblox processes with detailed information
- Window count enforcement and orphaned process cleanup
- Individual and bulk process control


## Quick Start

### Option 1: Download Executable (Recommended)
1. Download `JARAM.exe` from the releases section
2. Run the executable directly - no installation required
3. Configuration files will be automatically created in your AppData folder

### Option 2: Run from Source
1. Ensure you have Python 3.13 or higher installed
2. Clone or download the repository
3. Install dependencies: `pip install -r requirements.txt`
4. Run: `python gui.py`

### System Requirements
- **Operating System**: Windows (primary support)
- **Python**: 3.13 or higher (if running from source)
- **Roblox**: Must be installed on the system
- **Dependencies**: PyQt6, psutil, requests, pywin32


### Configuration Location
All configuration files are automatically stored in:
```
C:\Users\[USERNAME]\AppData\Roaming\JARAM\
├── users.json          # User accounts with enhanced metadata
├── settings.json       # Application settings and preferences
└── backups/            # Automatic timestamped backups (10 most recent)
```

### Setting Up Accounts

#### 1. Launch JARAM
- **Executable**: Double-click `JARAM.exe`
- **Source**: Run `python gui.py`

#### 2. Add User Accounts
1. Go to **File → Manage Users**
2. Fill in the account details:
   - **User ID**: Your Roblox user ID
   - **Username**: Display name for organization
   - **Private Server Link**: Required for private server access
   - **Place**: Not required for private servers
   - **Cookie**: Your .ROBLOSECURITY cookie
3. Click **Add User** to save

#### 3. Get ROBLOSECURITY Cookies
1. Open your browser and log into Roblox
2. Open Developer Tools (F12)
3. Go to **Application/Storage → Cookies → https://www.roblox.com**
4. Find the `.ROBLOSECURITY` cookie and copy its value

#### 4. Private Server Setup
JARAM supports two types of private server links:

**Direct Links:**
```
https://www.roblox.com/games/[PLACE_ID]/[GAME_NAME]?privateServerLinkCode=[CODE]
```

**Share Links (automatically resolved):**
```
https://www.roblox.com/share?code=[CODE]&type=Server
```

Share links are automatically converted to direct links using the Roblox API for browserless launching.

## Usage Guide

### Starting the Application
- **Executable**: Double-click `JARAM.exe`
- **Source**: Run `python gui.py`

### Interface Overview

#### Dashboard Tab
- **System Statistics**: Total users, active sessions, running processes
- **Quick Actions**: Start/stop manager, restart all sessions, kill all processes
- **Activity Feed**: Real-time updates on user activity and system events
- **Uptime Tracking**: Monitor how long the manager has been running

#### Users Tab
- **User Display**: Shows User ID, Username, Private Server status, Place, and activity
- **Real-time Status**: Online/Offline status with inactive duration tracking
- **Process Information**: Associated PIDs and last active timestamps
- **Individual Controls**: Restart or kill specific user sessions
- **Consolidated Management**: Add users directly from this tab

#### Processes Tab
- **Process Monitoring**: View all Roblox processes with detailed information
- **Window Count Tracking**: Monitor window limits and detect violations
- **Process Control**: Kill individual processes or perform bulk cleanup
- **Orphaned Process Detection**: Identify and clean up stale processes

#### Logs Tab
- **Real-time Logging**: Live application logs with timestamps
- **Log Management**: Save logs to file with automatic timestamping
- **Auto-scroll Option**: Keep latest logs visible automatically
- **Detailed Information**: Comprehensive logging of all operations

#### Settings Tab
- **Timing Configuration**: Adjust check intervals and timeouts
- **Game Settings**: Configure place ID and window limits
- **Advanced Options**: Customize behavior and performance parameters

### Core Operations

#### Starting the Manager
1. Click **"Start Manager"** in the Dashboard
2. Manager initializes all configured user sessions
3. Real-time monitoring begins automatically
4. Users are launched into their configured private servers

#### Managing User Accounts
1. **Add Users**: File → Manage Users or use the Users tab
2. **Edit Users**: Double-click any user in the management dialog
3. **Remove Users**: Select and delete users as needed
4. **Automatic Saving**: All changes are saved with automatic backups

#### Session Management
- **Individual Restart**: Click "Restart" for specific users in the Users tab
- **Bulk Operations**: Use Dashboard quick actions for all sessions
- **Automatic Recovery**: Sessions restart automatically when users go offline
- **Private Server Launching**: Users join their configured private servers automatically

#### Process Control
- **Individual Control**: Kill specific processes from the Processes tab
- **Emergency Stop**: Use "Kill All Processes" for immediate shutdown
- **Cleanup Operations**: Remove dead processes and orphaned entries
- **Window Management**: Automatic enforcement of window limits


### Game Settings
- **Place ID**: Default Roblox place ID (overridden by private server place IDs)
- **Window Limit**: Maximum windows per process (default: 1)
- **Excluded PID**: Process ID to ignore during monitoring (default: 0)


## Troubleshooting

### Common Issues

#### None yet :D
Yeah no issues yet.



## Technical Specifications

### System Requirements
- **Operating System**: Windows 10/11 (primary), Windows 8.1 (limited support)
- **Memory**: 4GB RAM minimum, 8GB recommended for multiple accounts
- **Storage**: 100MB for application, additional space for logs and backups
- **Network**: Internet connection required for share link resolution and presence monitoring
- **Roblox**: Current Roblox client installation required


### Supported Link Formats
```
Direct Private Server Links:
https://www.roblox.com/games/[PLACE_ID]/[GAME_NAME]?privateServerLinkCode=[CODE]

Share Links (Auto-Resolved):
https://www.roblox.com/share?code=[CODE]&type=Server
```

## License and Disclaimer

This project is developed for educational and personal use purposes. Please refer to our [LICENSE](LICENSE.md) for complete terms and conditions. Users are responsible for:
- Complying with Roblox Terms of Service
- Ensuring account security and cookie protection
- Adhering to all terms outlined in LICENSE.md

We are not responsible for any misuse of this application or violations of service terms.

## Support and Community

### Getting Help
1. **Documentation**: Review this README
2. **Logs**: Use the Logs tab for detailed error information
3. **Configuration**: Verify setup using Help → Show Config Location
4. **Community**: Join the Discord server for support and updates: https://discord.gg/6cuCu6ymkX

### Reporting Issues
When reporting issues, please include:
- Operating system and version
- Python version (if running from source)
- Application logs from the Logs tab
- Steps to reproduce the issue
- Configuration details (without sensitive cookies)
