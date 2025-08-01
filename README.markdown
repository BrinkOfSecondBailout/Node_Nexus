# Node Nexus: A Custom In-Memory Database Server

## Overview

Node Nexus is a lightweight, socket-based server written in C that implements a custom in-memory database for managing a hierarchical file system. Designed with advanced systems programming concepts, it features user authentication, a tree-based data structure, and binary serialization for persistent storage. Instead of relying on a traditional database like SQLite, Node Nexus uses a custom in-memory database to showcase low-level memory management, thread-safe operations, and efficient binary serialization/deserialization. Multiple clients can connect to the server safely and effectively at once (up to a limit of course).

### Key Features

- **Custom In-Memory Database**: Stores data in a tree of nodes and leaves, managed in shared memory using `mmap` for efficient allocation and deallocation.
- **Binary Serialization**: Persists the database to `database.dat` using a custom binary format, optimized with `zlib` compression for binary data, showcasing serialization techniques without a traditional database.
- **User Authentication**: Supports user registration, login/logout, and a preset admin user (`admin`) with a password set via an environment variable for security.
- **Thread-Safe Operations**: Uses `pthread` mutexes to ensure safe concurrent access in a multi-client environment.
- **Command-Line Interface**: Offers a rich set of commands for navigating and manipulating the file system, with admin-only commands for managing users and resetting the database.
- **File Compression**: Supports compressed binary file storage, leveraging `zlib` to reduce memory usage.
- **Efficient Shutdown**: Implements a `dirty` flag to save the database only when modified, optimizing disk I/O.

## Why a Custom In-Memory Database?

Node Nexus intentionally avoids traditional databases (e.g., SQLite, PostgreSQL) to demonstrate proficiency in:

- **Memory Management**: Uses `mmap` to allocate a shared memory pool, managing nodes, leaves, and users with custom allocation (`alloc_shared`) and cleanup (`munmap`). This showcases fine-grained control over memory without relying on database engines.
- **Binary Serialization/Deserialization**: Persists the entire database (users, nodes, leaves) to a binary file (`database.dat`) with a custom format, including counts for children, siblings, and leaves, and compressed binary data.
- **Performance Optimization**: Implements a hash table for fast leaf lookups and a `dirty` flag to avoid unnecessary saves, for efficient data access and storage strategies.
- **Thread Safety**: Ensures all database operations are protected by a mutex, avoiding undefined behaviors and crashes due to potential overlapping database changes.

## Installation

### Prerequisites

- **Operating System**: Linux or WSL (Windows Subsystem for Linux)
- **Compiler**: GCC
- **Libraries**: `zlib`, `libcrypto` (OpenSSL)
- **Tools**: `make`, `telnet` (for testing)

Install dependencies on Ubuntu/WSL:
```bash
sudo apt update
sudo apt install build-essential libz-dev libssl-dev
```

### Build Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/BrinkOfSecondBailout/Node-Nexus.git
   cd node-nexus/src
   ```

2. Compile the server:
   ```bash
   gcc -o nexus nexus.c database.c myserver.c classifier.c -lz -pthread -lcrypto -lm
   ```

3. Set the admin password environment variable:
   ```bash
   export NODE_NEXUS_ADMIN_PASSWORD="your_secure_password_here"
   ```
   To make it persistent, add to `~/.bashrc` or `~/.zshrc`:
   ```bash
   echo 'export NODE_NEXUS_ADMIN_PASSWORD="your_secure_password_here"' >> ~/.bashrc
   source ~/.bashrc
   ```

4. Run the server:
   ```bash
   ./nexus [port]
   ```
   If not specified, default port is defined in `myserver.c`. Example: `./node_nexus 8080`

## Usage

Connect to the server using a client like `telnet` or `nc` (default port set at 8000 unless customized otherwise):
```bash
telnet localhost 8000

or

nc localhost 8000
```

### Available Commands

Run `help` to see all commands with examples. Key commands include:

- **General Commands**:
  - `register <user> <pass>`: Create a new account (e.g., `register alice password123`).
  - `login <user> <pass>`: Log in (e.g., `login alice password123`).
  - `change_pw <user> <pass>`: Change your password (e.g., `change_pw alice password123`).
  - `logout`: Log out.
  - `tree`: Display all directories and files.
  - `newdir <name>`: Create a directory (e.g., `newdir my_folder`).
  - `addfile <dir> <file> <type> <value>`: Add a file (e.g., `addfile curr wonderland -f alice.png`).
  - `open <file_name>`: View a file (e.g., `open test.txt`).
  - `save <file_name>`: Download a binary file (e.g., `save data.bin`).
  - `kill -<flag> <name>`: Delete a file (`-f`) or directory (`-d`) (e.g., `kill -f test.txt`).
  - `exit`: Exit the client.

- **Admin Commands** (requires `admin` login):
  - `users`: List all users with online/offline status.
  - `boot <user>`: Force logout user (e.g., `boot alice`).
  - `boot_all`: Force logout all users.
  - `banish <user>`: Delete user.
  - `classify <file_name>`: Use AI to analyze a text file to guage sentiment (beta mode) (e.g., `classify diary.txt`).
  - `nuke`: Delete all files and directories.

### Example Session

```bash
telnet localhost 8080
register alice password123
login alice password123
newdir documents
addfile documents note.txt -s 
"Hello, Node Nexus!"
tree
open note.txt
logout
login admin your_secure_password_here
players
nuke
exit
```

## Project Structure

- `database.h`/`database.c`: Implements the in-memory database, serialization, and user management.
- `nexus.h`/`nexus.c`: Handles client commands and interactions.
- `myserver.h`/`myserver.c`: Manages socket connections and server logic.
- `base64.h`/`base64.c`: Provides base64 encoding/decoding for binary data.
- `classifier.h`/`classifier.c`: AI algorithm to gauge text sentiment (beta mode).
- `database.dat`: Binary file for persistent storage.
## Design Choices

- **In-Memory Database**: Uses a tree of `Node` and `Leaf` structs in shared memory (`mmap`) for fast access, with a hash table for quick leaf lookups.
- **Binary Serialization**: Saves the database to `database.dat` with a custom format, including user data and compressed binary leaves, to demonstrate serialization without external dependencies.
- **Dirty Flag**: Optimizes disk writes by saving only when the database is modified, reducing I/O overhead.
- **Environment Variable**: Stores the admin password in `NODE_NEXUS_ADMIN_PASSWORD` to keep sensitive data out of source code, ensuring GitHub safety.
- **Thread Safety**: Uses `pthread` mutexes to protect shared memory, enabling concurrent client handling.

## Security Considerations

- **Password Hashing**: User passwords are hashed with SHA-256 for secure storage.
- **Environment Variable**: The admin password is set via `NODE_NEXUS_ADMIN_PASSWORD`, excluded from version control (`.gitignore` includes `.env`).
- **Admin Restrictions**: Commands like `players` and `nuke` are admin-only, though currently enforced client-side (future work: server-side checks).

## Future Enhancements

- Server-side authentication checks for admin commands.
- Support for file uploads via a client UI.
- Dynamic help system based on user privileges.
- Compression for all data types, not just binary.
- RESTful API for web-based access.

## Contributing

Contributions are welcome! Please fork the repository, create a branch, and submit a pull request. Ensure changes are tested and maintain thread safety.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

Built as a portfolio project to demonstrate systems programming skills, inspired by concepts from "Crafting Interpreters" by Robert Nystrom and socket programming tutorials.
