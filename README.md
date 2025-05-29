Setup Instructions: 
If first time cloning : git clone --recurse-submodules https://github.com/your-username/your-repo.git
If already cloned run : git submodule update --init --recursive


COME BACK TO THIS AND REFINE: 

QT6
CMAKE
Libsodium - vcpkg
## 🚀 Project Setup

### 1. Prerequisites

- CMake ≥ 3.16
- Qt6 (Core, Gui, Widgets)
- [vcpkg](https://github.com/microsoft/vcpkg)

### 2. Install Dependencies

```bash
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
./vcpkg/vcpkg install libsodium
