"""
Setup script for ExProtocol package
"""
import os
import sys
import platform
import subprocess
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist
from setuptools.command.install import install
from distutils.core import Command

# Get the directory containing this file
HERE = os.path.abspath(os.path.dirname(__file__))
HAMMING_DIR = os.path.join(HERE, 'c_hamming')


class BuildHamming(Command):
    """Custom command to build the Hamming binary"""
    description = 'Build the Hamming C binary'
    user_options = []

    def initialize_options(self):
        self.build_lib = None

    def finalize_options(self):
        # Get the build directory from the build_py command
        self.set_undefined_options('build_py', ('build_lib', 'build_lib'))

    def run(self):
        """Build the Hamming binary for the current platform"""
        hamming_c = os.path.join(HAMMING_DIR, 'hamming.c')
        
        if not os.path.exists(hamming_c):
            raise FileNotFoundError(f"hamming.c not found at {hamming_c}")
        
        system = platform.system()
        machine = platform.machine()
        
        if system == 'Windows':
            # Try MinGW first, then MSVC, then clang
            binary_name = 'hamming.exe'
            
            # Try to find a compiler
            compilers = []
            
            # Check for MinGW gcc
            try:
                subprocess.run(['gcc', '--version'], 
                             capture_output=True, check=True, timeout=2)
                compilers.append(('gcc', ['-Wall', '-Wextra', '-std=c99', '-O3']))
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
            
            # Check for MSVC cl
            try:
                subprocess.run(['cl'], capture_output=True, check=True, timeout=2)
                compilers.append(('cl', ['/W3', '/O2', '/TC', '/Fe:hamming.exe', '/link']))
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
            
            # Check for clang
            try:
                subprocess.run(['clang', '--version'], 
                             capture_output=True, check=True, timeout=2)
                compilers.append(('clang', ['-Wall', '-Wextra', '-std=c99', '-O3']))
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
            
            if not compilers:
                raise RuntimeError(
                    "No C compiler found on Windows. Please install one of:\n"
                    "  - MinGW-w64 (gcc)\n"
                    "  - Microsoft Visual C++ (cl)\n"
                    "  - LLVM/Clang (clang)"
                )
            
            # Use the first available compiler
            compiler, flags = compilers[0]
            cmd = [compiler] + flags + ['-o', binary_name, hamming_c]
            
            # MSVC uses different output flag
            if compiler == 'cl':
                # Remove -o flag, MSVC uses /Fe
                cmd = [c for c in cmd if c != '-o' and c != binary_name]
                cmd.extend(['/Fe:' + binary_name])
        elif system == 'Linux':
            # Use gcc on Linux
            binary_name = 'hamming'
            compiler = 'gcc'
            cmd = [
                compiler,
                '-Wall', '-Wextra', '-std=c99', '-O3',
                '-o', binary_name,
                hamming_c
            ]
        elif system == 'Darwin':  # macOS
            # Use clang/gcc on macOS
            binary_name = 'hamming'
            compiler = 'gcc'
            cmd = [
                compiler,
                '-Wall', '-Wextra', '-std=c99', '-O3',
                '-o', binary_name,
                hamming_c
            ]
        else:
            raise RuntimeError(f"Unsupported platform: {system}")
        
        print(f"Building Hamming binary for {system} ({machine})...")
        print(f"Command: {' '.join(cmd)}")
        
        # Always build in the source directory first
        old_cwd = os.getcwd()
        os.chdir(HAMMING_DIR)
        
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            # Verify the binary was created in source directory
            built_binary = os.path.join(HAMMING_DIR, binary_name)
            if not os.path.exists(built_binary):
                raise RuntimeError(f"Binary was not created at {built_binary}")
            
            # Make executable on Unix
            if system != 'Windows':
                os.chmod(built_binary, 0o755)
            
            print(f"✅ Successfully built {binary_name} in source directory")
            
            # Copy to build/install location if build_lib is set
            if self.build_lib:
                output_dir = os.path.join(self.build_lib, 'ExProtocol', 'c_hamming')
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, binary_name)
                
                import shutil
                shutil.copy2(built_binary, output_path)
                if system != 'Windows':
                    os.chmod(output_path, 0o755)
                print(f"✅ Copied binary to {output_path}")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Build failed:")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            raise
        finally:
            os.chdir(old_cwd)


class BuildPyWithHamming(build_py):
    """Build Python package and Hamming binary"""
    
    def run(self):
        # Build Python package first to set up directory structure
        build_py.run(self)
        
        # Now copy C source files to the built package directory
        # This ensures they're available in the installed package
        if self.build_lib:
            package_dir = os.path.join(self.build_lib, 'ExProtocol', 'c_hamming')
            os.makedirs(package_dir, exist_ok=True)
            
            # Copy C source files
            import shutil
            for file in ['hamming.c', 'makefile']:
                src = os.path.join(HAMMING_DIR, file)
                if os.path.exists(src):
                    dst = os.path.join(package_dir, file)
                    shutil.copy2(src, dst)
                    print(f"Copied {file} to {package_dir}")
        
        # Build Hamming binary (this will use build_lib if set)
        self.run_command('build_hamming')


class SDistWithHamming(sdist):
    """Create source distribution with build instructions"""
    
    def run(self):
        # Don't build binary in sdist, just include source
        sdist.run(self)


class InstallWithHamming(install):
    """Install package and ensure Hamming binary is built"""
    
    def run(self):
        # Ensure build happens before install
        # This will build the binary during the build phase
        if not self.skip_build:
            self.run_command('build_py')
        # Run the standard install
        install.run(self)
        
        # Post-install: ensure binary exists in installed location
        # This handles cases where installation from wheel didn't include binary
        if hasattr(self, 'install_lib') and self.install_lib:
            try:
                package_dir = os.path.join(self.install_lib, 'ExProtocol')
                c_hamming_dir = os.path.join(package_dir, 'c_hamming')
                hamming_c = os.path.join(c_hamming_dir, 'hamming.c')
                system = platform.system()
                binary_name = 'hamming.exe' if system == 'Windows' else 'hamming'
                binary_path = os.path.join(c_hamming_dir, binary_name)
                
                # If source exists but binary doesn't, build it
                if os.path.exists(hamming_c) and not os.path.exists(binary_path):
                    print(f"Building Hamming binary in installed location: {c_hamming_dir}")
                    old_cwd = os.getcwd()
                    os.chdir(c_hamming_dir)
                    try:
                        if system == 'Windows':
                            # Try compilers in order
                            for compiler in ['gcc', 'clang', 'cl']:
                                try:
                                    test_cmd = [compiler, '--version'] if compiler != 'cl' else ['cl']
                                    subprocess.run(test_cmd, capture_output=True, 
                                                 check=True, timeout=2)
                                    if compiler == 'cl':
                                        subprocess.run(['cl', '/W3', '/O2', '/TC', 
                                                       f'/Fe:{binary_name}', 'hamming.c'], 
                                                     check=True, cwd=c_hamming_dir)
                                    else:
                                        subprocess.run([compiler, '-Wall', '-Wextra', 
                                                       '-std=c99', '-O3', '-o', binary_name, 
                                                       'hamming.c'], check=True, cwd=c_hamming_dir)
                                    if os.path.exists(binary_path):
                                        print(f"✅ Successfully built {binary_name}")
                                        break
                                except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                                    continue
                            else:
                                print("⚠️  Warning: No C compiler found. Binary not built.")
                        else:
                            # Linux/macOS - use gcc
                            subprocess.run(['gcc', '-Wall', '-Wextra', '-std=c99', '-O3', 
                                          '-o', binary_name, 'hamming.c'], 
                                         check=True, cwd=c_hamming_dir)
                            if os.path.exists(binary_path):
                                os.chmod(binary_path, 0o755)
                                print(f"✅ Successfully built {binary_name}")
                    except subprocess.CalledProcessError as e:
                        print(f"⚠️  Warning: Could not build binary: {e}")
                        print("You may need to build it manually or install a C compiler.")
                    finally:
                        os.chdir(old_cwd)
            except Exception as e:
                # Non-critical - just warn
                print(f"⚠️  Warning: Could not verify/build binary: {e}")


# Read the README for long description
try:
    with open(os.path.join(HERE, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "ExProtocol - Secure P2P communication protocol"

setup(
    name='exprotocol',
    version='0.1.2',
    description='Secure peer-to-peer communication protocol with proof-of-work, encryption, and error correction',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Muni Besen',
    author_email='',  # Add your email
    url='https://github.com/Silenttttttt/ExProtocol',
    license='MIT',
    packages=find_packages(),
    python_requires='>=3.8',
    install_requires=[
        'cryptography>=3.0.0',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Communications',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    cmdclass={
        'build_hamming': BuildHamming,
        'build_py': BuildPyWithHamming,
        'sdist': SDistWithHamming,
        'install': InstallWithHamming,
    },
    package_data={
        'ExProtocol': ['c_hamming/*.c', 'c_hamming/makefile'],
    },
    include_package_data=True,
    zip_safe=False,  # Not safe because we need to execute the binary
)

