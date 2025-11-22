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
from distutils.core import Command

# Get the directory containing this file
HERE = os.path.abspath(os.path.dirname(__file__))
HAMMING_DIR = os.path.join(HERE, 'c_hamming')


class BuildHamming(Command):
    """Custom command to build the Hamming binary"""
    description = 'Build the Hamming C binary'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

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
        
        # Change to the hamming directory
        old_cwd = os.getcwd()
        os.chdir(HAMMING_DIR)
        
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            print(f"✅ Successfully built {binary_name}")
            
            # Verify the binary exists
            binary_path = os.path.join(HAMMING_DIR, binary_name)
            if not os.path.exists(binary_path):
                raise RuntimeError(f"Binary was not created at {binary_path}")
            
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
        # Build Hamming binary first
        self.run_command('build_hamming')
        # Then build Python package
        build_py.run(self)


class SDistWithHamming(sdist):
    """Create source distribution with build instructions"""
    
    def run(self):
        # Don't build binary in sdist, just include source
        sdist.run(self)


# Read the README for long description
try:
    with open(os.path.join(HERE, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "ExProtocol - Secure P2P communication protocol"

setup(
    name='exprotocol',
    version='0.1.0',
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
    },
    package_data={
        '': ['c_hamming/hamming*', 'c_hamming/*.c', 'c_hamming/makefile'],
    },
    include_package_data=True,
    zip_safe=False,  # Not safe because we need to execute the binary
)

