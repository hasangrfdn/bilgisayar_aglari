from setuptools import setup, find_packages

setup(
    name="secure_file_transfer",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "PyQt5>=5.15.0",
        "scapy>=2.5.0",
        "pycryptodome>=3.19.0",
        "cryptography>=41.0.0",
        "psutil>=5.9.0",
        "pytest>=7.4.0",
        "python-dotenv>=1.0.0",
        "colorama>=0.4.6",
        "tqdm>=4.66.0",
    ],
    entry_points={
        'console_scripts': [
            'secure-transfer=src.main:main',
        ],
    },
) 