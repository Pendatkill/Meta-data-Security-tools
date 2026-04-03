# Developer: pendatkill
# Module: setup
# Description: Package setup configuration for metadata-security-toolkit

from setuptools import setup, find_packages

setup(
    name="metadata-security-toolkit",
    version="0.1.0",
    author="pendatkill",
    description="A toolkit for analyzing file metadata, EXIF data, cryptographic signatures, and AI-generated content detection.",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "Pillow>=9.0.0",
        "PyMuPDF>=1.20.0",
        "python-docx>=0.8.11",
        "openpyxl>=3.0.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Multimedia :: Graphics",
    ],
)
