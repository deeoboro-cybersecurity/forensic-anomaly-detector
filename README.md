Automated Forensic Extraction and Anomaly Detection System

This project is an automated digital forensics tool built with Python. Security Operations Center (SOC) analysts often spend hours manually extracting file metadata and system logs to investigate cyber threats. This tool solves that bottleneck by automating the artifact extraction process and using a machine learning Isolation Forest model to instantly flag hidden or anomalous files. It is designed to speed up incident response times and eliminate human error from the initial scanning phase.

This tool automates the extraction of digital forensic artifacts and leverages machine learning to identify anomalous file behavior, streamlining Security Operations Center (SOC) and Incident Response workflows.

Core Features

Automated Artifact Scanning: Traverses file systems to extract critical metadata (timestamps, file sizes, extensions) using Python's native os libraries. 

Cryptographic Hashing: Generates SHA-256 and MD5 hashes for file integrity verification and malicious payload identification via the hashlib module.

Machine Learning Anomaly Detection: Implements an Isolation Forest model to assign risk scores and flag anomalous file modifications or hidden artifacts.

Automated Reporting: Compiles scan results and anomaly flags into structured JSON and human-readable text reports for incident logging.
Graphical User Interface: Provides an accessible desktop interface for configuring scan parameters and reviewing outputs.

Project Architecture
The system is built with a modular architecture for easy maintenance and integration:

main.py - The entry point that initializes the application.

ai/anomaly.py - Contains the machine learning logic for risk scoring.

scanner/scanner.py - Handles file system traversal and metadata extraction.

hashing/hasher.py - Manages cryptographic hash generation.

reports/reports.py - Structures the output data.

gui/app.py - Drives the graphical interface.

data/controlled_dataset/ - Storage for baseline testing environments.

output/ - Directory for generated report.json and report.txt files.

Technical Stack

Language: Python

Key Libraries: os, hashlib, scikit-learn (Isolation Forest), datetime, tkinter/PyQt (GUI)

How to Run

Clone the repository to your local machine.

Ensure you have the required dependencies installed (e.g., pip install scikit-learn).

Execute python main.py to launch the graphical interface and configure your scan parameters.
Ensure you have the required dependencies installed (e.g., pip install scikit-learn).

Execute python main.py to launch the graphical interface and configure your scan parameters.
