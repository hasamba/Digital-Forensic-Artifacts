## Project: Automated DFIR Artifact Generation \& Timeline Analysis

### Overview

This project automates the creation of forensic artifacts from simulated attack scenarios, enabling efficient analysis and timeline reconstruction. As a digital forensics researcher, I am continuously seeking realistic attack data for analysis. This project leverages publicly available DFIR reports to create those scenarios.

The core workflow involves generating attack simulations based on real-world incident reports, capturing forensic artifacts, and processing those artifacts into a consolidated timeline for analysis.

### Methodology

1. **Incident Report Acquisition:** Incident reports, primarily sourced from [The DFIR Report](https://thedfirreport.com/), are used as the basis for attack simulations.
2. **Attack Simulation:** `Claude` is used to generate `PowerShell` scripts that emulate the attack chains described in the incident reports.
3. **Lab Environment Execution:** The generated scripts are executed within a clean, isolated lab environment to ensure controlled artifact generation.
4. **Artifact Acquisition:** After script execution, KAPE (Kroll Artifact Parser and Extractor) is used with the SANS Triage Compound configuration to acquire a broad range of relevant artifacts. The output is stored in a ZIP file for portability.
5. **Timeline Generation:**
    * `Log2Timeline` (Plaso) is used with the `KITCHENSINK` method to create a comprehensive timeline file (PLASO file) from the acquired artifacts.
    * The PLASO file is converted to a CSV format for easier manipulation.
    * `Timeline_noise` is then used to filter the CSV file, removing common noise and irrelevant events to improve analysis efficiency.

### Workflow Diagram

    A[DFIR Report] -->|Script Generation|> B[ChatGPT: PowerShell Script]
    B -->|Execution|> C[Lab Environment]
    C -->|Artifact Acquisition|> D[KAPE: ZIP File]
    D -->|Timeline Creation|> E[Log2Timeline (Plaso): PLASO File]
    E -->|CSV Conversion|> F[CSV File]
    F -->|Noise Reduction|> G[Timeline_noise: CSV Timeline]


### Benefits

* **Realistic Attack Simulations:** Emulates real-world attack scenarios based on credible incident reports.
* **Automated Artifact Generation:** Streamlines the process of creating forensic artifacts.
* **Comprehensive Timeline Analysis:** Provides a consolidated and filtered timeline for efficient incident investigation.
* **Educational Resource:** Serves as a valuable resource for learning and practicing digital forensics techniques.
