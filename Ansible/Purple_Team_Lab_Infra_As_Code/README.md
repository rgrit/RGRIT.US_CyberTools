# Purple Team Infrastructure as Code

This directory contains **Infrastructure as Code (IaC)** playbooks designed to automate the setup of a **Purple Team Lab** environment. The lab integrates offensive and defensive tools for proactive security testing and detection engineering. It simulates real-world attack scenarios while enabling automated logging, monitoring, and detection.

## Directory Contents

### 1. `proxmox-initial-setup.yml`
This playbook prepares a Proxmox server by:
- Removing enterprise repositories to use the no-subscription repository.
- Enabling necessary repositories.
- Setting up IOMMU for PCI passthrough.
- Installing essential packages such as `qemu-guest-agent` and `vim`.
- Configuring network interfaces for passthrough.

#### **Usage**
```bash
ansible-playbook -i hosts.yml proxmox-initial-setup.yml -b -K
```

### 2. `download-proxmox-isos.yml`
This playbook downloads the necessary ISO images to the Proxmox server to be used for virtual machine installation, including images for Kali Linux, Ubuntu, and additional resources for the Purple Team Lab.

#### **Usage**
```bash
ansible-playbook -i hosts.yml download-proxmox-isos.yml -b -K
```

### 3. `create-vms.yml`
This playbook creates and configures virtual machines in Proxmox using pre-downloaded ISO files. The VMs are designed to simulate both attacker and defender roles in the Purple Team Lab setup.

- **Kali Linux** is used as the attacker machine for simulating real-world attacks.
- **Wazuh** (in the **Wazuh-ubuntu** machine) is used to monitor and collect logs, providing a **Security Information and Event Management (SIEM)** solution.
- **Purple Lab** (in the **purple-lab** machine) is set up with **Krook9d’s Purple Lab** to automate the creation of detection engineering resources.

#### **Usage**
```bash
ansible-playbook -i hosts.yml create-vms.yml
```

### 4. `hosts.yml`
Defines the Proxmox server details and authentication required by Ansible. It includes the connection details for SSH and Proxmox API authentication (using API token-based authentication).

```yaml
all:
  hosts:
    proxmox:
      ansible_host: 192.168.1.175
      ansible_user: root
      ansible_ssh_private_key_file: ~/.ssh/id_rsa
      ansible_python_interpreter: /usr/bin/python3
      api_host: 192.168.1.175
      api_user: root@pam
      api_token_id: "ansible"
      api_token_secret: "your-proxmox-api-token"
      validate_certs: false
```

## **Lab Overview**
The Purple Team Infrastructure as Code (IaC) setup provides an automated framework for deploying a lab environment that integrates **offensive and defensive security tooling**. This lab consists of:

- **Kali Linux**: The attacker machine for penetration testing, red teaming, and offensive security.
- **Wazuh**: A **SIEM and IDS** system to monitor security events, analyze logs, and detect attacks.
- **Purple Lab**: The defensive and detection engineering lab, including **Krook9d’s Purple Lab**, to facilitate attack detection and automated rule generation.

## **Future Improvements**
- **Automate Wazuh Agent Installation**: Deploy and configure Wazuh agents across all machines automatically.
- **Network Segmentation & Isolation**: Automate network configurations to isolate VMs and restrict communication.
- **Integrate Attack Simulations**: Implement tools like **Metasploit** and **Cobalt Strike** to run automated attack scenarios.
- **Automate Detection Engineering**: Tune detection rule sets dynamically based on attack simulations.
- **Security Incident Response Automation**: Integrate tools like **TheHive** and **Cortex** for automated alert analysis and response.

## **Usage Notes**
- Ensure API credentials are secure and not hardcoded in playbooks.
- The playbooks use `validate_certs: false`; adjust this flag if using valid SSL certificates.
- Modify the VM configurations in `create-vms.yml` as necessary.
- For future enhancements, focus on improving detection automation and attack simulation.

This setup is designed to **streamline the deployment of a fully functional Purple Team Lab**, enabling both **attack and defense teams** to test, detect, and respond to cyber threats in an automated environment.

