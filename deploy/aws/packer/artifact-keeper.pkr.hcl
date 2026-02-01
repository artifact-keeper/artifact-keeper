packer {
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "artifact_keeper_version" {
  type        = string
  description = "Artifact Keeper release version (e.g. 0.2.0). Used to download the correct binary from GitHub Releases."
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

variable "ami_regions" {
  type        = list(string)
  default     = []
  description = "Additional regions to copy the AMI to. Empty = only build region."
}

variable "postgresql_version" {
  type    = string
  default = "16"
}

variable "meilisearch_version" {
  type    = string
  default = "1.12.3"
}

variable "trivy_version" {
  type    = string
  default = "0.58.2"
}

variable "grype_version" {
  type    = string
  default = "0.86.1"
}

# -----------------------------------------------------------------------------
# Source: Amazon EBS (Ubuntu 24.04 LTS)
# -----------------------------------------------------------------------------

source "amazon-ebs" "artifact-keeper" {
  ami_name        = "artifact-keeper-${var.artifact_keeper_version}-{{timestamp}}"
  ami_description = "Artifact Keeper ${var.artifact_keeper_version} — open-source artifact registry with PostgreSQL, Meilisearch, Trivy, and Grype pre-installed."
  instance_type   = var.instance_type
  region          = var.aws_region
  ami_regions     = var.ami_regions

  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"] # Canonical
  }

  ssh_username = "ubuntu"

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name        = "artifact-keeper-${var.artifact_keeper_version}"
    Application = "artifact-keeper"
    Version     = var.artifact_keeper_version
    OS          = "ubuntu-24.04"
    ManagedBy   = "packer"
  }
}

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------

build {
  sources = ["source.amazon-ebs.artifact-keeper"]

  # Upload provisioning scripts
  provisioner "file" {
    source      = "${path.root}/../scripts/"
    destination = "/tmp/ak-scripts"
  }

  # Run the install script
  provisioner "shell" {
    environment_vars = [
      "ARTIFACT_KEEPER_VERSION=${var.artifact_keeper_version}",
      "POSTGRESQL_VERSION=${var.postgresql_version}",
      "MEILISEARCH_VERSION=${var.meilisearch_version}",
      "TRIVY_VERSION=${var.trivy_version}",
      "GRYPE_VERSION=${var.grype_version}",
      "DEBIAN_FRONTEND=noninteractive",
    ]
    execute_command = "chmod +x {{ .Path }}; sudo -E {{ .Path }}"
    scripts = [
      "${path.root}/../scripts/01-system.sh",
      "${path.root}/../scripts/02-postgresql.sh",
      "${path.root}/../scripts/03-meilisearch.sh",
      "${path.root}/../scripts/04-scanners.sh",
      "${path.root}/../scripts/05-artifact-keeper.sh",
      "${path.root}/../scripts/06-nginx.sh",
      "${path.root}/../scripts/07-first-boot.sh",
      "${path.root}/../scripts/99-cleanup.sh",
    ]
  }
}
