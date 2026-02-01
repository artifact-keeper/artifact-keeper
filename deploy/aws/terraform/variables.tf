variable "ami_id" {
  type        = string
  description = "Artifact Keeper AMI ID. Find the latest at https://github.com/artifact-keeper/artifact-keeper/releases"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

variable "key_name" {
  type        = string
  description = "Name of an existing EC2 key pair for SSH access."
}

variable "domain" {
  type        = string
  default     = ""
  description = "Optional domain name. If set, first-boot will request a Let's Encrypt certificate."
}

variable "admin_email" {
  type        = string
  default     = ""
  description = "Email for Let's Encrypt notifications. Required if domain is set."
}

variable "data_volume_size" {
  type        = number
  default     = 50
  description = "Size in GB for the artifact storage EBS volume."
}

variable "allowed_ssh_cidrs" {
  type        = list(string)
  default     = []
  description = "CIDR blocks allowed to SSH. Empty = no SSH access from internet."
}

variable "vpc_id" {
  type        = string
  default     = ""
  description = "Existing VPC ID. Leave empty to use the default VPC."
}

variable "subnet_id" {
  type        = string
  default     = ""
  description = "Existing subnet ID. Leave empty to let AWS pick a default subnet."
}

variable "name_prefix" {
  type    = string
  default = "artifact-keeper"
}
