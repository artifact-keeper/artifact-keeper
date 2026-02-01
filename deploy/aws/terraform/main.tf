terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --------------------------------------------------------------------------
# Data sources
# --------------------------------------------------------------------------

data "aws_vpc" "selected" {
  id      = var.vpc_id != "" ? var.vpc_id : null
  default = var.vpc_id == "" ? true : false
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.selected.id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

# --------------------------------------------------------------------------
# Security Group
# --------------------------------------------------------------------------

resource "aws_security_group" "artifact_keeper" {
  name_prefix = "${var.name_prefix}-"
  description = "Artifact Keeper instance security group"
  vpc_id      = data.aws_vpc.selected.id

  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP"
  }

  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }

  # SSH (restricted)
  dynamic "ingress" {
    for_each = length(var.allowed_ssh_cidrs) > 0 ? [1] : []
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.allowed_ssh_cidrs
      description = "SSH"
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = {
    Name = "${var.name_prefix}-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# --------------------------------------------------------------------------
# IAM Role (minimal — read instance tags, write CloudWatch logs)
# --------------------------------------------------------------------------

resource "aws_iam_role" "artifact_keeper" {
  name_prefix = "${var.name_prefix}-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "${var.name_prefix}-role"
  }
}

resource "aws_iam_role_policy" "artifact_keeper" {
  name_prefix = "${var.name_prefix}-"
  role        = aws_iam_role.artifact_keeper.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeTags",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
    ]
  })
}

resource "aws_iam_instance_profile" "artifact_keeper" {
  name_prefix = "${var.name_prefix}-"
  role        = aws_iam_role.artifact_keeper.name
}

# --------------------------------------------------------------------------
# EC2 Instance
# --------------------------------------------------------------------------

resource "aws_instance" "artifact_keeper" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = var.subnet_id != "" ? var.subnet_id : data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.artifact_keeper.id]
  iam_instance_profile   = aws_iam_instance_profile.artifact_keeper.name

  user_data = var.domain != "" ? "DOMAIN=${var.domain}\nADMIN_EMAIL=${var.admin_email}" : null

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = {
    Name = var.name_prefix
  }
}

# --------------------------------------------------------------------------
# Data volume (separate EBS for artifacts)
# --------------------------------------------------------------------------

resource "aws_ebs_volume" "data" {
  availability_zone = aws_instance.artifact_keeper.availability_zone
  size              = var.data_volume_size
  type              = "gp3"
  encrypted         = true

  tags = {
    Name = "${var.name_prefix}-data"
  }
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/xvdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.artifact_keeper.id
}
