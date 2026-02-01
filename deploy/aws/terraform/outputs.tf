output "instance_id" {
  value       = aws_instance.artifact_keeper.id
  description = "EC2 instance ID"
}

output "public_ip" {
  value       = aws_instance.artifact_keeper.public_ip
  description = "Public IP address"
}

output "public_dns" {
  value       = aws_instance.artifact_keeper.public_dns
  description = "Public DNS hostname"
}

output "url" {
  value       = var.domain != "" ? "https://${var.domain}" : "http://${aws_instance.artifact_keeper.public_ip}"
  description = "Artifact Keeper URL"
}

output "ssh_command" {
  value       = "ssh -i ~/.ssh/${var.key_name}.pem ubuntu@${aws_instance.artifact_keeper.public_ip}"
  description = "SSH command to connect to the instance"
}

output "credentials_command" {
  value       = "ssh -i ~/.ssh/${var.key_name}.pem ubuntu@${aws_instance.artifact_keeper.public_ip} 'sudo cat /opt/artifact-keeper/.credentials'"
  description = "Command to retrieve the generated admin credentials"
}
