# To get the name servers for our zone to put in our domain registrar.
output "example_name_servers" {  
  value = "${aws_route53_zone.main.name_servers}"
}

# ALB DNS is generated dynamically, return URL so that it can be used
output "url" {
  value = "http://${aws_alb.load_balancer.dns_name}/"
}

output "smtp_username" {
  value = aws_iam_access_key.smtp_user.id
}

output "smtp_password" {
  value = aws_iam_access_key.smtp_user.ses_smtp_password_v4
  sensitive = false
}

output "bastion_host_1_public_ip" {  
  value = "${aws_eip.bastion_elastic_ip_1.public_ip}"
}

output "bastion_host_1_private_ip" {  
  value = "${aws_instance.bastion_host_1.private_ip}"
}

output "bastion_host_2_public_ip" {  
  value = "${aws_eip.bastion_elastic_ip_2.public_ip}"
}

output "bastion_host_2_private_ip" {  
  value = "${aws_instance.bastion_host_2.private_ip}"
}

output "app_1_private_ip" {  
  value = "${aws_instance.app.private_ip}"
}

output "www_1_private_ip" {  
  value = "${aws_instance.www.private_ip}"
}
