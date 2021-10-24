# To get the name servers for our zone to put in our domain registrar.
output "example_name_servers" {  
  value = "${aws_route53_zone.main.name_servers}"
}

# ALB DNS is generated dynamically, return URL so that it can be used
output "url" {
  value = "http://${aws_alb.load_balancer.dns_name}/"
}
