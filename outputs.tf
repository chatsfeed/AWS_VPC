# To get the name servers for our zone to put in our domain registrar.
output "example_name_servers" {  
  value = "${aws_route53_zone.main.name_servers}"
}

output "load_balancer_public_ip" {
  value = "${aws_alb.load_balancer.public_ip}"
}
